use crate::atomic_config::{read_vault_json, write_vault_json_atomic};
use crate::cpvc1::CpvcConfig;
use crate::error::{CoreError, Result};
use crate::key_slot::{KeySlot, SlotType};
use crate::local_db;
use crate::ovb1::{build_ovb_file, decrypt_snapshot, parse_ovb_with_aad};
use crate::password_change::change_master_password;
use crate::snapshot::{pack_snapshot_from_dir, unpack_snapshot_to_dir};
use crate::vault_init::{create_vault_config, NewVaultMaterial};
use std::fs;
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

/// M1-7：目标目录须为空（或不存在）。
pub fn ensure_empty_target(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(dir).map_err(|e| CoreError::io(e.to_string()))?;
    if entries.next().is_some() {
        return Err(CoreError::format("target directory not empty"));
    }
    Ok(())
}

fn cleanup_failed_target(dir: &Path) {
    if dir.exists() {
        let _ = fs::remove_dir_all(dir);
    }
}

/// 在空目录创建 Vault（vault.json + SQLCipher vault.db）。
pub fn bootstrap_vault_dir(dir: &Path, master_password: &str) -> Result<NewVaultMaterial> {
    ensure_empty_target(dir)?;
    fs::create_dir_all(dir).map_err(|e| CoreError::io(e.to_string()))?;
    let material = create_vault_config(master_password)?;
    write_vault_json_atomic(dir, &material.config)?;
    let vault_uuid = Uuid::parse_str(&material.config.vault_id)
        .map_err(|_| CoreError::format("vault_id"))?;
    local_db::init_database(dir, &*material.vmk, &vault_uuid)?;
    Ok(material)
}

pub fn export_ovb_from_dir(dir: &Path, master_password: &str) -> Result<Vec<u8>> {
    let cfg = read_vault_json(dir)?;
    let vmk = cfg.unlock_master(master_password)?;
    cfg.verify_mac(&*vmk)?;
    let snapshot = pack_snapshot_from_dir(dir, &vmk)?;
    let vault_uuid = Uuid::parse_str(&cfg.vault_id).map_err(|_| CoreError::format("vault_id"))?;
    build_ovb_file(&*vmk, &vault_uuid, cfg.key_slots.clone(), &snapshot)
}

pub enum RecoveryUnlock {
    MasterPassword(String),
    RecoverySecret([u8; 32]),
}

fn unlock_vmk_from_ovb_slots(
    slots: &[KeySlot],
    vault_id: &Uuid,
    unlock: &RecoveryUnlock,
) -> Result<Zeroizing<[u8; 32]>> {
    let vault_id_str = vault_id.to_string();
    let format_major = 1u8;
    match unlock {
        RecoveryUnlock::MasterPassword(pw) => {
            let slot = slots
                .iter()
                .find(|s| s.slot_type == SlotType::MasterPassword)
                .ok_or_else(|| CoreError::format("no master slot in ovb"))?;
            slot.unwrap_vmk(&vault_id_str, format_major, pw.as_bytes())
        }
        RecoveryUnlock::RecoverySecret(secret) => {
            let slot = slots
                .iter()
                .find(|s| s.slot_type == SlotType::RecoveryKey)
                .ok_or_else(|| CoreError::format("no recovery slot in ovb"))?;
            slot.unwrap_vmk(&vault_id_str, format_major, secret)
        }
    }
}

/// 从 OVB 恢复到新的空目录：解密 → 校验 → 落盘（失败则删除目标目录）。
pub fn recover_ovb_to_dir(ovb_bytes: &[u8], target_dir: &Path, unlock: RecoveryUnlock) -> Result<()> {
    ensure_empty_target(target_dir)?;
    let outcome = (|| {
        let (header, aad, ciphertext) = parse_ovb_with_aad(ovb_bytes)?;
        let vmk = unlock_vmk_from_ovb_slots(&header.slots, &header.vault_id, &unlock)?;
        let plain = decrypt_snapshot(&*vmk, &header, &aad, &ciphertext)?;
        fs::create_dir_all(target_dir).map_err(|e| CoreError::io(e.to_string()))?;
        unpack_snapshot_to_dir(&plain, target_dir, &vmk)?;
        let cfg = read_vault_json(target_dir)?;
        cfg.verify_mac(&*vmk)?;
        local_db::verify_database(target_dir, &*vmk)?;
        Ok(())
    })();
    if outcome.is_err() {
        cleanup_failed_target(target_dir);
    }
    outcome
}

/// 改主密码并原子写回 vault.json（M1-4 崩溃恢复入口）。
pub fn change_master_password_in_dir(
    dir: &Path,
    old_password: &str,
    new_password: &str,
) -> Result<CpvcConfig> {
    let cfg = read_vault_json(dir)?;
    let next = change_master_password(&cfg, old_password, new_password)?;
    write_vault_json_atomic(dir, &next)?;
    Ok(next)
}
