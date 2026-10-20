use crate::atomic_config::{read_vault_json, write_vault_json_atomic};
use crate::cpvc1::CpvcConfig;
use crate::crypto::VMK_LEN;
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

/// M1-7 / M3-4：一致性副本写入空目录并校验（不切换当前工作库）。
pub fn clone_vault_to_empty_dir(
    source_dir: &Path,
    target_dir: &Path,
    vmk: &Zeroizing<[u8; 32]>,
) -> Result<()> {
    ensure_empty_target(target_dir)?;
    let outcome = (|| {
        let snapshot = pack_snapshot_from_dir(source_dir, vmk)?;
        fs::create_dir_all(target_dir).map_err(|e| CoreError::io(e.to_string()))?;
        unpack_snapshot_to_dir(&snapshot, target_dir, vmk)?;
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

/// M3-3：从 `restore-points/<ts>/` 恢复到新的空目录。
pub fn recover_restore_point_to_dir(
    restore_point_dir: &Path,
    target_dir: &Path,
    vmk: &Zeroizing<[u8; 32]>,
) -> Result<()> {
    ensure_empty_target(target_dir)?;
    let vault_json = restore_point_dir.join("vault.json");
    let vault_db = restore_point_dir.join(local_db::DB_FILENAME);
    if !vault_json.is_file() || !vault_db.is_file() {
        return Err(CoreError::format("invalid restore point"));
    }
    let outcome = (|| {
        fs::create_dir_all(target_dir).map_err(|e| CoreError::io(e.to_string()))?;
        fs::copy(&vault_json, target_dir.join("vault.json"))
            .map_err(|e| CoreError::io(e.to_string()))?;
        fs::copy(&vault_db, target_dir.join(local_db::DB_FILENAME))
            .map_err(|e| CoreError::io(e.to_string()))?;
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

/// M3-5：在独立 staging 目录完成 VMK 轮换与配置重写，校验通过后切换；生成新恢复密钥。
pub fn security_rebuild_in_dir(
    dir: &Path,
    master_password: &str,
    recovery_key_display: &str,
) -> Result<String> {
    let cfg = read_vault_json(dir)?;
    let old_vmk = cfg.unlock_master(master_password)?;
    cfg.verify_mac(&*old_vmk)?;
    let recovery_secret = crate::recovery_key::parse_display(recovery_key_display.trim())?;
    let mut old_rec_arr = [0u8; VMK_LEN];
    old_rec_arr.copy_from_slice(&recovery_secret);
    let via_recovery = cfg.unlock_recovery(&old_rec_arr)?;
    if via_recovery.as_ref() != old_vmk.as_ref() {
        return Err(CoreError::Auth);
    }

    let parent = dir
        .parent()
        .ok_or_else(|| CoreError::format("vault directory has no parent"))?;
    let staging = parent.join(format!(".credpivot-rebuild-{}", Uuid::new_v4()));
    cleanup_failed_target(&staging);
    ensure_empty_target(&staging)?;
    clone_vault_to_empty_dir(dir, &staging, &old_vmk)?;

    let mut new_vmk_arr = [0u8; VMK_LEN];
    new_vmk_arr.copy_from_slice(&crate::crypto::random_bytes(VMK_LEN));
    let new_vmk = Zeroizing::new(new_vmk_arr);
    let (new_recovery_secret, new_recovery_display) = crate::recovery_key::generate();
    let mut new_rec_arr = [0u8; VMK_LEN];
    new_rec_arr.copy_from_slice(&new_recovery_secret);

    let vault_uuid = Uuid::parse_str(&cfg.vault_id).map_err(|_| CoreError::format("vault_id"))?;
    local_db::rekey_database(&staging, &old_vmk, &new_vmk, &vault_uuid)?;

    let mut next = read_vault_json(&staging)?;
    next.control_revision += 1;
    let master = KeySlot::create_master_password(
        &next.vault_id,
        next.format_major,
        master_password,
        &*new_vmk,
    )?;
    let recovery = KeySlot::create_recovery(
        &next.vault_id,
        next.format_major,
        &new_rec_arr,
        &*new_vmk,
    )?;
    next.key_slots = vec![master, recovery];
    next.sign(&*new_vmk)?;
    write_vault_json_atomic(&staging, &next)?;

    let staged_cfg = read_vault_json(&staging)?;
    staged_cfg.verify_mac(&*new_vmk)?;
    local_db::verify_database(&staging, &*new_vmk)?;
    let _ = staged_cfg
        .unlock_recovery(&new_rec_arr)
        .map_err(|_| CoreError::format("new recovery key verification failed"))?;
    if staged_cfg.unlock_recovery(&old_rec_arr).is_ok() {
        cleanup_failed_target(&staging);
        return Err(CoreError::format("old recovery key still valid after rebuild"));
    }

    let backup = parent.join(format!(".credpivot-rebuild-backup-{}", Uuid::new_v4()));
    fs::rename(dir, &backup).map_err(|e| CoreError::io(e.to_string()))?;
    if fs::rename(&staging, dir).is_err() {
        let _ = fs::rename(&backup, dir);
        cleanup_failed_target(&staging);
        return Err(CoreError::format("failed to activate rebuilt vault"));
    }
    let _ = fs::remove_dir_all(&backup);
    Ok(new_recovery_display)
}
