use crate::atomic_config::{read_vault_json, write_vault_json_atomic};
use crate::cpvc1::CpvcConfig;
use crate::crypto::VMK_LEN;
use crate::error::{CoreError, Result};
use crate::key_slot::{KeySlot, SlotType};
use crate::local_db;
use crate::ovb1::{build_ovb_file, decrypt_snapshot, parse_ovb_with_aad};
use crate::password_change::rewrap_master_password;
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
    let vmk = cfg.unlock_master(old_password)?;
    cfg.verify_mac(&vmk)?;
    let next = rewrap_master_password(&cfg, new_password, &vmk)?;
    // 先持久化改密意图；配置替换后即使进程退出，也能沿用原同步基准发布新密码。
    let db = local_db::open_database(dir, &vmk)?;
    crate::sync::stage_password_change(&db, &cfg, &next, &vmk)?;
    drop(db);
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
/// `vault_json_source`：同 VMK 代际恢复数据时传入当前工作库的 `vault.json`，避免把主密码配置退回旧槽。
pub fn recover_restore_point_to_dir(
    restore_point_dir: &Path,
    target_dir: &Path,
    vmk: &Zeroizing<[u8; 32]>,
    vault_json_source: Option<&Path>,
) -> Result<()> {
    ensure_empty_target(target_dir)?;
    let vault_json = restore_point_dir.join("vault.json");
    let vault_db = restore_point_dir.join(local_db::DB_FILENAME);
    if !vault_json.is_file() || !vault_db.is_file() {
        return Err(CoreError::format("invalid restore point"));
    }
    let outcome = (|| {
        fs::create_dir_all(target_dir).map_err(|e| CoreError::io(e.to_string()))?;
        let json_src = vault_json_source
            .filter(|p| p.is_file())
            .unwrap_or(&vault_json);
        fs::copy(json_src, target_dir.join("vault.json"))
            .map_err(|e| CoreError::io(e.to_string()))?;
        fs::copy(&vault_db, target_dir.join(local_db::DB_FILENAME))
            .map_err(|e| CoreError::io(e.to_string()))?;
        let cfg = read_vault_json(target_dir)?;
        cfg.verify_mac(&*vmk)?;
        local_db::verify_database(target_dir, &*vmk)?;
        let restored = local_db::open_database(target_dir, vmk)?;
        crate::sync::disconnect(&restored)?;
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

    // 旧代际的验证记录不能证明新密钥和新恢复密钥可恢复；激活后重新生成恢复点。
    {
        let conn = local_db::open_database(&staging, &new_vmk)?;
        conn.execute("DELETE FROM vault_settings WHERE key IN (?1,?2,?3,?4,?5)", rusqlite::params![
            crate::backup_status::KEY_LOCAL_RESTORE_OK,
            crate::backup_status::KEY_OVB_EXPORT_OK,
            crate::backup_status::KEY_OVB_DECRYPT_OK,
            crate::backup_status::KEY_RECOVERY_KEY_OK,
            crate::restore_point::SETTINGS_LAST_RESTORE_MS,
        ])?;
        crate::mark_restore_dirty(&conn)?;
    }

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

    // 本地历史全部保留；复制失败时不能切换或删除原保险库。
    if let Err(e) = preserve_restore_points_from_backup(dir, &staging)
        .and_then(|_| preserve_sync_backups(dir, &staging))
        .and_then(|_| sync_rebuilt_directory(&staging)) {
        cleanup_failed_target(&staging);
        return Err(e);
    }
    // 一次系统调用交换目录，崩溃时原路径始终指向完整的新库或旧库，不需要猜测临时目录。
    if let Err(error) = exchange_vault_directories(dir, &staging) {
        cleanup_failed_target(&staging);
        return Err(error);
    }
    // 交换后 staging 才是旧库，清理失败不影响已激活的新库和恢复密钥交付。
    // 先持久化交换结果；父目录同步失败时保留旧库，不能以清理破坏断电后的回退副本。
    if fs::File::open(parent).and_then(|file| file.sync_all()).is_ok() {
        let _ = fs::remove_dir_all(&staging);
    }
    Ok(new_recovery_display)
}

fn preserve_sync_backups(source: &Path, target: &Path) -> Result<()> {
    let source = source.join("sync-backups");
    let metadata = match fs::symlink_metadata(&source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(CoreError::io(error.to_string())),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(CoreError::format("invalid sync backup directory"));
    }
    let target = target.join("sync-backups");
    fs::create_dir(&target).map_err(|error| CoreError::io(error.to_string()))?;
    for entry in fs::read_dir(&source).map_err(|error| CoreError::io(error.to_string()))? {
        let entry = entry.map_err(|error| CoreError::io(error.to_string()))?;
        if !entry.file_type().map_err(|error| CoreError::io(error.to_string()))?.is_file() {
            return Err(CoreError::format("invalid sync backup entry"));
        }
        fs::copy(entry.path(), target.join(entry.file_name()))
            .map_err(|error| CoreError::io(error.to_string()))?;
    }
    Ok(())
}

fn exchange_vault_directories(active: &Path, staged: &Path) -> Result<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let active = CString::new(active.as_os_str().as_bytes())
            .map_err(|_| CoreError::format("invalid vault directory"))?;
        let staged = CString::new(staged.as_os_str().as_bytes())
            .map_err(|_| CoreError::format("invalid staging directory"))?;
        #[cfg(target_os = "macos")]
        let result = {
            extern "C" { fn renamex_np(from: *const std::ffi::c_char, to: *const std::ffi::c_char, flags: u32) -> i32; }
            // macOS sys/stdio.h：RENAME_SWAP = 2；目录位于同一父目录/文件系统。
            unsafe { renamex_np(active.as_ptr(), staged.as_ptr(), 2) }
        };
        #[cfg(target_os = "linux")]
        let result = {
            extern "C" { fn renameat2(from_fd: i32, from: *const std::ffi::c_char, to_fd: i32, to: *const std::ffi::c_char, flags: u32) -> i32; }
            // Linux fcntl.h：AT_FDCWD = -100；RENAME_EXCHANGE = 2。
            unsafe { renameat2(-100, active.as_ptr(), -100, staged.as_ptr(), 2) }
        };
        if result != 0 { return Err(CoreError::io(std::io::Error::last_os_error().to_string())); }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (active, staged);
        // 不支持原子交换的系统/文件系统必须拒绝切换，不能退回有空窗的两次 rename。
        Err(CoreError::format("atomic vault directory exchange is unavailable"))
    }
}

/// 交换之前落盘新库及备份目录，不能在原文件删除后才依赖尚未刷盘的复制内容。
fn sync_rebuilt_directory(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory).map_err(|error| CoreError::io(error.to_string()))? {
        let entry = entry.map_err(|error| CoreError::io(error.to_string()))?;
        let kind = entry.file_type().map_err(|error| CoreError::io(error.to_string()))?;
        if kind.is_dir() {
            sync_rebuilt_directory(&entry.path())?;
        } else if kind.is_file() {
            fs::File::open(entry.path()).and_then(|file| file.sync_all())
                .map_err(|error| CoreError::io(error.to_string()))?;
        } else { return Err(CoreError::format("invalid rebuilt vault entry")); }
    }
    fs::File::open(directory).and_then(|file| file.sync_all())
        .map_err(|error| CoreError::io(error.to_string()))
}

fn preserve_restore_points_from_backup(backup: &Path, active: &Path) -> Result<()> {
    use crate::restore_point::RESTORE_POINTS_DIR;
    let src = backup.join(RESTORE_POINTS_DIR);
    if !src.is_dir() {
        return Ok(());
    }
    let dst = active.join(RESTORE_POINTS_DIR);
    std::fs::create_dir_all(&dst).map_err(|e| CoreError::io(e.to_string()))?;
    for entry in std::fs::read_dir(&src).map_err(|e| CoreError::io(e.to_string()))? {
        let entry = entry.map_err(|e| CoreError::io(e.to_string()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let target = dst.join(name);
        if target.exists() {
            continue;
        }
        // 保留原库完整可用，激活失败时仍可直接回退；恢复点内只应包含普通文件。
        std::fs::create_dir_all(&target).map_err(|e| CoreError::io(e.to_string()))?;
        for file in std::fs::read_dir(&path).map_err(|e| CoreError::io(e.to_string()))? {
            let file = file.map_err(|e| CoreError::io(e.to_string()))?;
            if !file.file_type().map_err(|e| CoreError::io(e.to_string()))?.is_file() {
                return Err(CoreError::format("invalid restore point entry"));
            }
            std::fs::copy(file.path(), target.join(file.file_name()))
                .map_err(|e| CoreError::io(e.to_string()))?;
        }
    }
    Ok(())
}

/// 仅轮换恢复槽；旧备份仍需各自原来的恢复码。
pub fn reset_recovery_key_in_dir(dir: &Path, password: &str, old_key: &str) -> Result<String> {
    let mut config = read_vault_json(dir)?;
    let vmk = config.unlock_master(password)?;
    config.verify_mac(&vmk)?;
    let old_secret = crate::parse_recovery_display(old_key.trim())?;
    let old_secret: [u8; VMK_LEN] = old_secret.try_into().map_err(|_| CoreError::BadSecret)?;
    if config.unlock_recovery(&old_secret)?.as_ref() != vmk.as_ref() { return Err(CoreError::Auth); }
    let conn = local_db::open_database(dir, &vmk)?;
    // 当前同步协议只允许主密码槽变化，不能静默替换已绑定远端的恢复槽。
    if crate::sync::binding(&conn)?.is_some() {
        return Err(CoreError::format("请先断开 WebDAV 同步，再重置恢复码；旧远端备份仍使用旧恢复码。"));
    }
    crate::create_restore_point_for_risky_op(dir, &vmk, &conn)?;
    let (secret, display) = crate::generate_recovery_key();
    let secret: [u8; VMK_LEN] = secret.try_into().map_err(|_| CoreError::BadSecret)?;
    let slot = KeySlot::create_recovery(&config.vault_id, config.format_major, &secret, &vmk)?;
    config.key_slots.retain(|s| s.slot_type != SlotType::RecoveryKey);
    config.key_slots.push(slot);
    config.control_id = Uuid::new_v4().to_string();
    config.control_revision = config.control_revision.checked_add(1).ok_or_else(|| CoreError::format("control revision overflow"))?;
    config.sign(&vmk)?;
    if config.unlock_recovery(&secret)?.as_ref() != vmk.as_ref() { return Err(CoreError::Auth); }
    // 写入失败时只会丢失验证时间，不会误报旧码仍可恢复新配置。
    conn.execute("DELETE FROM vault_settings WHERE key IN (?1,?2,?3)", rusqlite::params![
        crate::backup_status::KEY_RECOVERY_KEY_OK,
        crate::backup_status::KEY_OVB_EXPORT_OK,
        crate::backup_status::KEY_OVB_DECRYPT_OK,
    ])?;
    crate::mark_restore_dirty(&conn)?;
    if let Err(error) = write_vault_json_atomic(dir, &config) {
        // rename 已成功但最后的目录同步失败时，仍必须交付已生效的新码。
        let activated = read_vault_json(dir).is_ok_and(|active| {
            active.control_id == config.control_id && active.verify_mac(&vmk).is_ok()
        });
        if !activated {
            let pending = dir.join("vault.json.next");
            if fs::read_to_string(&pending).ok().and_then(|body| crate::parse_config(&body).ok())
                .is_some_and(|next| next.control_id == config.control_id) {
                let _ = fs::remove_file(pending);
            }
            return Err(error);
        }
    }
    Ok(display)
}
