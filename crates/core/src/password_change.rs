use crate::cpvc1::CpvcConfig;
use crate::error::{CoreError, Result};
use crate::key_slot::{KeySlot, SlotType};
use uuid::Uuid;
/// 普通改主密码：VMK 不变，替换主密码槽并递增 control_revision（13.4）。
pub fn change_master_password(
    config: &CpvcConfig,
    old_password: &str,
    new_password: &str,
) -> Result<CpvcConfig> {
    let vmk = config.unlock_master(old_password)?;
    let recovery = config
        .key_slots
        .iter()
        .find(|s| s.slot_type == SlotType::RecoveryKey)
        .cloned()
        .ok_or_else(|| CoreError::format("no recovery slot"))?;

    let new_master = KeySlot::create_master_password(
        &config.vault_id,
        config.format_major,
        new_password,
        &*vmk,
    )?;

    let mut next = CpvcConfig {
        magic: config.magic.clone(),
        format_major: config.format_major,
        vault_id: config.vault_id.clone(),
        control_id: Uuid::new_v4().to_string(),
        control_revision: config.control_revision + 1,
        key_slots: vec![new_master, recovery],
        control_mac: None,
    };
    next.sign(&*vmk)?;
    Ok(next)
}
