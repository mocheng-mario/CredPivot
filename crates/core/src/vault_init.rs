use crate::cpvc1::{CpvcConfig, FORMAT_MAJOR, MAGIC};
use crate::crypto::{random_bytes, VMK_LEN};
use crate::error::Result;
use crate::key_slot::KeySlot;
use crate::recovery_key;
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct NewVaultMaterial {
    pub vmk: Zeroizing<[u8; VMK_LEN]>,
    pub recovery_secret: Vec<u8>,
    pub recovery_display: String,
    pub config: CpvcConfig,
}

/// 创建新 Vault 控制配置（不含数据库文件，M1-4 入口）。
pub fn create_vault_config(master_password: &str) -> Result<NewVaultMaterial> {
    let vmk_bytes = random_bytes(VMK_LEN);
    let mut vmk = Zeroizing::new([0u8; VMK_LEN]);
    vmk.copy_from_slice(&vmk_bytes);

    let (recovery_secret, recovery_display) = recovery_key::generate();
    let mut recovery_arr = [0u8; VMK_LEN];
    recovery_arr.copy_from_slice(&recovery_secret);

    let vault_id = Uuid::new_v4().to_string();
    let master = KeySlot::create_master_password(&vault_id, FORMAT_MAJOR, master_password, &*vmk)?;
    let recovery = KeySlot::create_recovery(&vault_id, FORMAT_MAJOR, &recovery_arr, &*vmk)?;

    let mut config = CpvcConfig {
        magic: MAGIC.into(),
        format_major: FORMAT_MAJOR,
        vault_id,
        control_id: Uuid::new_v4().to_string(),
        control_revision: 1,
        key_slots: vec![master, recovery],
        control_mac: None,
    };
    config.sign(&*vmk)?;

    Ok(NewVaultMaterial {
        vmk,
        recovery_secret,
        recovery_display,
        config,
    })
}
