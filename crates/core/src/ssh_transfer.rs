use crate::{CoreError, Result};
use rusqlite::Connection;
use serde_json::{json, Value};
use ssh_key::{private::Ed25519Keypair, LineEnding, PrivateKey};
use zeroize::Zeroizing;

pub fn import_key(conn: &Connection, label: &str, pem: &str, passphrase: &str) -> Result<Value> {
    if label.trim().is_empty() || label.len() > 200 || pem.len() > 65536 || passphrase.len() > 16384
    {
        return Err(CoreError::format("密钥名称或文件大小无效"));
    }
    let key =
        PrivateKey::from_openssh(pem).map_err(|_| CoreError::format("OpenSSH 私钥格式无效"))?;
    // 导入文件控制 KDF 参数，先限制工作量，避免异常文件长时间阻塞 Agent。
    if let ssh_key::Kdf::Bcrypt { rounds, .. } = key.kdf() {
        if *rounds == 0 || *rounds > 256 {
            return Err(CoreError::limit("私钥 KDF 迭代数超出允许范围（1–256）"));
        }
    }
    let key = if key.is_encrypted() {
        key.decrypt(passphrase).map_err(|_| CoreError::BadSecret)?
    } else {
        key
    };
    let pair = key
        .key_data()
        .ed25519()
        .ok_or_else(|| CoreError::format("仅支持 Ed25519 私钥"))?;
    let seed = Zeroizing::new(pair.private.to_bytes());
    let public = crate::format_ssh_ed25519_openssh(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .as_bytes(),
        label.trim(),
    );
    // 相同密钥不能重复导入，也不能泄漏已有私钥。
    let existing: i64 = conn.query_row(
        "SELECT COUNT(*) FROM ssh_keys WHERE private_key_seed=?1",
        [seed.as_slice()],
        |r| r.get(0),
    )?;
    if existing > 0 {
        return Err(CoreError::format("密钥已存在，请检查凭据列表或回收站"));
    }
    let rec = crate::insert_ssh_key(conn, label.trim(), &public, &seed, false, None)?;
    Ok(json!({"id":rec.id,"item_id":rec.item_id,"public_openssh":rec.public_openssh}))
}
pub fn export_key(conn: &Connection, id: &str, passphrase: &str) -> Result<Value> {
    if passphrase.len() > 16384 {
        return Err(CoreError::limit("私钥密码过长"));
    }
    let record = crate::repo_m2::load_ssh_key_by_id(conn, id)?;
    let seed = Zeroizing::new(record.seed);
    let key = PrivateKey::new(Ed25519Keypair::from_seed(&seed).into(), record.label)
        .map_err(|_| CoreError::format("密钥编码失败"))?;
    let key = if passphrase.is_empty() {
        key
    } else {
        key.encrypt(&mut rand::rngs::OsRng, passphrase)
            .map_err(|_| CoreError::format("密钥加密失败"))?
    };
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| CoreError::format("密钥导出失败"))?;
    Ok(json!({"pem":pem.as_str(),"encrypted":!passphrase.is_empty()}))
}
