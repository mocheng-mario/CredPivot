use crate::paths::{ensure_runtime_dir, runtime_dir};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::PathBuf;

/// 与仓库 `assets/ssh-expect-pass.exp` 同步；安装到 ~/.credpivot。
const EMBEDDED_SCRIPT: &str = include_str!("../../../assets/ssh-expect-pass.exp");

pub fn materialized_ssh_expect_path() -> PathBuf {
    runtime_dir().join("ssh-expect-pass.exp")
}

fn embedded_digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(EMBEDDED_SCRIPT.as_bytes());
    hex::encode(hasher.finalize())
}

fn file_digest(path: &std::path::Path) -> std::io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// 将内置脚本写入 `~/.credpivot/ssh-expect-pass.exp`（内容或摘要变化时覆盖）。
pub fn ensure_ssh_expect_script() -> std::io::Result<PathBuf> {
    ensure_runtime_dir()?;
    let path = materialized_ssh_expect_path();
    let digest_path = runtime_dir().join("ssh-expect-pass.exp.sha256");
    let want = embedded_digest();
    if path.is_file() {
        if let Ok(got) = file_digest(&path) {
            if got == want {
                return Ok(path);
            }
        }
    }
    fs::write(&path, EMBEDDED_SCRIPT)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    }
    fs::write(digest_path, want)?;
    Ok(path)
}
