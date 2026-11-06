#[cfg(not(target_os = "android"))]
use crate::error::{AgentError, Result};
#[cfg(target_os = "macos")]
use crate::paths::{
    materialized_askpass_digest_path, materialized_askpass_path, materialized_native_host_path,
};
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::io::Read;
#[cfg(not(target_os = "android"))]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

/// M0 peer checks for Unix socket clients.
#[derive(Debug, Clone)]
pub struct PeerAuthConfig {
    /// Expected basename of native-host binary inside the app bundle.
    pub expected_host_binary_name: String,
    /// When set (dev only), skip signature/path checks.
    pub dev_skip_peer_check: bool,
}

impl Default for PeerAuthConfig {
    fn default() -> Self {
        Self {
            expected_host_binary_name: "credpivot-native-host".into(),
            dev_skip_peer_check: cfg!(debug_assertions) && std::env::var("CREDPIVOT_DEV_SKIP_PEER_CHECK")
                .map(|v| v == "1")
                .unwrap_or(false),
        }
    }
}

/// 对端是否为 Chrome Native Messaging 的 host 进程（非 App 内嵌 Agent）。
#[cfg(not(target_os = "android"))]
pub fn peer_is_native_host_executable(path: &Path, cfg: &PeerAuthConfig) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        == Some(cfg.expected_host_binary_name.as_str())
}

#[cfg(not(target_os = "android"))]
pub fn peer_is_askpass_executable(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        == Some("credpivot-askpass")
}

/// Git 的仓库上下文只接受 App 分发的适配程序，不能让任意进程伪造选择弹窗。
#[cfg(not(target_os = "android"))]
pub(crate) fn authorize_git_ssh_peer(pid: u32) -> Result<()> {
    #[cfg(target_os="macos")]
    {
        let peer=peer_executable_path(pid)?;
        let executable=std::env::current_exe()?;
        let bundled=executable.parent().and_then(Path::parent).ok_or_else(||AgentError::PeerDenied("App path unavailable".into()))?
            .join("Resources/credpivot-git-ssh");
        let installed=crate::paths::runtime_dir().join("git-ssh");
        let canonical=fs::canonicalize(&peer)?;
        let own=canonical.parent().and_then(Path::parent).is_some_and(|p|p==installed.as_path());
        if (own || paths_same_file(&peer,&bundled)?) && sha256_file(&peer)?==sha256_file(&bundled)? { return Ok(()); }
        Err(AgentError::PeerDenied("Git SSH helper is outdated or untrusted".into()))
    }
    #[cfg(not(target_os="macos"))]
    { let _=pid; Err(AgentError::PeerDenied("Git SSH integration requires macOS".into())) }
}

#[cfg(not(target_os = "android"))]
pub fn authorize_peer(pid: u32, cfg: &PeerAuthConfig) -> Result<()> {
    // Release 不接受环境变量或调用方构造配置绕过这道身份边界。
    if cfg!(debug_assertions) && cfg.dev_skip_peer_check {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let path = peer_executable_path(pid)?;
        if !path_is_trusted_native_host(&path, cfg)? {
            crate::diagnostics::error(
                "peer_auth",
                "peer executable not trusted",
            );
            return Err(AgentError::PeerDenied(format!(
                "peer executable not trusted: {}",
                path.display()
            )));
        }
        verify_peer_codesign_matches_self(&path)?;
        return Ok(());
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        let _ = cfg;
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn peer_bypass_is_debug_only() {
        let mut config = PeerAuthConfig::default();
        config.dev_skip_peer_check = true;
        // 不存在的 PID 只能被 Debug 绕过；Release 必须继续进入真实对端校验并拒绝。
        assert_eq!(authorize_peer(u32::MAX, &config).is_ok(), cfg!(debug_assertions));
    }
}

#[cfg(target_os = "macos")]
fn path_is_trusted_native_host(path: &Path, cfg: &PeerAuthConfig) -> Result<bool> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if file_name == "credpivot-askpass" {
        return path_is_trusted_askpass(path);
    }
    if file_name != cfg.expected_host_binary_name {
        return Ok(false);
    }
    if installed_native_host(path)? {
        return Ok(true);
    }
    if let Ok(trusted) = std::env::var("CREDPIVOT_TRUSTED_NATIVE_HOST") {
        let peer = fs::canonicalize(path).map_err(|e| AgentError::PeerDenied(e.to_string()))?;
        let expect = fs::canonicalize(&trusted).map_err(|e| AgentError::PeerDenied(e.to_string()))?;
        if peer == expect {
            return Ok(true);
        }
    }
    let s = path.to_string_lossy();
    Ok(s.contains(".app/Contents/MacOS/") || s.contains("CredPivot.app"))
}

#[cfg(target_os = "macos")]
fn paths_same_file(a: &Path, b: &Path) -> Result<bool> {
    if !a.exists() || !b.exists() {
        return Ok(false);
    }
    let a = fs::canonicalize(a).map_err(|e| AgentError::PeerDenied(e.to_string()))?;
    let b = fs::canonicalize(b).map_err(|e| AgentError::PeerDenied(e.to_string()))?;
    Ok(a == b)
}

#[cfg(target_os = "macos")]
fn sha256_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path).map_err(|e| AgentError::PeerDenied(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf).map_err(|e| AgentError::PeerDenied(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(target_os = "macos")]
fn path_is_trusted_askpass(path: &Path) -> Result<bool> {
    if paths_same_file(path, &materialized_askpass_path())? {
        return Ok(true);
    }
    if let Ok(trusted) = std::env::var("CREDPIVOT_TRUSTED_ASKPASS") {
        let peer = fs::canonicalize(path).map_err(|e| AgentError::PeerDenied(e.to_string()))?;
        let expect = fs::canonicalize(&trusted).map_err(|e| AgentError::PeerDenied(e.to_string()))?;
        if peer == expect {
            return Ok(true);
        }
    }
    let s = path.to_string_lossy();
    Ok(s.contains(".app/Contents/MacOS/") || s.contains("CredPivot.app"))
}

#[cfg(target_os = "macos")]
fn read_stored_askpass_digest() -> Option<String> {
    let body = fs::read_to_string(materialized_askpass_digest_path()).ok()?;
    let digest = body.trim().to_ascii_lowercase();
    if digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(digest)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn trusted_bundle_askpass_sha256() -> Result<String> {
    let trusted = std::env::var("CREDPIVOT_TRUSTED_ASKPASS")
        .map(PathBuf::from)
        .map_err(|_| AgentError::PeerDenied("trusted askpass not configured".into()))?;
    if !trusted.exists() {
        return Err(AgentError::PeerDenied(
            "trusted askpass path missing; reinstall from CredPivot App".into(),
        ));
    }
    if paths_same_file(&trusted, &materialized_askpass_path())? {
        return Err(AgentError::PeerDenied(
            "trusted reference must be App bundle binary, not ~/.credpivot copy".into(),
        ));
    }
    sha256_file(&trusted)
}

#[cfg(target_os = "macos")]
fn verify_materialized_askpass_digest(peer_path: &Path) -> Result<()> {
    if !paths_same_file(peer_path, &materialized_askpass_path())? {
        return Ok(());
    }
    let actual = sha256_file(peer_path)?;

    // 安装时写入的摘要与副本一致（优先，避免开发期 bundle 与 ~/.credpivot 短暂不一致）
    if read_stored_askpass_digest().as_deref() == Some(actual.as_str()) {
        return Ok(());
    }

    if let Ok(expected) = trusted_bundle_askpass_sha256() {
        if expected == actual {
            let _ = fs::write(materialized_askpass_digest_path(), format!("{actual}\n"));
            return Ok(());
        }
    }

    if read_stored_askpass_digest().is_some() {
        return Err(AgentError::PeerDenied(
            "materialized askpass out of date; click one-click SSH again or run make macos-sync-artifacts"
                .into(),
        ));
    }

    Err(AgentError::PeerDenied(
        "materialized askpass does not match trusted digest; reopen CredPivot App after build".into(),
    ))
}

/// Agent 启动时补齐可信 askpass 路径（与 Swift `applyTrustedAskpassEnv` 互补）。
pub fn bootstrap_trusted_askpass_env() {
    #[cfg(target_os = "macos")]
    {
        if std::env::var_os("CREDPIVOT_TRUSTED_ASKPASS").is_some() {
            return;
        }
        let path = crate::paths::materialized_askpass_trusted_ref_path();
        if let Ok(raw) = fs::read_to_string(&path) {
            let p = raw.trim();
            if !p.is_empty() && Path::new(p).exists() {
                std::env::set_var("CREDPIVOT_TRUSTED_ASKPASS", p);
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn installed_native_host(path: &Path) -> Result<bool> {
    if paths_same_file(path, &materialized_native_host_path())? { return Ok(true); }
    let directory = crate::paths::runtime_dir().join("native-host");
    if !directory.is_dir() { return Ok(false); }
    let parent = fs::canonicalize(&directory)?;
    let peer = fs::canonicalize(path)?;
    // 只接受固定目录下的一层摘要子目录，不能借助路径前缀或符号链接逃逸。
    Ok(peer.parent().and_then(Path::parent) == Some(parent.as_path())
        && peer.parent().and_then(Path::file_name).and_then(|s|s.to_str())
            .is_some_and(|s|s.len()==64 && s.bytes().all(|c|c.is_ascii_hexdigit())))
}

#[cfg(target_os = "macos")]
fn verify_materialized_native_host_digest(peer_path: &Path) -> Result<()> {
    if !installed_native_host(peer_path)? {
        return Ok(());
    }
    let trusted = std::env::var("CREDPIVOT_TRUSTED_NATIVE_HOST")
        .map(PathBuf::from)
        .map_err(|_| AgentError::PeerDenied("trusted native-host not configured".into()))?;
    if !trusted.exists() {
        return Err(AgentError::PeerDenied(
            "trusted native-host path missing; reinstall from CredPivot App".into(),
        ));
    }
    if paths_same_file(&trusted, peer_path)? {
        return Err(AgentError::PeerDenied(
            "trusted reference must be App bundle binary, not ~/.credpivot copy".into(),
        ));
    }
    let expected = sha256_file(&trusted)?;
    let actual = sha256_file(peer_path)?;
    if expected != actual {
        return Err(AgentError::PeerDenied(
            "native-host is outdated; reconnect to the installed version".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_peer_codesign_matches_self(peer_path: &Path) -> Result<()> {
    use std::process::Command;

    if paths_same_file(peer_path, &materialized_askpass_path())? {
        return verify_materialized_askpass_digest(peer_path);
    }
    if installed_native_host(peer_path)? {
        return verify_materialized_native_host_digest(peer_path);
    }

    let verify = Command::new("codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(peer_path)
        .status()
        .map_err(|e| AgentError::PeerDenied(e.to_string()))?;
    if !verify.success() {
        return Err(AgentError::PeerDenied("peer codesign verification failed".into()));
    }

    let self_path = std::env::current_exe()
        .map_err(|e| AgentError::PeerDenied(e.to_string()))?;
    let verify_self = Command::new("codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(&self_path)
        .status()
        .map_err(|e| AgentError::PeerDenied(e.to_string()))?;
    if !verify_self.success() {
        return Err(AgentError::PeerDenied("agent codesign verification failed".into()));
    }

    let peer_team = codesign_team_id(peer_path)?;
    let self_team = codesign_team_id(&self_path)?;
    match (peer_team, self_team) {
        (Some(p), Some(s)) if p == s => Ok(()),
        (None, None) => {
            if executables_in_same_macos_app_bundle(peer_path, &self_path) {
                Ok(())
            } else {
                Err(AgentError::PeerDenied(
                    "ad-hoc signed peer must reside in the same app bundle as agent".into(),
                ))
            }
        }
        _ => Err(AgentError::PeerDenied(
            "peer team identifier does not match agent".into(),
        )),
    }
}

#[cfg(target_os = "macos")]
fn macos_app_bundle_root(executable: &Path) -> Option<PathBuf> {
    let mut cur = fs::canonicalize(executable).ok()?;
    while cur.file_name().and_then(|n| n.to_str()) != Some("Contents") {
        if !cur.pop() {
            return None;
        }
    }
    if !cur.pop() {
        return None;
    }
    Some(cur)
}

#[cfg(target_os = "macos")]
fn executables_in_same_macos_app_bundle(a: &Path, b: &Path) -> bool {
    match (macos_app_bundle_root(a), macos_app_bundle_root(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

#[cfg(target_os = "macos")]
fn codesign_team_id(path: &Path) -> Result<Option<String>> {
    use std::process::Command;
    let output = Command::new("codesign")
        .args(["-dv", path.to_str().unwrap_or("")])
        .output()
        .map_err(|e| AgentError::PeerDenied(e.to_string()))?;
    let text = String::from_utf8_lossy(&output.stderr);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("TeamIdentifier=") {
            let t = rest.trim();
            if t == "not set" {
                return Ok(None);
            }
            return Ok(Some(t.to_string()));
        }
    }
    Ok(None)
}

#[cfg(target_os = "macos")]
pub fn peer_executable_path(pid: u32) -> Result<PathBuf> {
    use std::os::raw::c_void;
    extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut c_void, buffer_size: u32) -> i32;
    }
    let mut buf = [0u8; 4096];
    let rc = unsafe { proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
    if rc <= 0 {
        return Err(AgentError::PeerDenied("could not resolve peer executable path".into()));
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = std::str::from_utf8(&buf[..len])
        .map_err(|e| AgentError::PeerDenied(e.to_string()))?;
    Ok(PathBuf::from(s))
}
