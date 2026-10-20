use crate::error::{AgentError, Result};
use crate::paths::{
    materialized_askpass_digest_path, materialized_askpass_path, materialized_native_host_path,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

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
            dev_skip_peer_check: std::env::var("CREDPIVOT_DEV_SKIP_PEER_CHECK")
                .map(|v| v == "1")
                .unwrap_or(false),
        }
    }
}

/// 对端是否为 Chrome Native Messaging 的 host 进程（非 App 内嵌 Agent）。
pub fn peer_is_native_host_executable(path: &Path, cfg: &PeerAuthConfig) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        == Some(cfg.expected_host_binary_name.as_str())
}

pub fn peer_is_askpass_executable(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        == Some("credpivot-askpass")
}

pub fn authorize_peer(pid: u32, cfg: &PeerAuthConfig) -> Result<()> {
    if cfg.dev_skip_peer_check {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let path = peer_executable_path(pid)?;
        if !path_is_trusted_native_host(&path, cfg)? {
            crate::diagnostics::error(
                "peer_auth",
                format!("peer executable not trusted: {}", path.display()),
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
    if paths_same_file(path, &materialized_native_host_path())? {
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
fn expected_materialized_askpass_sha256() -> Result<String> {
    if let Ok(trusted) = std::env::var("CREDPIVOT_TRUSTED_ASKPASS") {
        let path = PathBuf::from(trusted);
        if path.exists() {
            if paths_same_file(&path, &materialized_askpass_path())? {
                return Err(AgentError::PeerDenied(
                    "trusted reference must be App bundle binary, not ~/.credpivot copy".into(),
                ));
            }
            return sha256_file(&path);
        }
    }
    let digest_path = materialized_askpass_digest_path();
    let body = fs::read_to_string(&digest_path).map_err(|_| {
        AgentError::PeerDenied(
            "trusted askpass not configured; open CredPivot and retry one-click SSH".into(),
        )
    })?;
    let digest = body.trim();
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AgentError::PeerDenied(
            "invalid askpass.sha256; reinstall askpass from CredPivot App".into(),
        ));
    }
    Ok(digest.to_ascii_lowercase())
}

#[cfg(target_os = "macos")]
fn verify_materialized_askpass_digest(peer_path: &Path) -> Result<()> {
    if !paths_same_file(peer_path, &materialized_askpass_path())? {
        return Ok(());
    }
    let expected = expected_materialized_askpass_sha256()?;
    let actual = sha256_file(peer_path)?;
    if expected != actual {
        return Err(AgentError::PeerDenied(
            "materialized askpass does not match trusted digest".into(),
        ));
    }
    Ok(())
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
fn verify_materialized_native_host_digest(peer_path: &Path) -> Result<()> {
    if !paths_same_file(peer_path, &materialized_native_host_path())? {
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
            "materialized native-host does not match App bundle binary".into(),
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
    if paths_same_file(peer_path, &materialized_native_host_path())? {
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
