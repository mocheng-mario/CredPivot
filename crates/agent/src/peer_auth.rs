use crate::error::{AgentError, Result};
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

pub fn authorize_peer(pid: u32, cfg: &PeerAuthConfig) -> Result<()> {
    if cfg.dev_skip_peer_check {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let path = peer_executable_path(pid)?;
        if !path_is_trusted_native_host(&path, cfg)? {
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
    if file_name != cfg.expected_host_binary_name {
        return Ok(false);
    }
    if let Ok(trusted) = std::env::var("CREDPIVOT_TRUSTED_NATIVE_HOST") {
        let peer = std::fs::canonicalize(path).map_err(|e| AgentError::PeerDenied(e.to_string()))?;
        let expect = std::fs::canonicalize(&trusted).map_err(|e| AgentError::PeerDenied(e.to_string()))?;
        return Ok(peer == expect);
    }
    let s = path.to_string_lossy();
    Ok(s.contains(".app/Contents/MacOS/") || s.contains("CredPivot.app"))
}

#[cfg(target_os = "macos")]
fn verify_peer_codesign_matches_self(peer_path: &Path) -> Result<()> {
    use std::process::Command;

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
        (None, None) => Ok(()),
        _ => Err(AgentError::PeerDenied(
            "peer team identifier does not match agent".into(),
        )),
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
fn peer_executable_path(pid: u32) -> Result<PathBuf> {
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
