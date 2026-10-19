use crate::error::{AgentError, Result};

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
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if file_name == cfg.expected_host_binary_name {
            return Ok(());
        }
        // Same-team signed host is validated in native-host parent check; App accepts our host binary path.
        if path.to_string_lossy().contains("CredPivot.app") && file_name == cfg.expected_host_binary_name {
            return Ok(());
        }
        return Err(AgentError::PeerDenied(format!(
            "unexpected peer executable: {}",
            path.display()
        )));
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn peer_executable_path(pid: u32) -> Result<std::path::PathBuf> {
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
    Ok(std::path::PathBuf::from(s))
}
