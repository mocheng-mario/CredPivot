use std::process::Command;

/// Ask macOS to launch CredPivot when the agent socket is unreachable.
pub fn launch_credpivot_app() {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open")
            .args(["-b", "com.credpivot.macos"])
            .status();
    }
}

/// 扩展连接时唤起 App，并写入待指纹确认标记。
pub fn launch_credpivot_app_for_extension_gate() {
    #[cfg(target_os = "macos")]
    {
        let fresh = credpivot_agent::touch_extension_gate_pending_if_absent()
            .unwrap_or(false);
        if fresh {
            let _ = Command::new("open")
                .args(["-b", "com.credpivot.macos"])
                .status();
        }
    }
}

pub async fn wait_for_agent_socket(path: &std::path::Path, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < timeout_ms as u128 {
        if tokio::net::UnixStream::connect(path).await.is_ok() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    false
}
