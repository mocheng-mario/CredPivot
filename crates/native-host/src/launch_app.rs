use std::process::Command;

/// 浏览器拉起 App 时保持后台，由原生协调器弹出验证窗口。
pub fn launch_credpivot_app() {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open")
            .args([
                "-g",
                "-b",
                "com.credpivot.macos",
                "--args",
                "--credpivot-browser-background",
            ])
            .status();
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
