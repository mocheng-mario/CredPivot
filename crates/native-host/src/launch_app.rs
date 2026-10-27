use std::process::Command;

/// 浏览器拉起 App 时保持后台，由原生协调器弹出验证窗口。
pub fn launch_credpivot_app() -> bool {
    #[cfg(target_os = "macos")]
    {
        let file = credpivot_agent::runtime_dir().join("native_host_app.path");
        let Ok(path) = std::fs::read_to_string(file) else { return false; };
        let app = std::path::Path::new(path.trim());
        if !app.is_absolute() || app.extension().and_then(|s|s.to_str()) != Some("app") || !app.is_dir() { return false; }
        let Ok(info) = Command::new("/usr/bin/plutil").args(["-extract", "CFBundleIdentifier", "raw", "-o", "-"])
            .arg(app.join("Contents/Info.plist")).output() else { return false; };
        if !info.status.success() || String::from_utf8_lossy(&info.stdout).trim() != "com.credpivot.macos" { return false; }
        return Command::new("/usr/bin/open").args(["-g", "-a"]).arg(app)
            .args(["--args", "--credpivot-browser-background"]).status().is_ok_and(|status| status.success());
    }
    #[cfg(not(target_os = "macos"))]
    { false }
}

pub async fn wait_for_agent_socket(path: &std::path::Path, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < timeout_ms as u128 {
        if matches!(tokio::time::timeout(std::time::Duration::from_millis(200), tokio::net::UnixStream::connect(path)).await, Ok(Ok(_))) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn existing_socket_file_is_not_enough_for_readiness() {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("cp-{nonce}.sock"));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        assert!(wait_for_agent_socket(&path, 500).await);
        drop(listener);
        assert!(path.exists());
        assert!(!wait_for_agent_socket(&path, 20).await);
        std::fs::remove_file(&path).unwrap();
    }
}
