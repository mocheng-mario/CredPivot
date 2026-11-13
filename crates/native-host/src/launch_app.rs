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
