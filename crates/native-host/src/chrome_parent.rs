use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParentCheckError {
    #[error("could not read parent process")]
    ParentUnknown,
    #[error("parent is not Google Chrome: {0}")]
    NotChrome(String),
}

/// M0: require direct parent executable name to be Google Chrome.
pub fn verify_chrome_parent() -> Result<(), ParentCheckError> {
    #[cfg(target_os = "macos")]
    {
        let ppid = parent_pid()?;
        let path = executable_path(ppid)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if name == "google chrome" || name == "google chrome canary" {
            let lower = path.to_string_lossy().to_lowercase();
            if lower.contains("/google chrome.app/")
                || lower.contains("/google chrome canary.app/")
            {
                return Ok(());
            }
            return Err(ParentCheckError::NotChrome(
                "chrome executable outside expected app bundle".into(),
            ));
        }
        return Err(ParentCheckError::NotChrome(path.display().to_string()));
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn parent_pid() -> Result<u32, ParentCheckError> {
    let pid = unsafe { libc::getppid() };
    if pid <= 1 {
        return Err(ParentCheckError::ParentUnknown);
    }
    Ok(pid as u32)
}

#[cfg(target_os = "macos")]
fn executable_path(pid: u32) -> Result<std::path::PathBuf, ParentCheckError> {
    use std::os::raw::c_void;
    extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut c_void, buffer_size: u32) -> i32;
    }
    let mut buf = [0u8; 4096];
    let rc = unsafe { proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
    if rc <= 0 {
        return Err(ParentCheckError::ParentUnknown);
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = std::str::from_utf8(&buf[..len]).map_err(|_| ParentCheckError::ParentUnknown)?;
    Ok(std::path::PathBuf::from(s))
}
