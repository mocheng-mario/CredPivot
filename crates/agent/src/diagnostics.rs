use crate::paths::runtime_dir;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

static LOG_MUTEX: Mutex<()> = Mutex::new(());

pub fn log_file_path() -> PathBuf {
    runtime_dir().join("logs").join("agent.log")
}

pub fn init() {
    let _ = write_line("INFO", "agent", "diagnostics initialized");
}

pub fn error(target: &str, message: impl AsRef<str>) {
    let _ = write_line("ERROR", target, message.as_ref());
}

fn write_line(level: &str, target: &str, message: &str) -> std::io::Result<()> {
    let _guard = LOG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let path = log_file_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    let line = format!("{ts}\t{level}\t{target}\t{message}\n");
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

/// 读取日志尾部若干行（按行截断，默认最多约 512KB）。
pub fn tail_lines(max_lines: usize) -> String {
    let path = log_file_path();
    let data = match fs::read(&path) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    const MAX_BYTES: usize = 512 * 1024;
    let slice = if data.len() > MAX_BYTES {
        &data[data.len() - MAX_BYTES..]
    } else {
        &data[..]
    };
    let text = String::from_utf8_lossy(slice);
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= max_lines {
        return lines.join("\n");
    }
    lines[lines.len() - max_lines..].join("\n")
}
