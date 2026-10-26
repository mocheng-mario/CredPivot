use crate::paths::{ensure_runtime_dir, runtime_dir};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static LOG_MUTEX: Mutex<()> = Mutex::new(());
const LOG_HEADER: &[u8] = b"# CredPivot events v1\n";
const MAX_TAIL_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

pub fn log_file_path() -> PathBuf {
    daily_log_path(chrono::Local::now().date_naive())
}

fn daily_log_path(date: chrono::NaiveDate) -> PathBuf {
    runtime_dir().join("logs").join(format!("agent-{date}.log"))
}

/// 各进程读取统一配置，使已运行的 Native Host / askpass 也沿用新级别。
pub fn level() -> LogLevel {
    match credpivot_core::effective_app_settings().log_level.as_str() {
        "debug" => LogLevel::Debug,
        "warn" => LogLevel::Warn,
        "error" => LogLevel::Error,
        _ => LogLevel::Info,
    }
}

pub fn set_level(level: LogLevel) -> std::io::Result<()> {
    let mut settings = credpivot_core::read_app_settings()?;
    settings.log_level = level.as_str().into();
    credpivot_core::write_app_settings(&settings)
}

pub fn init() {
    info("agent", "diagnostics initialized");
}

// 只接受静态事件文案；禁止传入异常全文、请求/响应、路径、用户名或凭据。
pub fn debug(target: &'static str, event: &'static str) {
    log(LogLevel::Debug, target, event);
}

pub fn info(target: &'static str, event: &'static str) {
    log(LogLevel::Info, target, event);
}

pub fn warn(target: &'static str, event: &'static str) {
    log(LogLevel::Warn, target, event);
}

pub fn error(target: &'static str, event: &'static str) {
    log(LogLevel::Error, target, event);
}

fn log(level: LogLevel, target: &'static str, event: &'static str) {
    if level < self::level() {
        return;
    }
    if write_line(level, target, event).is_err() {
        // 写日志失败不能影响凭据操作，也不能把可能含路径的 I/O 异常写入 stderr。
        eprintln!("ERROR credpivot diagnostics write failed");
    }
}

fn private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn lock_log_directory() -> std::io::Result<File> {
    ensure_runtime_dir()?;
    let dir = runtime_dir().join("logs");
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    let file = private_file(&dir.join("write.lock"))?;
    // 多进程共用日志；文件关闭时释放锁，避免轮转与其他进程的追加互相覆盖。
    file.lock_exclusive()?;
    Ok(file)
}

fn open_log(path: &Path, rotate: bool) -> std::io::Result<File> {
    let settings = credpivot_core::effective_app_settings();
    let mut file = private_file(path)?;
    let mut header = vec![0; LOG_HEADER.len()];
    let valid_header = match file.read_exact(&mut header) {
        Ok(()) => header.as_slice() == LOG_HEADER,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => false,
        Err(e) => return Err(e),
    };
    if !valid_header {
        // 旧版本可能记录异常中的隐私数据，不把旧格式内容继续展示或保留为备份。
        for index in 1..=10 {
            match fs::remove_file(path.with_extension(format!("log.{index}"))) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(LOG_HEADER)?;
    }
    // 大小限制和分卷保留数量只作用于当天文件；不自动删除其他日期的日志。
    for index in (settings.log_backup_count + 1)..=10 {
        match fs::remove_file(path.with_extension(format!("log.{index}"))) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    if rotate && file.metadata()?.len() >= settings.log_max_mb * 1024 * 1024 {
        for index in (1..settings.log_backup_count).rev() {
            match fs::rename(path.with_extension(format!("log.{index}")), path.with_extension(format!("log.{}", index + 1))) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        fs::rename(path, path.with_extension("log.1"))?;
        file = private_file(path)?;
        file.write_all(LOG_HEADER)?;
    }
    Ok(file)
}

fn write_line(level: LogLevel, target: &str, event: &str) -> std::io::Result<()> {
    let _guard = LOG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _file_lock = lock_log_directory()?;
    // 文件日期和事件时间取自同一时刻，避免跨午夜时记录落入错误日期。
    let now = chrono::Local::now();
    let path = daily_log_path(now.date_naive());
    let mut file = open_log(&path, true)?;
    file.seek(SeekFrom::End(0))?;
    let ts = now.format("%Y-%m-%d %H:%M:%S%.3f");
    writeln!(
        file,
        "{ts}\t{}\t{target}\t{event}",
        level.as_str().to_ascii_uppercase()
    )
}

/// 只读取当天最后约 512KB，并按新到旧返回，避免日志变大时整文件载入内存。
pub fn tail_lines(max_lines: usize) -> String {
    read_log(None, max_lines).map(|(_, text, _)| text)
        .unwrap_or_else(|_| "ERROR diagnostics log unavailable".into())
}

/// 只接受本应用固定的日志命名，不能把客户端提供的路径直接拼进读取操作。
fn log_file_key(name: &str) -> Option<(&str, u8)> {
    let (stem, suffix) = name.split_once(".log")?;
    let date = if stem == "agent" { "" } else {
        let date = stem.strip_prefix("agent-")?;
        if date.len() != 10 || chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_err() { return None; }
        date
    };
    let part = if suffix.is_empty() { 0 } else {
        let value = suffix.strip_prefix('.')?;
        let part: u8 = value.parse().ok()?;
        if !(1..=10).contains(&part) || value != part.to_string() { return None; }
        part
    };
    Some((date, part))
}

/// 路径、文件列表和内容在同一个锁内取样，避免分卷或跨午夜时展示不一致。
pub(crate) fn read_log(selected: Option<&str>, max_lines: usize) -> std::io::Result<(PathBuf, String, Vec<String>)> {
    let _guard = LOG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _file_lock = lock_log_directory()?;
    let current = log_file_path();
    let directory = current.parent().ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() { continue; }
        let Ok(name) = entry.file_name().into_string() else { continue; };
        if log_file_key(&name).is_some() { files.push(name); }
    }
    // 当天还没有符合记录级别的事件时，也允许选择当天空日志。
    let today = current.file_name().and_then(|v| v.to_str()).unwrap_or_default().to_string();
    if !files.contains(&today) { files.push(today); }
    files.sort_by(|a, b| {
        let (ad, ap) = log_file_key(a).unwrap_or_default();
        let (bd, bp) = log_file_key(b).unwrap_or_default();
        bd.cmp(ad).then_with(|| ap.cmp(&bp))
    });
    let path = match selected {
        Some(name) if log_file_key(name).is_some() && files.iter().any(|f| f == name) => directory.join(name),
        Some(_) => return Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        None => current.clone(),
    };
    let read = || -> std::io::Result<String> {
        // 历史日志只读，不能因选中旧文件就清理分卷、创建缺失文件或重写文件头。
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && path == current => return Ok(String::new()),
            Err(e) => return Err(e),
            Ok(metadata) if !metadata.is_file() => return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)),
            Ok(_) => {}
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&path)?;
        let mut header = vec![0; LOG_HEADER.len()];
        file.read_exact(&mut header)?;
        if header.as_slice() != LOG_HEADER {
            // 旧的不安全日志格式不能展示；保留文件但不返回可能包含隐私的正文。
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        let start = file.metadata()?.len().saturating_sub(MAX_TAIL_BYTES);
        file.seek(SeekFrom::Start(start))?;
        let mut data = Vec::new();
        file.take(MAX_TAIL_BYTES).read_to_end(&mut data)?;
        let text = String::from_utf8_lossy(&data);
        let mut lines = text.lines();
        if start > 0 {
            // 截断点可能落在一行或一个 UTF-8 字符中，丢弃第一条不完整事件。
            lines.next();
        }
        let lines: Vec<_> = lines.filter(|line| !line.starts_with('#')).collect();
        Ok(lines.into_iter().rev().take(max_lines.min(2000)).collect::<Vec<_>>().join("\n"))
    };
    let text = read()?;
    Ok((path, text, files))
}
