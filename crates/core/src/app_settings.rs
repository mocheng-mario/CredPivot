use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;

static SETTINGS_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// 本机偏好，不属于保险库备份；身份验证时间和解锁材料仍由钥匙串保存。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppSettings {
    pub version: u32,
    pub vault_idle_seconds: u64,
    pub sensitive_auth_seconds: u64,
    pub browser_idle_seconds: u64,
    pub clipboard_clear_seconds: u64,
    pub master_password_days: u64,
    pub master_password_idle_hours: u64,
    pub restore_interval_hours: u64,
    pub restore_keep_count: usize,
    pub password_history_limit: usize,
    pub password_reminder_days: u32,
    pub theme: String,
    pub language: String,
    pub log_level: String,
    pub log_max_mb: u64,
    pub log_backup_count: usize,
    // None 仅用于首次从 macOS 偏好迁入；迁入后写入明确的值。
    pub terminal_app_path: Option<String>,
    pub launch_at_login: Option<bool>,
    pub chrome_extension_id: Option<String>,
    pub vault_directory: Option<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            version: 1,
            vault_idle_seconds: 300,
            sensitive_auth_seconds: 120,
            browser_idle_seconds: 300,
            clipboard_clear_seconds: 30,
            master_password_days: 7,
            master_password_idle_hours: 24,
            restore_interval_hours: 24,
            restore_keep_count: crate::MAX_RESTORE_POINTS,
            password_history_limit: 20,
            password_reminder_days: 90,
            theme: "system".into(),
            language: "zh-CN".into(),
            log_level: "info".into(),
            log_max_mb: 2,
            log_backup_count: 1,
            terminal_app_path: None,
            launch_at_login: None,
            chrome_extension_id: None,
            vault_directory: None,
        }
    }
}

impl AppSettings {
    pub fn validate(&self) -> io::Result<()> {
        let valid = self.password_history_limit <= 50
            && self.password_reminder_days <= 3650
            && matches!(self.theme.as_str(), "system" | "light" | "dark")
            && !self.language.is_empty() && self.language.len() <= 64
            && self.language.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            && self.version == 1
            && (60..=1800).contains(&self.vault_idle_seconds)
            && self.vault_idle_seconds % 60 == 0
            && self.sensitive_auth_seconds <= 300
            && (60..=1800).contains(&self.browser_idle_seconds)
            && self.browser_idle_seconds % 60 == 0
            && (5..=300).contains(&self.clipboard_clear_seconds)
            && (1..=7).contains(&self.master_password_days)
            && (1..=24).contains(&self.master_password_idle_hours)
            && (1..=24).contains(&self.restore_interval_hours)
            && (1..=100).contains(&self.restore_keep_count)
            && matches!(self.log_level.as_str(), "debug" | "info" | "warn" | "error")
            && (1..=100).contains(&self.log_max_mb)
            && (1..=10).contains(&self.log_backup_count)
            && self.terminal_app_path.as_ref().map_or(true, |p| {
                p.is_empty() || (p.starts_with('/') && p.ends_with(".app") && p.len() <= 4096)
            })
            && self.chrome_extension_id.as_ref().map_or(true, |id| {
                id.is_empty() || (id.len() == 32 && id.bytes().all(|c| (b'a'..=b'p').contains(&c)))
            })
            && self
                .vault_directory
                .as_ref()
                .map_or(true, |p| p.starts_with('/') && p.len() <= 4096);
        if valid {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "配置值超出允许范围，或配置版本不受支持",
            ))
        }
    }

    pub fn security_differs(&self, other: &Self) -> bool {
        self.vault_idle_seconds != other.vault_idle_seconds
            || self.sensitive_auth_seconds != other.sensitive_auth_seconds
            || self.browser_idle_seconds != other.browser_idle_seconds
            || self.clipboard_clear_seconds != other.clipboard_clear_seconds
            || self.master_password_days != other.master_password_days
            || self.master_password_idle_hours != other.master_password_idle_hours
    }
}

pub fn app_settings_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".credpivot/settings.json")
}

pub fn read_app_settings() -> io::Result<AppSettings> {
    let path = app_settings_path();
    match fs::read(path) {
        Ok(bytes) => {
            let settings: AppSettings = serde_json::from_slice(&bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "配置文件 JSON 格式无效")
            })?;
            settings.validate()?;
            Ok(settings)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut settings = AppSettings::default();
            // 首次生成统一配置时保留原有日志级别和浏览器空闲时间。
            let parent = app_settings_path().parent().unwrap().to_path_buf();
            if let Ok(level) = fs::read_to_string(parent.join("log_level")) {
                if matches!(level.trim(), "debug" | "info" | "warn" | "error") {
                    settings.log_level = level.trim().into();
                }
            }
            if let Ok(seconds) = fs::read_to_string(parent.join("extension_gate_idle_secs")) {
                if let Ok(value) = seconds.trim().parse::<u64>() {
                    if (60..=1800).contains(&value) && value % 60 == 0 {
                        settings.browser_idle_seconds = value;
                    }
                }
            }
            if let Ok(directory) = fs::read_to_string(parent.join("active_vault_dir")) {
                let directory = directory.trim();
                if PathBuf::from(directory).join("vault.json").is_file() {
                    settings.vault_directory = Some(directory.into());
                }
            }
            Ok(settings)
        }
        Err(e) => Err(e),
    }
}

pub fn effective_app_settings() -> AppSettings {
    read_app_settings().unwrap_or_else(|_| {
        // 手工编辑出错时不放宽安全窗口，也不覆盖损坏文件；设置页可恢复默认值。
        AppSettings {
            vault_idle_seconds: 60,
            sensitive_auth_seconds: 0,
            browser_idle_seconds: 60,
            clipboard_clear_seconds: 5,
            master_password_days: 1,
            master_password_idle_hours: 1,
            ..AppSettings::default()
        }
    })
}

/// 恢复默认前保留原始文件；即使 JSON 损坏，也不能用回退值代替原内容。
pub fn backup_app_settings() -> io::Result<Option<PathBuf>> {
    let _guard = SETTINGS_WRITE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let source = app_settings_path();
    let bytes = match fs::read(&source) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let backup = source.with_file_name(format!(
        "settings.backup-{}-{}.json",
        crate::repo::now_ms(),
        uuid::Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&backup)?;
    if let Err(e) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&backup);
        return Err(e);
    }
    Ok(Some(backup))
}

pub fn write_app_settings(settings: &AppSettings) -> io::Result<()> {
    settings.validate()?;
    let _guard = SETTINGS_WRITE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let path = app_settings_path();
    let parent = path.parent().unwrap();
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let next = path.with_extension("json.next");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&next)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let bytes = serde_json::to_vec_pretty(settings).map_err(io::Error::other)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(next, path)
}
