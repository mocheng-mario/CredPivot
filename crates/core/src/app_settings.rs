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
    pub auto_unlock_on_wake: bool,
    pub sensitive_auth_seconds: u64,
    pub browser_idle_seconds: u64,
    pub clipboard_clear_seconds: u64,
    pub master_password_days: u64,
    pub master_password_idle_hours: u64,
    pub restore_interval_hours: u64,
    pub restore_keep_count: usize,
    pub password_history_limit: usize,
    pub password_reminder_days: u32,
    pub ssh_sign_policy: String,
    pub git_ssh_auth_seconds: u64,
    pub git_ssh_trusted_repositories: Vec<String>,
    pub shortcut_search: String,
    pub shortcut_lock: String,
    pub shortcut_new: String,
    pub theme: String,
    pub accent_color: String,
    pub language: String,
    pub log_level: String,
    pub log_max_mb: u64,
    pub log_backup_count: usize,
    pub terminal_app_path: Option<String>,
    pub launch_at_login: Option<bool>,
    pub chrome_extension_id: Option<String>,
    pub vault_directory: Option<String>,
    pub webdav: Option<crate::sync::WebDavSettings>,
    // 每台设备独立保存各保险库的同步来源名，不通过业务快照覆盖其他设备的名称。
    pub sync_host_names: std::collections::BTreeMap<String, String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            version: 1,
            vault_idle_seconds: 300,
            auto_unlock_on_wake: true,
            sensitive_auth_seconds: 120,
            browser_idle_seconds: 300,
            clipboard_clear_seconds: 30,
            master_password_days: 7,
            master_password_idle_hours: 24,
            restore_interval_hours: 24,
            restore_keep_count: crate::MAX_RESTORE_POINTS,
            password_history_limit: 20,
            password_reminder_days: 90,
            ssh_sign_policy: "session".into(),
            git_ssh_auth_seconds: 300,
            git_ssh_trusted_repositories: Vec::new(),
            shortcut_search: "command+k".into(),
            shortcut_lock: "command+l".into(),
            shortcut_new: "command+n".into(),
            theme: "system".into(),
            accent_color: "#565DD9".into(),
            language: "zh-CN".into(),
            log_level: "info".into(),
            log_max_mb: 2,
            log_backup_count: 1,
            terminal_app_path: Some(String::new()),
            // 缺失表示还没选择。默认 false 会在启动时被当成关闭，并注销系统登录项。
            launch_at_login: None,
            // 缺失不是用户清空。空字符串才会移除已安装的浏览器连接。
            chrome_extension_id: None,
            vault_directory: None,
            webdav: None,
            sync_host_names: std::collections::BTreeMap::new(),
        }
    }
}

impl AppSettings {
    pub fn validate(&self) -> io::Result<()> {
        if crate::ssh_git::normalize_trusted_repositories(&self.git_ssh_trusted_repositories).is_err() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "Git 信任列表最多 100 个不同目标，需填写有效的 SSH 仓库地址或 Git 使用范围"));
        }
        let shortcuts = [&self.shortcut_search, &self.shortcut_lock, &self.shortcut_new];
        let mut seen = std::collections::HashSet::new();
        let valid = shortcuts.iter().all(|v| {
            let mut parts: Vec<_> = v.split('+').collect();
            parts.sort_unstable();
            let normalized = parts.join("+");
            valid_shortcut(v) && !matches!(normalized.as_str(),
                "c+command" | "command+v" | "command+x" | "a+command"
                | "command+z" | "command+shift+z" | "command+w" | "command+q"
                | "command+h" | "command+m")
                && (v.is_empty() || seen.insert(normalized))
        })
            && matches!(self.ssh_sign_policy.as_str(), "session" | "confirm" | "biometric")
            && self.password_history_limit <= 50
            && self.password_reminder_days <= 3650
            && matches!(self.theme.as_str(), "system" | "light" | "dark")
            && self.accent_color.len() == 7
            && self.accent_color.starts_with('#')
            && self.accent_color.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit)
            && !self.language.is_empty() && self.language.len() <= 64
            && self.language.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            && self.webdav.as_ref().is_none_or(|s| s.valid())
            && self.sync_host_names.len() <= 128
            && self.sync_host_names.iter().all(|(id, name)| {
                uuid::Uuid::parse_str(id).is_ok() && crate::sync::valid_host_name(name)
            })
            && self.version == 1
            && (60..=1800).contains(&self.vault_idle_seconds)
            && self.vault_idle_seconds % 60 == 0
            && self.sensitive_auth_seconds <= 300
            && self.git_ssh_auth_seconds <= 1800
            && self.git_ssh_auth_seconds % 60 == 0
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
        self.ssh_sign_policy != other.ssh_sign_policy
            || self.git_ssh_auth_seconds != other.git_ssh_auth_seconds
            || self.git_ssh_trusted_repositories != other.git_ssh_trusted_repositories
            || self.vault_idle_seconds != other.vault_idle_seconds
            || self.sensitive_auth_seconds != other.sensitive_auth_seconds
            || self.browser_idle_seconds != other.browser_idle_seconds
            || self.clipboard_clear_seconds != other.clipboard_clear_seconds
            || self.master_password_days != other.master_password_days
            || self.master_password_idle_hours != other.master_password_idle_hours
    }

    pub fn trusts_git_repository(&self, identity: &str) -> bool {
        self.git_ssh_trusted_repositories.iter().any(|value| {
            crate::ssh_git::trusted_repository_matches(value, identity)
        })
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
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(AppSettings::default()),
        Err(e) => Err(e),
    }
}

pub fn effective_app_settings() -> AppSettings {
    read_app_settings().unwrap_or_else(|_| {
        // 手工编辑出错时不放宽安全窗口，也不覆盖损坏文件；设置页可恢复默认值。
        AppSettings {
            vault_idle_seconds: 60,
            sensitive_auth_seconds: 0,
            git_ssh_auth_seconds: 0,
            ssh_sign_policy: "biometric".into(),
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
    let mut settings = settings.clone();
    settings.git_ssh_trusted_repositories = crate::ssh_git::normalize_trusted_repositories(&settings.git_ssh_trusted_repositories)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Git 信任列表无效"))?;
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
    let bytes = serde_json::to_vec_pretty(&settings).map_err(io::Error::other)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(next, path)
}

// 仅支持可明确映射的单个主键，空值停用；限制组合避免误注册普通文字键。
fn valid_shortcut(value: &str) -> bool {
    if value.is_empty() { return true; }
    let parts: Vec<_> = value.split('+').collect();
    let Some(key) = parts.last() else { return false; };
    let mut seen = std::collections::HashSet::new();
    parts.len() >= 2 && parts.len() <= 5
        && parts[..parts.len()-1].iter().all(|m| matches!(*m,"command"|"control"|"option"|"shift") && seen.insert(*m))
        && (seen.contains("command") || seen.contains("control"))
        && (*key == "space" || (key.len() == 1 && key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())))
}
