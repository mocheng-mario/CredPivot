//! 浏览器插件里的通行密钥站点开关副本。不写入保险库，也不参与同步。

use serde_json::{Map, Value};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

fn path() -> PathBuf {
    crate::paths::runtime_dir().join("passkey-sites.json")
}

fn load() -> (Map<String, Value>, Vec<String>) {
    let Ok(bytes) = fs::read(path()) else {
        return (Map::new(), Vec::new());
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return (Map::new(), Vec::new());
    };
    let sites = value
        .get("sites")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let pending = value
        .get("pending")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    (sites, pending)
}

fn valid_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty()
        && !host.contains('@')
        && origin.len() <= 2048
        && !origin.chars().any(char::is_control)
}

fn save(sites: &Map<String, Value>, pending: &[String]) -> io::Result<()> {
    crate::paths::ensure_runtime_dir()?;
    let body = serde_json::to_vec(&serde_json::json!({ "sites": sites, "pending": pending }))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let target = path();
    let temporary = target.with_extension("json.tmp");
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&body)?;
        file.sync_all()?;
    }
    fs::rename(temporary, target)
}

/// 插件上报当前开关。已经出现在上报里的地址会从待开启队列移除，包括手动关闭。
pub fn report(sites: &Value) -> io::Result<Vec<String>> {
    let Some(incoming) = sites.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "站点开关无效",
        ));
    };
    if incoming.len() > 500 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "站点开关过多",
        ));
    }
    let mut clean = Map::new();
    for (origin, enabled) in incoming {
        if valid_origin(origin) && enabled.is_boolean() {
            clean.insert(origin.clone(), enabled.clone());
        }
    }
    let (_, mut pending) = load();
    pending.retain(|origin| !clean.contains_key(origin));
    save(&clean, &pending)?;
    Ok(pending)
}

/// 只在插件还没有这个站点记录时排队自动开启。已有的手动关闭保持关闭。
pub fn queue_if_unset(origin: &str) {
    if !valid_origin(origin) {
        return;
    }
    let (sites, mut pending) = load();
    if sites.contains_key(origin) || pending.iter().any(|item| item == origin) {
        return;
    }
    pending.push(origin.to_string());
    let _ = save(&sites, &pending);
}

pub fn snapshot() -> Value {
    let (sites, _) = load();
    serde_json::json!({ "sites": sites })
}
