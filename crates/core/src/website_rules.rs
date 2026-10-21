use crate::credential_management::{details_for, UriRule};
use crate::{CoreError, Result};
use regex::{Regex, RegexBuilder};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use url::Url;

fn website_url(value: &str) -> Result<Url> {
    let value = value.trim();
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(CoreError::format("请输入有效网站，长度不能超过 4096 字节"));
    }
    let value = if value.contains("://") {
        value.to_string()
    } else {
        format!("https://{value}")
    };
    let url = Url::parse(&value).map_err(|_| CoreError::format("网站地址无效"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_some_and(|host| host.contains('*'))
    {
        return Err(CoreError::format(
            "仅支持不含用户名和密码的 HTTP / HTTPS 网站",
        ));
    }
    Ok(url)
}

fn compile_regex(pattern: &str) -> Result<Regex> {
    if pattern.trim().is_empty() || pattern.len() > 4096 {
        return Err(CoreError::format(
            "请输入正则表达式，长度不能超过 4096 字节",
        ));
    }
    // 先校验用户表达式本身，防止括号恰好与外层锚定分组配对而被误判为合法。
    let _ = RegexBuilder::new(pattern)
        .size_limit(512 * 1024)
        .dfa_size_limit(512 * 1024)
        .nest_limit(64)
        .build()
        .map_err(|e| CoreError::format(format!("正则表达式无效或过于复杂：{e}")))?;
    // 全串匹配避免把 example.com.evil.test 当作 example.com；限制编译资源。
    RegexBuilder::new(&format!(r"\A(?:{})\z", pattern))
        .size_limit(512 * 1024)
        .dfa_size_limit(512 * 1024)
        .nest_limit(64)
        .build()
        .map_err(|e| CoreError::format(format!("正则表达式无效或过于复杂：{e}")))
}

fn wildcard_regex(pattern: &str) -> Result<Regex> {
    let value = pattern.trim();
    let value = if value.contains("://") {
        value.to_string()
    } else {
        format!("https://{value}")
    };
    let (scheme, authority) = value
        .split_once("://")
        .ok_or_else(|| CoreError::format("通配符地址无效"))?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    let host = authority.split(':').next().unwrap_or("");
    if !matches!(scheme.as_str(), "http" | "https")
        || authority
            .chars()
            .any(|c| matches!(c, '/' | '?' | '#' | '@' | '\\'))
        || !host.is_ascii()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*'))
        || !host.replace('*', "").contains('.')
    {
        return Err(CoreError::format(
            "请输入具体域名，例如 https://*.example.com；* 仅用于域名，不支持路径",
        ));
    }
    let url = website_url(&value.replace('*', "wildcard"))?;
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    let host = regex::escape(&host.to_ascii_lowercase()).replace(r"\*", "[^/:]*");
    compile_regex(&format!(
        "{}://{}{}",
        url.scheme(),
        host,
        regex::escape(&port)
    ))
}

fn validate_rule(rule: &UriRule) -> Result<()> {
    if rule.uri.len() > 4096 || rule.match_mode.len() > 100 {
        return Err(CoreError::limit("网站匹配规则超出长度限制"));
    }
    match rule.match_mode.as_str() {
        "exact_origin" | "bitwarden_default" => {
            website_url(&rule.uri)?;
        }
        "wildcard" => {
            wildcard_regex(&rule.uri)?;
        }
        "regex" => {
            if rule.uri.trim().is_empty() {
                return Err(CoreError::format("正则表达式不能为空"));
            }
            compile_regex(rule.uri.trim())?;
        }
        // 未识别的导入模式只保留，不隐式扩大原凭据的匹配范围。
        _ => {}
    }
    Ok(())
}

pub fn validate_website_rules(rules: &[UriRule]) -> Result<()> {
    if rules.len() > 100 {
        return Err(CoreError::limit("每个账号最多配置 100 条网站规则"));
    }
    for (index, rule) in rules.iter().enumerate() {
        validate_rule(rule)
            .map_err(|e| CoreError::format(format!("第 {} 条网站规则：{e}", index + 1)))?;
    }
    Ok(())
}

fn rule_matches(rule: &UriRule, page: &Url) -> Result<bool> {
    if rule.uri.len() > 4096 || rule.match_mode.len() > 100 {
        return Err(CoreError::limit("网站匹配规则超出长度限制"));
    }
    let origin = page.origin().ascii_serialization();
    match rule.match_mode.as_str() {
        "exact_origin" | "bitwarden_default" => {
            let expected = website_url(&rule.uri)?;
            let a = expected.host_str().unwrap_or("");
            let b = page.host_str().unwrap_or("");
            // 保持旧版本 www 与非 www 的等价行为，其他协议、端口和域名必须一致。
            Ok(expected.scheme() == page.scheme()
                && expected.port_or_known_default() == page.port_or_known_default()
                && a.strip_prefix("www.").unwrap_or(a) == b.strip_prefix("www.").unwrap_or(b))
        }
        "wildcard" => Ok(wildcard_regex(&rule.uri)?.is_match(&origin)),
        "regex" => Ok(compile_regex(rule.uri.trim())?.is_match(&origin)),
        _ => Ok(false),
    }
}

pub fn test_website_rules(rules: &[UriRule], target: &str) -> Result<Value> {
    if rules.len() > 100 {
        return Err(CoreError::limit("每个账号最多配置 100 条网站规则"));
    }
    let page = website_url(target)?;
    let results: Vec<Value> = rules.iter().enumerate().map(|(index, rule)| {
        match rule_matches(rule, &page) {
            Ok(matched) => json!({"index":index,"matched":matched,"inactive":!matches!(rule.match_mode.as_str(),"exact_origin"|"bitwarden_default"|"wildcard"|"regex")}),
            Err(e) => json!({"index":index,"matched":false,"error":e.to_string()}),
        }
    }).collect();
    Ok(
        json!({"origin":page.origin().ascii_serialization(),"matched":results.iter().any(|r|r["matched"]==true),"results":results}),
    )
}

pub fn credential_website_rules(conn: &Connection, credential: &str) -> Result<Vec<UriRule>> {
    let row = crate::repo_m2::get_login_row(conn, credential)?;
    let details = details_for(conn, &row.item_id)?;
    if details.uris.is_empty() {
        return Ok(vec![UriRule {
            uri: row.origin,
            match_mode: "exact_origin".into(),
        }]);
    }
    Ok(details.uris)
}

pub fn credential_matches_origin(
    conn: &Connection,
    credential: &str,
    origin: &str,
) -> Result<bool> {
    let page = website_url(origin)?;
    let rules = credential_website_rules(conn, credential)?;
    if rules.len() > 100 {
        return Ok(false);
    }
    Ok(rules
        .iter()
        .any(|rule| rule_matches(rule, &page).unwrap_or(false)))
}

/// 由账号保存事务调用，不单独提交，也不改变密码或其他详情。
pub(crate) fn save_login_website_rules(
    conn: &Connection,
    item: &str,
    rules: &[UriRule],
) -> Result<()> {
    validate_website_rules(rules)?;
    let mut details = details_for(conn, item)?;
    details.uris = rules
        .iter()
        .map(|r| UriRule {
            uri: r.uri.trim().to_string(),
            match_mode: r.match_mode.clone(),
        })
        .collect();
    conn.execute(
        "UPDATE items SET details_json=?1 WHERE id=?2",
        params![
            serde_json::to_string(&details).map_err(|_| CoreError::format("网站规则无法序列化"))?,
            item
        ],
    )?;
    Ok(())
}
