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
    let mut ids = std::collections::HashSet::new();
    for (index, rule) in rules.iter().enumerate() {
        if rule.id.is_empty() || rule.id.len() > 100 || !ids.insert(&rule.id) {
            return Err(CoreError::format("网站规则 ID 为空或重复"));
        }
        validate_rule(rule)
            .map_err(|e| CoreError::format(format!("第 {} 条网站规则：{e}", index + 1)))?;
    }
    Ok(())
}

pub(crate) fn rule_matches(rule: &UriRule, page: &Url) -> Result<bool> {
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
            id: uuid::Uuid::new_v4().to_string(),
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
            id: r.id.clone(),
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

/// 账号只保存认证关联；适用网站由 MFA 自己维护。不再写入单值字段或资料 JSON。
pub(crate) fn save_linked_mfas(conn: &Connection, item_id: &str, ids: &[String]) -> Result<()> {
    crate::associations::replace_mfas(conn, item_id, ids)
}

pub(crate) fn validate_linked_mfas(conn: &Connection, ids: &[String]) -> Result<()> {
    if ids.len() > 100 { return Err(CoreError::limit("MFA 关联过多")); }
    let mut seen = std::collections::HashSet::new();
    for id in ids {
        if id.is_empty() || !seen.insert(id) { return Err(CoreError::format("MFA 关联重复或无效")); }
        let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM totp_credentials t JOIN items i ON i.id=t.item_id WHERE t.id=?1 AND i.trashed=0)", [id], |r|r.get(0))?;
        if !exists { return Err(CoreError::format("关联的 MFA 已不存在")); }
    }
    Ok(())
}

fn match_rank(rule: &UriRule) -> Option<u8> {
    match rule.match_mode.as_str() {
        "exact_origin" | "bitwarden_default" => Some(0),
        "wildcard" => Some(1),
        "regex" => Some(2),
        _ => None,
    }
}

/// 精确优先，命中后不再编译后续层级的表达式；元数据及规则由一次查询读取。
/// 只有用户展开其他匹配时才评估其余层级和未关联的 MFA。
pub fn browser_mfa_candidates(conn: &Connection, origin: &str, credential_id: Option<&str>, partition: Option<&str>) -> Result<Value> {
    let page = website_url(origin)?;
    let account = if let Some(credential) = credential_id {
        let login = crate::repo_m2::get_login_row(conn, credential)?;
        let account_partition = crate::partitions::item_partition(conn, &login.item_id)?;
        if partition.is_some_and(|partition| partition != account_partition) {
            return Ok(json!({"candidates":[],"can_check_other_matches":false,"all_matches":false}));
        }
        Some((login.item_id, account_partition))
    } else { None };
    let scope = account.as_ref().map(|(_, partition)| partition.as_str()).or(partition);
    let linked = if let Some((item, _)) = &account {
        crate::associations::mfa_credential_ids(conn, item)?
    } else { Vec::new() };
    let mut result = Vec::new();
    for row in crate::repo_m2::list_totp_credentials(conn)? {
        if scope.is_some_and(|partition| crate::partitions::item_partition(conn, &row.item_id).ok().as_deref() != Some(partition)) {
            continue;
        }
        let rules: Vec<_> = row.website_rules.iter().filter(|rule| match_rank(rule).is_some()).collect();
        let matched = rules.iter().any(|rule| rule_matches(rule, &page).unwrap_or(false));
        let include = if account.is_some() {
            linked.contains(&row.id) && (rules.is_empty() || matched)
        } else {
            !linked_to_any_account(conn, &row.item_id)? && !rules.is_empty() && matched
        };
        if include {
            result.push(json!({"id":row.id,"issuer":row.issuer,"account":row.account,"linked":linked.contains(&row.id)}));
        }
    }
    Ok(json!({"candidates":result,"can_check_other_matches":false,"all_matches":false}))
}

fn linked_to_any_account(conn: &Connection, totp_item: &str) -> Result<bool> {
    if !crate::associations::table_ready(conn)? {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM credential_links WHERE target_item_id=?1 AND kind='mfa')",
        [totp_item],
        |row| row.get(0),
    )?)
}

/// 发放验证码前单独重新检查所选 MFA 自己的规则，关联账号不能绕过网站限制。
pub fn mfa_matches_origin(conn: &Connection, totp_id: &str, origin: &str) -> Result<bool> {
    let page = website_url(origin)?;
    let item: String = conn.query_row("SELECT t.item_id FROM totp_credentials t JOIN items i ON i.id=t.item_id WHERE t.id=?1 AND i.trashed=0",[totp_id],|r|r.get(0))?;
    let details = details_for(conn, &item)?;
    if details.uris.len() > 100 { return Ok(false); }
    for rank in 0..=2 {
        if details.uris.iter().any(|r|match_rank(r)==Some(rank) && rule_matches(r,&page).unwrap_or(false)) { return Ok(true); }
    }
    Ok(false)
}

pub(crate) fn detach_mfa_references(conn:&Connection, item_id:&str) -> Result<()> {
    let mut stmt = conn.prepare("SELECT id FROM totp_credentials WHERE item_id=?1")?;
    let ids = stmt.query_map([item_id],|r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
    if ids.is_empty() { return Ok(()); }
    let mut stmt = conn.prepare("SELECT id,item_id FROM login_credentials")?;
    let logins = stmt.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;
    for (login,item) in logins {
        let mut details = details_for(conn,&item)?;
        let count = details.linked_mfa_ids.len();
        details.linked_mfa_ids.retain(|id| !ids.contains(id));
        if count != details.linked_mfa_ids.len() {
            let revision = crate::repo::new_revision();
            let ts = crate::repo::now_ms();
            conn.execute("UPDATE items SET details_json=?1,current_revision=?2,updated_at_ms=?3 WHERE id=?4",params![serde_json::to_string(&details).map_err(|_|CoreError::format("MFA 关联编码失败"))?,revision,ts,item])?;
            conn.execute("UPDATE login_credentials SET current_revision=?1,updated_at_ms=?2 WHERE id=?3",params![revision,ts,login])?;
        }
    }
    for id in ids { conn.execute("UPDATE login_credentials SET linked_totp_id=NULL WHERE linked_totp_id=?1",[id])?; }
    Ok(())
}
