use crate::{CoreError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub path: String,
    #[serde(default)]
    pub workspace: String,
}

fn invalid() -> CoreError { CoreError::format("ssh.git.invalidRule") }

/// Git 使用范围按完整路径段匹配；不把冒号后的组织名误认为端口，也不执行输入内容。
pub fn normalize_rule(input: &str) -> Result<String> {
    let input=input.trim();
    if input.is_empty() || input.len()>4096 || input.chars().any(|c|c.is_whitespace() || c.is_control())
        || input.split('/').any(|s|s=="." || s=="..") || input.contains('\\') || input.contains('%') { return Err(invalid()); }
    let raw = if input.starts_with("ssh://") { input.to_string() } else {
        if input.contains("://") { return Err(invalid()); }
        let raw=input.rsplit_once('@').map(|(_,v)|v).unwrap_or(input);
        let slash=raw.find('/').unwrap_or(raw.len());
        let raw=if let Some(colon)=raw.find(':').filter(|n|*n<slash) {
            format!("{}/{}",&raw[..colon],&raw[colon+1..])
        } else {raw.to_string()};
        format!("ssh://{raw}")
    };
    if raw.split('/').any(|s|s=="." || s=="..") { return Err(invalid()); }
    let url=url::Url::parse(&raw).map_err(|_|invalid())?;
    if url.scheme()!="ssh" || url.password().is_some() || url.query().is_some() || url.fragment().is_some() { return Err(invalid()); }
    let host=url.host_str().ok_or_else(invalid)?.to_ascii_lowercase();
    let port=url.port().unwrap_or(22);
    if port==0 { return Err(invalid()); }
    // 限制为 Git 常见路径字符，避免把 URL 编码、shell 语法或路径跳转当成另一条规则。
    let path=url.path().trim_matches('/');
    let path=path.strip_suffix(".git").unwrap_or(path);
    if path.is_empty() || !path.bytes().all(|b|b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        || path.split('/').any(|p|p.is_empty() || p=="." || p=="..") { return Err(invalid()); }
    let path=if host=="github.com" { path.to_ascii_lowercase() } else {path.to_string()};
    // 非默认端口保留 ssh://，避免再次编辑时将 :2222 误当作 scp 的路径分隔符。
    Ok(if port==22 {format!("{host}/{path}")} else {format!("ssh://{host}:{port}/{path}")})
}

pub fn normalize_rules(rules: &[String]) -> Result<Vec<String>> {
    if rules.len()>100 { return Err(invalid()); }
    let mut seen=BTreeSet::new();
    for rule in rules { seen.insert(normalize_rule(rule)?); }
    Ok(seen.into_iter().collect())
}

impl GitTarget {
    pub fn normalized(&self) -> Result<String> {
        if self.user.is_empty() || self.user.len()>128 || !self.user.bytes().all(|b|b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || self.workspace.len()>4096 || self.workspace.chars().any(char::is_control) { return Err(invalid()); }
        normalize_rule(&format!("ssh://{}@{}:{}/{}",self.user,self.host,self.port,self.path))
    }
    pub fn identity(&self) -> Result<String> { Ok(format!("{}@{}",self.user,self.normalized()?)) }
}

pub fn match_score(rule: &str, target: &str) -> usize {
    if target==rule || target.strip_prefix(rule).is_some_and(|rest|rest.starts_with('/')) {
        rule.split('/').count()
    } else {0}
}
