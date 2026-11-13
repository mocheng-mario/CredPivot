//! 本地可备份的 ES256 通行密钥。私钥仅在 SQLCipher 中持久化，不进入浏览器响应。
use crate::error::{CoreError, Result};
use crate::repo::{new_revision, now_ms};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct Request {
    pub create: bool,
    pub origin: String,
    pub rp_id: String,
    pub username: String,
    pub display_name: String,
    challenge: String,
    user_handle: String,
    credential_ids: Vec<String>,
    cred_props: bool,
    appid: bool,
    client_data_hash: Option<[u8; 32]>,
    android_package: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub credential_id: String,
    pub item_id: String,
    pub rp_id: String,
    pub username: String,
    pub display_name: String,
    pub created_at_ms: i64,
    pub last_used_at_ms: Option<i64>,
    pub group_id: Option<String>,
    pub linked_logins: Vec<Value>,
}

fn invalid() -> CoreError {
    CoreError::format("无效或暂不支持的通行密钥请求")
}

/// 父域 RP 必须可注册，不能使用 com、co.uk 或托管平台的公共后缀。
fn rp_id_matches_host(rp_id: &str, host: &str) -> bool {
    host == rp_id
        || (host.len() > rp_id.len() + 1
            && host.as_bytes().get(host.len() - rp_id.len() - 1) == Some(&b'.')
            && host.ends_with(rp_id)
            && psl::domain(rp_id.as_bytes()).is_some())
}

fn bytes(value: &Value, max: usize) -> Result<Vec<u8>> {
    let input = value.as_str().ok_or_else(invalid)?;
    if input.len() > max * 2 {
        return Err(invalid());
    }
    let decoded = URL_SAFE_NO_PAD.decode(input).map_err(|_| invalid())?;
    if decoded.is_empty() || decoded.len() > max || URL_SAFE_NO_PAD.encode(&decoded) != input {
        return Err(invalid());
    }
    Ok(decoded)
}

impl Request {
    pub fn parse(kind: &str, origin: &str, options: &Value) -> Result<Self> {
        let create = match kind {
            "create" => true,
            "get" => false,
            _ => return Err(invalid()),
        };
        let url = url::Url::parse(origin).map_err(|_| invalid())?;
        if url.scheme() != "https"
            || url.origin().ascii_serialization() != origin
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(invalid());
        }
        let host = url.domain().ok_or_else(invalid)?;
        let requested_rp = if create {
            &options["rp"]["id"]
        } else {
            &options["rpId"]
        };
        let rp_id = if requested_rp.is_null() {
            host
        } else {
            requested_rp.as_str().ok_or_else(invalid)?
        };
        if !rp_id_matches_host(rp_id, host) {
            return Err(invalid());
        }
        let challenge = URL_SAFE_NO_PAD.encode(bytes(&options["challenge"], 1024)?);
        if create
            && !options["pubKeyCredParams"].as_array().is_some_and(|p| {
                p.iter()
                    .any(|v| v["type"] == "public-key" && v["alg"] == -7)
            })
        {
            return Err(invalid());
        }
        if options["attestation"] == "enterprise" {
            return Err(invalid());
        }
        if options["authenticatorSelection"]
            .get("authenticatorAttachment")
            .is_some_and(|v| v != "platform")
        {
            return Err(invalid());
        }
        if let Some(extensions) = options.get("extensions") {
            let extensions = extensions.as_object().ok_or_else(invalid)?;
            // AppID 只兼容旧 U2F：本实现始终使用 RP ID，明确返回 appid=false。
            // 其他未实现扩展交还浏览器，避免静默忽略 PRF/支付等安全语义。
            if extensions.keys().any(|k| {
                k != "credProps" && !(k == "appid" && !create) && !(k == "appidExclude" && create)
            }) {
                return Err(invalid());
            }
        }
        for value in [
            options.get("userVerification"),
            options["authenticatorSelection"].get("userVerification"),
        ] {
            if value.is_some_and(|v| {
                !matches!(v.as_str(), Some("required" | "preferred" | "discouraged"))
            }) {
                return Err(invalid());
            }
        }
        let descriptors = options.get(if create {
            "excludeCredentials"
        } else {
            "allowCredentials"
        });
        let mut credential_ids = Vec::new();
        if let Some(descriptors) = descriptors {
            let descriptors = descriptors.as_array().ok_or_else(invalid)?;
            if descriptors.len() > 128 {
                return Err(invalid());
            }
            for descriptor in descriptors {
                if descriptor["type"] != "public-key" {
                    return Err(invalid());
                }
                credential_ids.push(URL_SAFE_NO_PAD.encode(bytes(&descriptor["id"], 1024)?));
            }
        }
        let (username, display_name, user_handle) = if create {
            let username = options["user"]["name"].as_str().ok_or_else(invalid)?;
            let display = options["user"]["displayName"]
                .as_str()
                .ok_or_else(invalid)?;
            if username.len() > 1024 || display.len() > 1024 {
                return Err(invalid());
            }
            (
                username.into(),
                display.into(),
                URL_SAFE_NO_PAD.encode(bytes(&options["user"]["id"], 64)?),
            )
        } else {
            (String::new(), String::new(), String::new())
        };
        Ok(Self {
            create,
            origin: origin.into(),
            rp_id: rp_id.into(),
            username,
            display_name,
            challenge,
            user_handle,
            credential_ids,
            cred_props: options["extensions"]["credProps"] == true,
            appid: !create && options["extensions"].get("appid").is_some(),
            client_data_hash: None,
            android_package: None,
        })
    }

    /// 仅供 Android App 的受保护系统提供方使用；签名和 Asset Links 由原生层先行验证。
    #[cfg(target_os = "android")]
    pub fn parse_android(kind: &str, origin: &str, options: &Value, package: &str, client_hash: Option<&str>) -> Result<Self> {
        if package.is_empty() || package.len() > 255 || !package.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_') { return Err(invalid()); }
        let rp = if kind == "create" { options["rp"]["id"].as_str() } else { options["rpId"].as_str() }.ok_or_else(invalid)?;
        let mut request = Self::parse(kind, &format!("https://{rp}"), options)?;
        if let Some(hash) = origin.strip_prefix("android:apk-key-hash:") {
            let decoded = URL_SAFE_NO_PAD.decode(hash).map_err(|_| invalid())?;
            if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != hash || client_hash.is_some() { return Err(invalid()); }
            request.android_package = Some(package.into());
        } else {
            let browser = Self::parse(kind, origin, options)?;
            if browser.rp_id != request.rp_id { return Err(invalid()); }
            let hash = URL_SAFE_NO_PAD.decode(client_hash.ok_or_else(invalid)?).map_err(|_| invalid())?;
            request.client_data_hash = Some(hash.try_into().map_err(|_| invalid())?);
        }
        request.origin = origin.into();
        Ok(request)
    }

    pub fn candidates(&self, conn: &Connection) -> Result<Vec<Summary>> {
        Ok(list_summaries(conn)?
            .into_iter()
            .filter(|r| {
                r.rp_id == self.rp_id
                    && (self.create
                        || self.credential_ids.is_empty()
                        || self.credential_ids.contains(&r.credential_id))
            })
            .collect())
    }

    pub fn excluded(&self, conn: &Connection) -> Result<bool> {
        Ok(self.create
            && self
                .candidates(conn)?
                .iter()
                .any(|r| self.credential_ids.contains(&r.credential_id)))
    }

    fn website_origin(&self) -> String {
        if self.android_package.is_some() { format!("https://{}", self.rp_id) } else { self.origin.clone() }
    }

    pub fn login_candidates(&self, conn: &Connection) -> Result<Vec<Value>> {
        let mut logins = crate::credential_management::rows(conn, "SELECT l.id,l.item_id,i.title,l.origin,l.username,i.partition_id,p.name AS partition_name
            FROM login_credentials l JOIN items i ON i.id=l.item_id JOIN partitions p ON p.id=i.partition_id
            WHERE i.trashed=0 ORDER BY i.title,l.username,l.id", [])?;
        let origin = self.website_origin();
        logins.retain(|login| login["id"].as_str().is_some_and(|id|
            crate::website_rules::credential_matches_origin(conn, id, &origin).unwrap_or(false)));
        Ok(logins)
    }

    /// 仅在 App 对本次请求确认并完成身份验证后调用。
    pub fn complete(&self, conn: &Connection, selected: &str, linked_login_id: &str) -> Result<Value> {
        let partition = if self.create {
            if linked_login_id.is_empty() { crate::partitions::PERSONAL.to_string() } else {
                let login = crate::repo_m2::get_login_row(conn, linked_login_id)?;
                crate::partitions::item_partition(conn, &login.item_id)?
            }
        } else {
            conn.query_row("SELECT i.partition_id FROM passkey_credentials p JOIN items i ON i.id=p.item_id WHERE p.credential_id=?1 AND i.trashed=0", [selected], |r|r.get::<_,String>(0))?
        };
        self.complete_in_partition(conn, selected, &partition, linked_login_id)
    }

    pub fn complete_in_partition(&self, conn: &Connection, selected: &str, partition: &str, linked_login_id: &str) -> Result<Value> {
        crate::partitions::require(conn, partition)?;
        let tx = conn.unchecked_transaction()?;
        let mut client_json = json!({"type":if self.create {"webauthn.create"} else {"webauthn.get"},
            "challenge":self.challenge,"origin":self.origin,"crossOrigin":false});
        if let Some(package) = &self.android_package { client_json["androidPackageName"] = json!(package); }
        let client_data = serde_json::to_vec(&client_json)
        .map_err(|_| invalid())?;
        // 浏览器已计算的 hash 必须原样签名，不能用重新序列化的 JSON 替代。
        let client_hash: [u8; 32] = self.client_data_hash.unwrap_or_else(|| Sha256::digest(&client_data).into());
        let client_encoded = if self.client_data_hash.is_some() { String::new() } else { URL_SAFE_NO_PAD.encode(&client_data) };
        let mut auth_data = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        // UP + UV + BE。可迁移凭据使用零计数；未确认异地备份，不能声称 BS=true。
        auth_data.push(if self.create { 0x4d } else { 0x0d });
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let result = if self.create {
            if self.excluded(&tx)? {
                return Err(CoreError::format("此网站已存在被排除的通行密钥"));
            }
            let linked_login = if linked_login_id.is_empty() { None } else {
                let login = crate::repo_m2::get_login_row(&tx, linked_login_id)?;
                if crate::partitions::item_partition(&tx, &login.item_id)? != partition {
                    return Err(CoreError::format("关联账号必须与通行密钥位于同一分区"));
                }
                Some(login)
            };
            let key = SigningKey::random(&mut OsRng);
            let encoded = key.verifying_key().to_encoded_point(false);
            let x = encoded.x().ok_or_else(invalid)?;
            let y = encoded.y().ok_or_else(invalid)?;
            let mut raw_id = [0u8; 32];
            OsRng.fill_bytes(&mut raw_id);
            let id = URL_SAFE_NO_PAD.encode(raw_id);
            let item = Uuid::new_v4().to_string();
            let ts = now_ms();
            let title = format!("{} · {}", self.rp_id, self.username);
            let secret = Zeroizing::new(key.to_bytes().to_vec());
            tx.execute(
                "INSERT INTO items(id,kind,title,current_revision,created_at_ms,updated_at_ms,partition_id)
                VALUES (?1,'passkey',?2,?3,?4,?4,?5)",
                params![item, title, new_revision(), ts, partition],
            )?;
            tx.execute("INSERT INTO passkey_credentials(credential_id,item_id,rp_id,user_handle,username,display_name,private_key,created_at_ms)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![id,item,self.rp_id,self.user_handle,self.username,self.display_name,secret.as_slice(),ts])?;
            if let Some(login) = linked_login {
                crate::associations::link_passkey(&tx, &login.item_id, &item, ts)?;
                let revision = new_revision();
                tx.execute("UPDATE items SET current_revision=?1,updated_at_ms=?2 WHERE id=?3",
                    params![revision,ts,login.item_id])?;
                tx.execute("UPDATE login_credentials SET current_revision=?1,updated_at_ms=?2 WHERE id=?3",
                    params![revision,ts,login.id])?;
            }
            auth_data.extend_from_slice(&[0u8; 16]); // 无硬件认证声明：零 AAGUID + none attestation。
            auth_data.extend_from_slice(&(raw_id.len() as u16).to_be_bytes());
            auth_data.extend_from_slice(&raw_id);
            // 固定 COSE EC2/P-256/ES256 公钥，私钥绝不参与响应序列化。
            auth_data
                .extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
            auth_data.extend_from_slice(x);
            auth_data.extend_from_slice(&[0x22, 0x58, 0x20]);
            auth_data.extend_from_slice(y);
            let mut attestation = vec![
                0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e', 0x67, b'a', b't', b't',
                b'S', b't', b'm', b't', 0xa0, 0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a',
            ];
            cbor_bytes(&mut attestation, &auth_data);
            let mut spki = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200")
                .map_err(|_| invalid())?;
            spki.extend_from_slice(encoded.as_bytes());
            let extensions = if self.cred_props {
                json!({"credProps":{"rk":true}})
            } else {
                json!({})
            };
            json!({"id":id,"rawId":id,"type":"public-key","authenticatorAttachment":"platform",
                "clientExtensionResults":extensions,"response":{"clientDataJSON":client_encoded,
                "attestationObject":URL_SAFE_NO_PAD.encode(attestation),"authenticatorData":URL_SAFE_NO_PAD.encode(auth_data),
                "publicKey":URL_SAFE_NO_PAD.encode(spki),"publicKeyAlgorithm":-7,"transports":["internal"]}})
        } else {
            if !self
                .candidates(&tx)?
                .iter()
                .any(|r| r.credential_id == selected)
            {
                return Err(invalid());
            }
            // 系统选择器中的分区选择不能绕过到另一个分区的通行密钥。
            if !tx.query_row("SELECT EXISTS(SELECT 1 FROM passkey_credentials p JOIN items i ON i.id=p.item_id WHERE p.credential_id=?1 AND i.partition_id=?2 AND i.trashed=0)", params![selected,partition], |r|r.get::<_,bool>(0))? {
                return Err(invalid());
            }
            let (secret, user_handle): (Vec<u8>, String) = tx.query_row(
                "SELECT private_key,user_handle FROM passkey_credentials WHERE credential_id=?1",
                [selected],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let secret = Zeroizing::new(secret);
            let key = SigningKey::from_slice(&secret)
                .map_err(|_| CoreError::format("通行密钥数据损坏"))?;
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&client_hash);
            let signature: Signature = key.sign(&signed);
            // 沿用本机使用记录，备份/导出不会带走网站登录时间。
            tx.execute("INSERT INTO local_usage(item_id,last_used_at_ms,use_count)
                SELECT item_id,?1,1 FROM passkey_credentials WHERE credential_id=?2
                ON CONFLICT(item_id) DO UPDATE SET last_used_at_ms=excluded.last_used_at_ms,use_count=use_count+1",params![now_ms(),selected])?;
            json!({"id":selected,"rawId":selected,"type":"public-key","authenticatorAttachment":"platform",
                "clientExtensionResults":if self.appid {json!({"appid":false})} else {json!({})},"response":{"clientDataJSON":client_encoded,
                "authenticatorData":URL_SAFE_NO_PAD.encode(auth_data),"signature":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),"userHandle":user_handle}})
        };
        if self.create {
            crate::mark_restore_dirty(&tx)?;
        }
        tx.commit()?;
        Ok(result)
    }
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    // 当前固定 ES256 authData < 256 字节；仍覆盖更长数据，避免长度截断。
    if bytes.len() < 24 {
        out.push(0x40 | bytes.len() as u8);
    } else if bytes.len() < 256 {
        out.extend_from_slice(&[0x58, bytes.len() as u8]);
    } else {
        out.push(0x59);
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

pub fn link_origins(conn: &Connection, credential_ids: &[String]) -> Result<Vec<String>> {
    let mut origins = Vec::new();
    for id in credential_ids {
        let rp_id: Option<String> = conn.query_row(
            "SELECT rp_id FROM passkey_credentials WHERE credential_id=?1",
            [id],
            |row| row.get(0),
        ).optional()?;
        if let Some(rp_id) = rp_id {
            let origin = if rp_id.starts_with("https://") { rp_id } else { format!("https://{rp_id}") };
            origins.push(origin);
        }
    }
    Ok(origins)
}

fn logins(conn: &Connection, passkey_item: &str) -> Result<Vec<Value>> {
    if !crate::associations::table_ready(conn)? {
        return Ok(Vec::new());
    }
    crate::credential_management::rows(conn, "SELECT l.id,l.item_id,i.title,l.origin,l.username
        FROM credential_links k
        JOIN login_credentials l ON l.item_id=k.account_item_id
        JOIN items i ON i.id=l.item_id
        WHERE k.kind='passkey' AND k.target_item_id=?1 AND i.trashed=0
        ORDER BY i.title,l.username,l.id", [passkey_item])
}

pub fn list(conn: &Connection) -> Result<Vec<Summary>> {
    let mut items = list_summaries(conn)?;
    for item in &mut items {
        item.linked_logins = logins(conn, &item.item_id)?;
    }
    Ok(items)
}

fn list_summaries(conn: &Connection) -> Result<Vec<Summary>> {
    let mut stmt = conn.prepare("SELECT p.credential_id,p.item_id,p.rp_id,p.username,p.display_name,p.created_at_ms,u.last_used_at_ms,i.group_id
        FROM passkey_credentials p JOIN items i ON i.id=p.item_id LEFT JOIN local_usage u ON u.item_id=p.item_id
        WHERE i.trashed=0 ORDER BY p.created_at_ms DESC,p.credential_id")?;
    let rows = stmt.query_map([], |r| {
        Ok(Summary {
            credential_id: r.get(0)?,
            item_id: r.get(1)?,
            rp_id: r.get(2)?,
            username: r.get(3)?,
            display_name: r.get(4)?,
            created_at_ms: r.get(5)?,
            last_used_at_ms: r.get(6)?,
            group_id: r.get(7)?,
            linked_logins: Vec::new(),
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}
