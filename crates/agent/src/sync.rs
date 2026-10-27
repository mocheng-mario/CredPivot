use crate::{
    error::{AgentError, Result},
    protocol::AgentRequest,
    vault_session::VaultSession,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use credpivot_core::{sync, VaultDatabase};
use serde_json::{json, Value};
use uuid::Uuid;
use zeroize::Zeroizing;

fn vault_error(e: credpivot_core::CoreError) -> AgentError {
    let e = match e {
        credpivot_core::CoreError::RecordValidation { record, source } => {
            return match vault_error(*source) {
                AgentError::Vault(message) => AgentError::SyncRecord { message, record },
                error => error,
            };
        }
        error => error,
    };
    let key = match e {
        credpivot_core::CoreError::Format(message) if message.starts_with("sync.") || message.starts_with("partitions.errors.") => message,
        credpivot_core::CoreError::Auth | credpivot_core::CoreError::BadSecret => {
            "sync.errors.remotePassword".into()
        }
        credpivot_core::CoreError::Conflict => "sync.errors.localChanged".into(),
        credpivot_core::CoreError::Limit(_) => "sync.errors.responseTooLarge".into(),
        _ => "sync.errors.operation".into(),
    };
    AgentError::Vault(key)
}

fn apply_error(error: credpivot_core::CoreError, stage: &'static str) -> AgentError {
    // 本地数据库异常可能含记录内容或路径，只记录固定阶段，保留明确的业务错误供界面提示。
    crate::diagnostics::error("sync_apply", stage);
    match vault_error(error) {
        AgentError::Vault(key) if key == "sync.errors.operation" || key == "sync.errors.remotePassword" => {
            // 此处处理本地备份/快照，不把本地完整性校验失败误报成远端主密码错误。
            AgentError::Vault(stage.into())
        }
        AgentError::SyncRecord { message, record } => {
            let message = if ["sync.errors.operation", "sync.errors.remotePassword", "sync.errors.format"].contains(&message.as_str()) {
                stage.into()
            } else { message };
            AgentError::SyncRecord { message, record }
        }
        error => error,
    }
}

pub(crate) fn handle(vault: &mut VaultSession, request: AgentRequest) -> Result<Value> {
    if !vault.unlocked {
        return Err(AgentError::Locked);
    }
    match request {
        AgentRequest::SyncCancel => {
            vault.sync_plan = None;
            Ok(json!({"cancelled":true}))
        }
        AgentRequest::SyncControlAuthorize => {
            if !vault.authorize_sensitive_operation() {
                return Err(AgentError::Protocol("auth_required".into()));
            }
            Ok(json!({"authorized":true}))
        }
        AgentRequest::SyncStatus => {
            sync::status(vault.db.as_ref().ok_or(AgentError::Locked)?.conn()).map_err(vault_error)
        }
        AgentRequest::SyncDisconnect => {
            if !vault.authorize_sensitive_operation() {
                return Err(AgentError::Protocol("auth_required".into()));
            }
            sync::disconnect(vault.db.as_ref().ok_or(AgentError::Locked)?.conn())
                .map_err(vault_error)?;
            vault.sync_plan = None;
            Ok(json!({"disconnected":true}))
        }
        AgentRequest::SyncPrepare {
            location,
            head,
            remote_ovb,
            strategy,
            remote_password,
        } => {
            vault.sync_plan = None;
            let db = vault.db.as_ref().ok_or(AgentError::Locked)?;
            let config = credpivot_core::read_vault_json(&vault.vault_dir).map_err(vault_error)?;
            if let Some(head) = &head {
                // 上传成功但确认响应丢失时，重读相同已签名入口后恢复本地进度。
                if strategy.is_none() {
                    sync::acknowledge_observed(db.conn(), &config, &location, head).map_err(vault_error)?;
                }
            }
            let bytes = remote_ovb
                .map(|s| {
                    if s.len() > sync::MAX_SYNC_BYTES * 4 / 3 + 8 {
                        return Err(AgentError::Vault("sync.errors.responseTooLarge".into()));
                    }
                    STANDARD
                        .decode(s)
                        .map_err(|_| AgentError::Vault("sync.errors.format".into()))
                })
                .transpose()?;
            let password = Zeroizing::new(remote_password);
            let plan = sync::prepare(
                db.conn(),
                &config,
                vault.vmk.as_ref().ok_or(AgentError::Locked)?,
                &location,
                head,
                bytes.as_deref(),
                strategy.as_deref(),
                &password,
            )
            .map_err(vault_error)?;
            let preview = plan.preview();
            vault.sync_plan = Some(plan);
            Ok(preview)
        }
        AgentRequest::SyncPreviewPage { plan_id, offset, limit } => {
            let plan = vault.sync_plan.as_ref().filter(|p| p.id == plan_id)
                .ok_or_else(|| AgentError::Vault("sync.errors.previewExpired".into()))?;
            Ok(plan.preview_changes(offset, limit))
        }
        AgentRequest::SyncResolve { plan_id, decisions } => {
            let plan = vault
                .sync_plan
                .as_mut()
                .filter(|p| p.id == plan_id)
                .ok_or_else(|| AgentError::Vault("sync.errors.previewExpired".into()))?;
            plan.resolve(decisions).map_err(vault_error)?;
            Ok(plan.preview())
        }
        AgentRequest::SyncApply { plan_id, host_name } => {
            if !sync::valid_host_name(&host_name) {
                return Err(AgentError::Vault("vault.syncHost.invalid".into()));
            }
            let plan = vault
                .sync_plan
                .as_ref()
                .filter(|p| p.id == plan_id)
                .ok_or_else(|| AgentError::Vault("sync.errors.previewExpired".into()))?;
            let manual = plan.initial || !plan.conflicts.is_empty();
            if manual && !vault.authorize_sensitive_operation() {
                return Err(AgentError::Protocol("auth_required".into()));
            }
            // 预检、备份或归档失败时保留预览；直到开始写入才消费，允许用户直接重试。
            let plan = vault.sync_plan.as_mut().ok_or(AgentError::Locked)?;
            plan.host_name = host_name.trim().to_string();
            let db = vault.db.as_ref().ok_or(AgentError::Locked)?;
            let current = sync::capture(db.conn())
                .map_err(|e| apply_error(e, "sync.errors.readLocal"))?;
            let current_config =
                credpivot_core::read_vault_json(&vault.vault_dir)
                    .map_err(|e| apply_error(e, "sync.errors.readLocal"))?;
            if sync::fingerprint(&current).map_err(vault_error)? != plan.local_fingerprint
                || sync::control_hash(&current_config).map_err(vault_error)?
                    != plan.local_control_hash
            {
                crate::diagnostics::warn("sync_apply", "preview invalidated by local changes");
                return Err(AgentError::Vault("sync.errors.localChanged".into()));
            }
            if let Err(error) = plan.finish() {
                return Err(apply_error(error, "sync.errors.previewValidation"));
            }
            let switches = sync::control_hash(&plan.target_config).map_err(vault_error)?
                != sync::control_hash(&current_config).map_err(vault_error)?;
            if plan.no_upload && !plan.changes_local() && !switches {
                sync::store_current(db.conn(), plan)
                    .map_err(|e| apply_error(e, "sync.errors.applyLocal"))?;
                vault.sync_plan = None;
                return Ok(json!({"no_upload":true,"changed":false}));
            }
            let changes = plan.changes_local();
            let backup = if plan.initial || changes {
                Some(
                    sync::backup(
                        &vault.vault_dir,
                        vault.vmk.as_ref().ok_or(AgentError::Locked)?,
                    )
                    .map_err(|e| apply_error(e, "sync.errors.backup"))?,
                )
            } else {
                None
            };
            let (head, archive) = plan.archive()
                .map_err(|e| apply_error(e, "sync.errors.archive"))?;
            let plan = vault.sync_plan.take().ok_or(AgentError::Locked)?;
            let mut local_applied = false;
            let applied: Result<()> = (|| {
                if switches {
                    // 不覆盖活动目录；新保险库构造和验证全部成功后，仅原子切换目录指针。
                    let parent = vault
                        .vault_dir
                        .parent()
                        .ok_or_else(|| AgentError::Vault("sync.errors.configuration".into()))?;
                    let next = parent.join(format!("credpivot-sync-{}", Uuid::new_v4()));
                    // 新 VMK 已经通过 OVB 认证，恢复到空目录后再保存本机同步状态。
                    sync::restore_with_vmk(&archive, &next, &plan.target_vmk)
                        .map_err(|e| apply_error(e, "sync.errors.applyLocal"))?;
                    let next_db = VaultDatabase::open(&next, &plan.target_vmk).map_err(vault_error)?;
                    if let Some(selected) = &vault.ssh_signing_key_id {
                        next_db
                            .conn()
                            .execute("UPDATE ssh_keys SET is_default=1 WHERE id=?1", [selected])
                            .map_err(|_| AgentError::Vault("sync.errors.operation".into()))?;
                    }
                    sync::store_applied(next_db.conn(), &plan, &head).map_err(vault_error)?;
                    crate::paths::persist_active_vault_dir(&next)
                        .map_err(|_| AgentError::Vault("sync.errors.switchVault".into()))?;
                    vault.db = Some(next_db);
                    vault.vault_dir = next;
                    vault.vmk = Some(Zeroizing::new(*plan.target_vmk));
                    local_applied = true;
                    // prepare 已验证将要采用的远端主密码，不能沿用旧保险库的验证时间。
                    vault.record_master_verification()?;
                } else if changes {
                    sync::apply_plan(vault.db.as_ref().ok_or(AgentError::Locked)?.conn(), &plan, &head)
                        .map_err(|e| apply_error(e, "sync.errors.applyLocal"))?;
                    local_applied = true;
                } else {
                    sync::store_pending(vault.db.as_ref().ok_or(AgentError::Locked)?.conn(), &plan, &head)
                        .map_err(|e| apply_error(e, "sync.errors.applyLocal"))?;
                }
                if changes || switches {
                    vault.passkey_requests.clear();
                    vault.data_revision = Uuid::new_v4().to_string();
                    vault.sync_ssh_from_db()?;
                }
                if plan.no_upload {
                    sync::store_current(vault.db.as_ref().ok_or(AgentError::Locked)?.conn(), &plan)
                        .map_err(vault_error)?;
                }
                Ok(())
            })();
            if let Err(error) = applied {
                // 数据已经提交时不再尝试恢复旧会话；锁定会清空旧 SSH 密钥、验证宽限和通行密钥请求。
                // IPC 层同时清理旧填充/SSH 授权，下一次解锁从已提交的数据库重建会话。
                if local_applied {
                    vault.lock();
                    crate::diagnostics::error("sync_apply", "local data committed but session finalization failed; vault locked");
                    return Err(AgentError::Locked);
                }
                return Err(error);
            }
            if plan.no_upload {
                Ok(
                    json!({"no_upload":true,"changed":changes || switches,"backup_path":backup,"vault_switched":switches}),
                )
            } else {
                Ok(
                    json!({"head":head,"ovb":STANDARD.encode(archive),"changed":changes || switches,"backup_path":backup,"vault_switched":switches}),
                )
            }
        }
        AgentRequest::SyncPublishAuthorize { location, head } => {
            let config = credpivot_core::read_vault_json(&vault.vault_dir).map_err(vault_error)?;
            let preserve_previous = sync::authorize_publish(
                vault.db.as_ref().ok_or(AgentError::Locked)?.conn(),
                &config,
                &location,
                &head,
            )
            .map_err(vault_error)?;
            Ok(json!({"authorized":true,"preserve_previous":preserve_previous}))
        }
        AgentRequest::SyncAcknowledge { location, head } => {
            let config = credpivot_core::read_vault_json(&vault.vault_dir).map_err(vault_error)?;
            sync::acknowledge(
                vault.db.as_ref().ok_or(AgentError::Locked)?.conn(),
                &config,
                &location,
                &head,
            )
            .map_err(vault_error)?;
            Ok(json!({"synced":true}))
        }
        _ => Err(AgentError::Protocol("invalid sync operation".into())),
    }
}
