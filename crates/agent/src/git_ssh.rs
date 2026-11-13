use crate::{error::{AgentError,Result}, ssh_agent::{self,GitContext,PendingAuthorization}, vault_session::VaultSession};
use credpivot_core::ssh_git::GitTarget;
use base64::Engine;
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::{sync::Arc,time::{Duration,Instant}};
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::{UnixListener,UnixStream},sync::{Mutex,oneshot}};

pub(crate) const SELECT_PREFIX: &[u8]=b"\x1bcredpivot-git-select\0";
fn failure() -> AgentError { AgentError::Protocol("ssh.git.failed".into()) }
fn fingerprint(public: &str) -> Result<String> {
    Ok(blob_fingerprint(&ssh_agent::public_blob(public)?))
}
pub(crate) fn blob_fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}",base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}
fn scopes(target: &GitTarget) -> Result<(String,String)> {
    let remote=target.identity().map_err(|_|failure())?;
    Ok((format!("git-ssh:local:{}",hex_digest(format!("{}\0{remote}",target.workspace).as_bytes())),
        format!("git-ssh:remote:{}",hex_digest(remote.as_bytes()))))
}
fn hex_digest(data: &[u8]) -> String { Sha256::digest(data).iter().map(|b|format!("{b:02x}")).collect() }

fn trust_path(v: &VaultSession, identity: &str) -> Result<std::path::PathBuf> {
    let config=credpivot_core::read_vault_json(&v.vault_dir).map_err(|_|failure())?;
    Ok(crate::paths::runtime_dir().join("git-trust").join(hex_digest(format!("{}\0{identity}",config.vault_id).as_bytes())))
}

// 库外文件只用于锁库时省去解锁确认；自动签名必须读取加密库内的首次授权记录。
pub(crate) fn trusted_key(v: &VaultSession, identity: &str) -> Option<(String,String)> {
    if !credpivot_core::effective_app_settings().trusts_git_repository(identity) { return None; }
    let data=if v.unlocked {
        v.db.as_ref()?.conn().query_row("SELECT value FROM sync_state WHERE key=?1",
            [format!("git-ssh-trust:{}",hex_digest(identity.as_bytes()))],|r|r.get::<_,String>(0)).ok()?.into_bytes()
    } else { std::fs::read(trust_path(v,identity).ok()?).ok()? };
    if data.len()>16384 { return None; }
    let value:Value=serde_json::from_slice(&data).ok()?;
    if value["remote"].as_str()!=Some(identity) { return None; }
    Some((value["key_id"].as_str()?.into(),value["fingerprint"].as_str()?.into()))
}

pub(crate) fn forget_trust(v: &VaultSession, scope: &str) -> Result<()> {
    if !scope.starts_with("git-ssh:") || scope.len()>160 { return Err(failure()); }
    let db=v.db.as_ref().ok_or(AgentError::Locked)?;
    let value=db.conn().query_row("SELECT (SELECT value FROM sync_state WHERE key=?1)",
        [scope],|r|r.get::<_,Option<String>>(0)).map_err(|_|failure())?;
    if let Some(value)=value {
        let value:Value=serde_json::from_str(&value).map_err(|_|failure())?;
        let remote=value["remote"].as_str().ok_or_else(failure)?;
        match std::fs::remove_file(trust_path(v,remote)?) {
            Ok(())=>{},
            Err(error) if error.kind()==std::io::ErrorKind::NotFound=>{},
            Err(error)=>return Err(error.into()),
        }
        db.conn().execute("DELETE FROM sync_state WHERE key=?1",
            [format!("git-ssh-trust:{}",hex_digest(remote.as_bytes()))]).map_err(|_|failure())?;
    }
    Ok(())
}

async fn choose(stream: &mut UnixStream, vault: &Arc<Mutex<VaultSession>>, target: &GitTarget) -> Result<(String,Option<String>,bool,GitContext)> {
    let remote=target.normalized().map_err(|_|failure())?;
    let authorization_scope=target.identity().map_err(|_|failure())?;
    let (local_scope,remote_scope)=scopes(target)?;
    let (id,receiver,candidates,generation)={
        let mut v=vault.lock().await;
        if !v.unlocked { return Err(AgentError::Locked); }
        let db=v.db.as_ref().ok_or(AgentError::Locked)?;
        let keys=db.list_ssh().map_err(|_|failure())?;
        // 本地副本选择优先；clone 尚无本地仓库时才建立可供后续 pull 使用的远端记忆。
        let mut reselect=false;
        for scope in [&local_scope,&remote_scope] {
            if scope==&local_scope && target.workspace.is_empty() { continue; }
            let stored=db.conn().query_row("SELECT value FROM sync_state WHERE key=?1",[scope],|r|r.get::<_,String>(0));
            if let Ok(stored)=stored {
                let value:Value=serde_json::from_str(&stored).map_err(|_|failure())?;
                if value["reselect"]==true { reselect=true; break; }
                if let Some(key)=keys.iter().find(|k|Some(k.id.as_str())==value["key_id"].as_str()) {
                    if scope==&remote_scope && !target.workspace.is_empty() {
                        let value=json!({"key_id":key.id,"remote":target.identity().map_err(|_|failure())?,"workspace":target.workspace}).to_string();
                        db.conn().execute("INSERT OR REPLACE INTO sync_state(key,value) VALUES (?1,?2)",[local_scope.as_str(),value.as_str()]).map_err(|_|failure())?;
                    }
                    return Ok((key.id.clone(),None,false,GitContext {
                        repository:remote,authorization_scope,authorization_generation:v.ssh_authorization.generation,
                        trusted_repository:false,manually_signed:Default::default(),
                        selection_source:if scope==&local_scope {"local_memory"} else {"remote_memory"},matched_rule:None,
                    }));
                }
            }
        }
        if !reselect {
            if let Some((id,expected))=trusted_key(&v,&authorization_scope) {
                if let Some(key)=keys.iter().find(|key|key.id==id) {
                    if fingerprint(&key.public_openssh)?==expected {
                        let scope=if target.workspace.is_empty() {&remote_scope} else {&local_scope};
                        let value=json!({"key_id":key.id,"remote":authorization_scope,"workspace":target.workspace}).to_string();
                        db.conn().execute("INSERT OR REPLACE INTO sync_state(key,value) VALUES (?1,?2)",[scope.as_str(),value.as_str()]).map_err(|_|failure())?;
                        return Ok((key.id.clone(),None,false,GitContext {
                            repository:remote,authorization_scope,authorization_generation:v.ssh_authorization.generation,
                            trusted_repository:false,manually_signed:Default::default(),selection_source:"remote_memory",matched_rule:None,
                        }));
                    }
                }
            }
        }
        let mut candidates=Vec::new(); let mut best=0;
        for key in &keys {
            let data=credpivot_core::manage_credentials(db.conn(),credpivot_core::VaultAction::ItemDetails {item_id:key.item_id.clone()}).map_err(|_|failure())?;
            let rules=data["details"]["ssh_git_rules"].as_array().cloned().unwrap_or_default();
            let matched_rule=rules.iter().filter_map(Value::as_str).map(|r|(r,credpivot_core::ssh_git::match_score(r,&remote)))
                .filter(|(_,score)|*score>0).max_by_key(|(_,score)|*score);
            let score=matched_rule.map_or(0,|(_,score)|score);
            best=best.max(score);
            let policy=data["details"]["ssh_sign_policy"].as_str().filter(|s|!s.is_empty()).map(str::to_owned)
                .unwrap_or_else(||credpivot_core::effective_app_settings().ssh_sign_policy);
            let partition:String=db.conn().query_row("SELECT p.name FROM partitions p JOIN items i ON i.partition_id=p.id WHERE i.id=?1",[&key.item_id],|r|r.get(0)).map_err(|_|failure())?;
            candidates.push(json!({"id":key.id,"label":key.label,"fingerprint":fingerprint(&key.public_openssh)?,"partition":partition,"policy":policy,"score":score,"rule":matched_rule.map(|(rule,_)|rule)}));
        }
        if best>0 && !reselect { candidates.retain(|c|c["score"].as_u64()==Some(best as u64)); }
        if best>0 && !reselect && candidates.len()==1 { return Ok((candidates[0]["id"].as_str().ok_or_else(failure)?.into(),None,false,GitContext {
            repository:remote,authorization_scope,authorization_generation:v.ssh_authorization.generation,
            trusted_repository:false,manually_signed:Default::default(),
            selection_source:"rule",matched_rule:candidates[0]["rule"].as_str().map(str::to_owned),
        })); }
        if candidates.is_empty() || candidates.len()>500 || v.ssh_authorization.pending.len()>=8 { return Err(failure()); }
        let generation=v.ssh_authorization.generation;
        let (reply,receiver)=oneshot::channel(); let id=uuid::Uuid::new_v4().to_string();
        v.ssh_authorization.pending.insert(id.clone(),PendingAuthorization {
            id:id.clone(),key_label:String::new(),fingerprint:String::new(),caller:"Git SSH".into(),policy:"git_select".into(),
            git:Some(GitContext {repository:remote.clone(),authorization_scope:authorization_scope.clone(),authorization_generation:generation,
                trusted_repository:false,manually_signed:Default::default(),
                selection_source:if reselect {"reselect"} else if best>0 {"multiple_rules"} else {"no_rule"},matched_rule:None}),
            candidates:candidates.clone(),created:Instant::now(),reply,
            reuse_seconds:Some(credpivot_core::effective_app_settings().git_ssh_auth_seconds),
        });
        (id,receiver,candidates,generation)
    };
    let mut disconnected=[0];
    let decision=tokio::select! {
        value=tokio::time::timeout(Duration::from_secs(90),receiver)=>value.ok().and_then(|v|v.ok()),
        _=stream.read(&mut disconnected)=>None,
    };
    let mut v=vault.lock().await; v.ssh_authorization.pending.remove(&id);
    if v.ssh_authorization.generation!=generation { return Err(failure()); }
    let selected=decision.filter(|d|d.approved).ok_or_else(failure)?;
    let candidate=candidates.iter().find(|c|c["id"].as_str()==Some(selected.key_id.as_str())).ok_or_else(failure)?;
    if !v.unlocked { return Err(AgentError::Locked); }
    let db=v.db.as_ref().ok_or(AgentError::Locked)?;
    let key=db.list_ssh().map_err(|_|failure())?.into_iter().find(|k|k.id==selected.key_id).ok_or_else(failure)?;
    if candidate["fingerprint"].as_str()!=Some(fingerprint(&key.public_openssh)?.as_str()) { return Err(failure()); }
    v.touch_activity();
    Ok((key.id,Some(candidate["policy"].as_str().ok_or_else(failure)?.into()),selected.remember,GitContext {
        repository:remote,authorization_scope,authorization_generation:generation,selection_source:"manual",matched_rule:candidate["rule"].as_str().map(str::to_owned),
        trusted_repository:false,manually_signed:Default::default(),
    }))
}

pub(crate) async fn serve_selection(stream: &mut UnixStream, vault: Arc<Mutex<VaultSession>>, pid: Option<u32>, body: &[u8]) -> Result<()> {
    crate::peer_auth::authorize_git_ssh_peer(pid.ok_or_else(failure)?)?;
    if body.len()>16384 { return Err(failure()); }
    let target:GitTarget=serde_json::from_slice(body).map_err(|_|failure())?; target.normalized().map_err(|_|failure())?;
    let trusted_repository={
        let mut v=vault.lock().await;
        if v.idle_expired() { v.lock(); }
        trusted_key(&v,&target.identity().map_err(|_|failure())?).is_some()
    };
    if !vault.lock().await.unlocked {
        let git=GitContext {repository:target.normalized().map_err(|_|failure())?,authorization_scope:target.identity().map_err(|_|failure())?,
            trusted_repository,manually_signed:Default::default(),
            authorization_generation:0,selection_source:"pending",matched_rule:None};
        let _=ssh_agent::authorized_identities(stream,&vault,"CredPivot Git SSH",None,Some(&git)).await?;
    }
    let (key_id,confirmed_policy,remember,git)=choose(stream,&vault,&target).await?;
    let directory=crate::paths::runtime_dir().join("git-sockets"); std::fs::create_dir_all(&directory)?;
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&directory,std::fs::Permissions::from_mode(0o700))?; }
    let nonce=uuid::Uuid::new_v4().simple().to_string();
    let path=directory.join(&nonce[..12]);
    if path.as_os_str().len()>=104 { return Err(failure()); }
    let listener=UnixListener::bind(&path)?;
    let result=async {
        let public={
            let mut v=vault.lock().await;
            if !v.unlocked { return Err(AgentError::Locked); }
            // 锁库或撤销记忆可能发生在选择完成后；不能重新建立已被撤销的授权。
            if v.ssh_authorization.generation!=git.authorization_generation { return Err(failure()); }
            let key=v.db.as_ref().ok_or(AgentError::Locked)?.list_ssh().map_err(|_|failure())?.into_iter().find(|k|k.id==key_id).ok_or_else(failure)?;
            if let Some(policy)=confirmed_policy { v.ssh_authorization.approve_once(key_id.clone(),nonce.clone(),policy); }
            key.public_openssh
        };
        let reply=serde_json::to_vec(&json!({"key_id":key_id,"public":public,"socket":path.to_string_lossy()})).map_err(|_|failure())?;
        stream.write_all(&(reply.len() as u32).to_be_bytes()).await?; stream.write_all(&reply).await?;
        // 适配器启动 SSH 后回传子进程 PID；同用户的其他进程也不能抢用本次授权。
        let mut child=[0;4];
        tokio::time::timeout(Duration::from_secs(10),stream.read_exact(&mut child)).await.map_err(|_|failure())??;
        let child=u32::from_be_bytes(child);
        if child==0 { return Err(failure()); }
        let mut connections=tokio::task::JoinSet::new();
        let completion=async { let mut closed=[0;4]; stream.read_exact(&mut closed).await.map(|_|u32::from_be_bytes(closed)==0) };
        tokio::pin!(completion);
        let succeeded=loop { tokio::select! {
            completed=&mut completion=>break completed.unwrap_or(false),
            accepted=listener.accept()=>{ let (socket,_)=accepted?;
                if socket.peer_cred().ok().and_then(|v|v.pid()).map(|v|v as u32)!=Some(child) { continue; }
                let vault=vault.clone(); let key=key_id.clone(); let scope=nonce.clone(); let git=git.clone();
                connections.spawn(async move { let _=ssh_agent::selected_connection(socket,vault,key,scope,git).await; }); },
            _=connections.join_next(), if !connections.is_empty()=>{},
        }};
        connections.abort_all();
        if succeeded {
            let v=vault.lock().await;
            // 传输期间的“忘记/重新选择”仍须生效，旧任务不能在结束时写回已撤销的记忆。
            if v.unlocked && v.ssh_authorization.generation==git.authorization_generation {
                if let Some(db)=v.db.as_ref() {
                    let establish_trust=git.manually_signed.load(std::sync::atomic::Ordering::Relaxed)
                        && (git.selection_source!="manual" || remember)
                        && credpivot_core::effective_app_settings().trusts_git_repository(&git.authorization_scope)
                        && ssh_agent::signing_policy(&v,&key_id)?.1=="session";
                    if (remember || establish_trust) && db.list_ssh().map_err(|_|failure())?.iter().any(|k|k.id==key_id && k.public_openssh==public) {
                        let (local,remote)=scopes(&target)?; let scope=if target.workspace.is_empty() {remote} else {local};
                        let value=json!({"key_id":key_id,"remote":target.identity().map_err(|_|failure())?,"workspace":target.workspace}).to_string();
                        db.conn().execute("INSERT OR REPLACE INTO sync_state(key,value) VALUES (?1,?2)",[scope.as_str(),value.as_str()]).map_err(|_|failure())?;
                        if establish_trust {
                            let path=trust_path(&v,&git.authorization_scope)?;
                            let directory=path.parent().ok_or_else(failure)?;
                            std::fs::create_dir_all(directory)?;
                            #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(directory,std::fs::Permissions::from_mode(0o700))?; }
                            let record=serde_json::to_vec(&json!({"remote":git.authorization_scope,"key_id":key_id,"fingerprint":fingerprint(&public)?})).map_err(|_|failure())?;
                            let record_text=std::str::from_utf8(&record).map_err(|_|failure())?;
                            let trust_scope=format!("git-ssh-trust:{}",hex_digest(git.authorization_scope.as_bytes()));
                            db.conn().execute("INSERT OR REPLACE INTO sync_state(key,value) VALUES (?1,?2)",
                                [trust_scope.as_str(),record_text]).map_err(|_|failure())?;
                            credpivot_core::write_file_atomic(&path,&record).map_err(|_|failure())?;
                        }
                    }
                }
            }
        }
        Ok(())
    }.await;
    drop(listener); let _=std::fs::remove_file(path); result
}

/// 独立的 Git SSH 适配程序入口；只转交参数与公钥引用，不导出私钥。
pub fn run_adapter() -> std::result::Result<i32,String> {
    match adapter() {
        Ok(code)=>Ok(code),
        Err(_)=>{
            // App 升级可能更新内容寻址的适配器；旧进程只重定向一次，避免要求重启终端。
            if std::env::var_os("CREDPIVOT_GIT_REDIRECTED").is_none() {
                if let Ok(data)=std::fs::read(crate::paths::runtime_dir().join("git-ssh-installation.json")) {
                    if let Ok(value)=serde_json::from_slice::<Value>(&data) {
                        if let Some(path)=value["helper"].as_str() {
                            if std::fs::canonicalize(path).ok()!=std::env::current_exe().ok().and_then(|p|std::fs::canonicalize(p).ok()) {
                                if let Ok(status)=std::process::Command::new(path).args(std::env::args_os().skip(1)).env("CREDPIVOT_GIT_REDIRECTED","1").status() {
                                    return Ok(status.code().unwrap_or(1));
                                }
                            }
                        }
                    }
                }
            }
            Err("CredPivot Git SSH 连接失败或已取消。请确认 App 已启动、保险库可解锁，以及 Git 接入与密钥使用范围配置正确。".into())
        }
    }
}

fn adapter() -> std::result::Result<i32,Box<dyn std::error::Error>> {
    use std::{io::{Read,Write},process::{Command,Stdio}};
    let args:Vec<String>=std::env::args().skip(1).collect();
    // Git 的 -G 探测不能触发任何解锁或选择窗口。
    if args.iter().any(|s|s=="-G") { return Ok(Command::new("/usr/bin/ssh").args(&args).status()?.code().unwrap_or(1)); }
    let mut index=0;
    while index<args.len() && args[index].starts_with('-') {
        let option=&args[index];
        if ["-p","-l","-o","-F","-i","-J"].contains(&option.as_str()) { index+=2; }
        else if ["-4","-6","-v","-vv","-vvv","-q","-T"].contains(&option.as_str()) { index+=1; }
        else { return Err("unsupported Git SSH arguments".into()); }
    }
    if index+2!=args.len() { return Err("invalid Git SSH arguments".into()); }
    let output=Command::new("/usr/bin/ssh").arg("-G").args(&args[..=index]).stdin(Stdio::null()).output()?;
    if !output.status.success() { return Err("SSH configuration failed".into()); }
    let config=String::from_utf8(output.stdout)?;
    let value=|key:&str|->Option<String> { config.lines().find_map(|line|line.strip_prefix(&format!("{key} ")).map(str::to_owned)) };
    // 尊重用户对该目标禁用 Agent 的配置；原样转交 SSH，不连接 App 或叠加身份。
    if value("identityagent").is_some_and(|agent|agent.eq_ignore_ascii_case("none")) {
        return Ok(Command::new("/usr/bin/ssh").args(&args).status()?.code().unwrap_or(1));
    }
    let words=shell_words(&args[index+1])?;
    if words.len()!=2 || !["git-upload-pack","git-receive-pack"].contains(&words[0].as_str()) { return Err("unsupported Git operation".into()); }
    let repo=Command::new("/usr/bin/git").args(["rev-parse","--absolute-git-dir"]).stderr(Stdio::null()).output()?;
    let workspace=if repo.status.success() {String::from_utf8(repo.stdout)?.trim().to_string()} else {String::new()};
    let mut target=GitTarget {host:value("hostname").ok_or("host missing")?,port:value("port").ok_or("port missing")?.parse()?,
        user:value("user").ok_or("user missing")?,path:words[1].clone(),workspace}; target.normalized()?;
    if !target.workspace.is_empty() {
        // clone 的 SSH 子进程可能仍在父目录；不要把新仓库选择写到无关父仓库上。
        let remotes=Command::new("/usr/bin/git").args(["config","--get-regexp",r"^remote\..*\.url$"]).stderr(Stdio::null()).output()?;
        let expected=target.normalized()?;
        let belongs=String::from_utf8(remotes.stdout)?.lines().filter_map(|s|s.split_once(' ').map(|(_,url)|url))
            .filter_map(|s|credpivot_core::ssh_git::normalize_rule(s).ok()).any(|s|s==expected);
        if !belongs { target.workspace.clear(); }
    }
    let socket=crate::paths::ssh_agent_socket_path();
    let mut connected=std::os::unix::net::UnixStream::connect(&socket);
    if connected.is_err() {
        if let Ok(path)=std::fs::read_to_string(crate::paths::runtime_dir().join("git-ssh-app.path")) {
            let _=Command::new("/usr/bin/open").args(["-gj",path.trim()]).status();
            // socket 文件存在不代表还有进程监听；App 重启后重新连接，而不是复用旧文件。
            for _ in 0..50 {
                connected=std::os::unix::net::UnixStream::connect(&socket);
                if connected.is_ok() { break; }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let mut control=connected?;
    // 锁库时可能先解锁、再选身份；客户端不能在第二个 90 秒授权窗口中途超时。
    control.set_read_timeout(Some(Duration::from_secs(240)))?;
    let mut request=SELECT_PREFIX.to_vec(); request.extend(serde_json::to_vec(&target)?);
    control.write_all(&(request.len() as u32).to_be_bytes())?; control.write_all(&request)?;
    let mut size=[0;4]; control.read_exact(&mut size)?; let size=u32::from_be_bytes(size) as usize;
    if size==0 || size>16384 { return Err("invalid selection response".into()); }
    let mut response=vec![0;size]; control.read_exact(&mut response)?; let response:Value=serde_json::from_slice(&response)?;
    let id=response["key_id"].as_str().ok_or("key missing")?;
    uuid::Uuid::parse_str(id)?;
    let directory=crate::paths::runtime_dir().join("ssh-public"); std::fs::create_dir_all(&directory)?;
    use std::os::unix::fs::{OpenOptionsExt,PermissionsExt};
    std::fs::set_permissions(&directory,std::fs::Permissions::from_mode(0o700))?;
    let reference=directory.join(format!("{id}.pub"));
    let temp=directory.join(format!(".{}.tmp",uuid::Uuid::new_v4()));
    let write_result=(|| -> std::result::Result<(),Box<dyn std::error::Error>> {
        let mut file=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
        file.write_all(response["public"].as_str().ok_or("public key missing")?.as_bytes())?; file.write_all(b"\n")?; file.sync_all()?;
        drop(file); std::fs::rename(&temp,&reference)?; Ok(())
    })();
    if let Err(error)=write_result { let _=std::fs::remove_file(&temp); return Err(error); }
    let lease=response["socket"].as_str().ok_or("socket missing")?;
    let mut ssh_args=vec!["-o".to_string(),format!("IdentityAgent={lease}"),"-o".into(),"IdentitiesOnly=yes".into(),
        "-o".into(),"ControlPath=none".into(),"-o".into(),"ControlMaster=no".into(),
        "-o".into(),"PreferredAuthentications=publickey".into(),"-o".into(),"PubkeyAuthentication=yes".into(),
        "-i".into(),reference.to_string_lossy().into_owned()];
    ssh_args.extend(args.clone());
    // IdentityFile 是累加配置；存在其他显式身份时拒绝混用，不能悄悄登录到另一账户。
    let mut check=ssh_args[..ssh_args.len()-1].to_vec(); check.insert(0,"-G".into());
    let resolved=Command::new("/usr/bin/ssh").args(&check).output()?;
    if !resolved.status.success() { return Err("SSH identity configuration failed".into()); }
    let reference_text=reference.to_string_lossy();
    if String::from_utf8(resolved.stdout)?.lines().filter_map(|line|line.strip_prefix("identityfile ")).any(|path|path!="none" && path!=reference_text.as_ref()) {
        eprintln!("CredPivot: SSH 配置叠加了其他 IdentityFile，请移除该目标的重复身份配置后重试。"); return Err("conflicting SSH identities".into());
    }
    // 保持控制连接直到 Git 的 SSH 子进程退出，Agent 据此关闭本次独占身份 socket。
    let mut child=Command::new("/usr/bin/ssh").args(&ssh_args).spawn()?;
    if let Err(error)=control.write_all(&child.id().to_be_bytes()) { let _=child.kill(); let _=child.wait(); return Err(error.into()); }
    let status=child.wait()?;
    let _=control.write_all(&(status.code().unwrap_or(1) as u32).to_be_bytes()); drop(control);
    Ok(status.code().unwrap_or(1))
}

fn shell_words(input: &str) -> std::result::Result<Vec<String>,Box<dyn std::error::Error>> {
    let mut result=Vec::new(); let mut word=String::new(); let mut quoted=false; let mut escape=false;
    for ch in input.chars() {
        if escape { word.push(ch); escape=false; }
        else if ch=='\'' { quoted=!quoted; }
        else if ch=='\\' && !quoted { escape=true; }
        else if ch.is_whitespace() && !quoted { if !word.is_empty() { result.push(std::mem::take(&mut word)); } }
        else if !quoted && "\";$`|&<>".contains(ch) { return Err("unsupported Git command quoting".into()); }
        else { word.push(ch); }
    }
    if quoted || escape { return Err("invalid Git command quoting".into()); }
    if !word.is_empty() { result.push(word); } Ok(result)
}
