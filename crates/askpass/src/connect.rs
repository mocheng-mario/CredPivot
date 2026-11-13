use credpivot_agent::{agent_socket_path, call_agent, runtime_dir, AgentRequest, AgentResponse};
use std::{io::IsTerminal, os::unix::process::CommandExt, process::Command, time::{Duration, Instant}};

fn main() {
    if let Err(message) = run() {
        eprintln!("CredPivot: {message}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!("用法：credpivot-connect --vault 保险库ID --connection 连接ID");
        return Ok(());
    }
    let mut vault_id = None;
    let mut connection_id = None;
    let mut index = 0;
    while index < args.len() {
        let value = args.get(index + 1).filter(|value| !value.is_empty()).ok_or("请从 App 重新复制终端连接命令")?;
        match args[index].as_str() {
            "--vault" if vault_id.is_none() => vault_id = Some(value.clone()),
            "--connection" if connection_id.is_none() => connection_id = Some(value.clone()),
            _ => return Err("参数无效，请从 App 重新复制终端连接命令".into()),
        }
        index += 2;
    }
    let vault_id = vault_id.ok_or("缺少保险库 ID，请从 App 重新复制终端连接命令")?;
    let connection_id = connection_id.ok_or("缺少连接 ID，请从 App 重新复制终端连接命令")?;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("请在交互式终端中执行这条连接命令".into());
    }
    ensure_app()?;
    redirect_to_latest(&args)?;
    let expect = runtime_dir().join("ssh-expect-pass.exp");
    let askpass = runtime_dir().join("credpivot-askpass");
    if !std::path::Path::new("/usr/bin/expect").is_file() {
        return Err("连接组件不完整，请更新并重新打开 CredPivot App".into());
    }
    eprintln!("正在等待 CredPivot 验证，按 Ctrl+C 可取消…");
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let response = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(125),
            call_agent(&agent_socket_path(), AgentRequest::TerminalConnect { vault_id, connection_id })).await
    })
        .map_err(|_| "验证超时，请重新执行连接命令")?
        .map_err(|_| "无法连接 App，请更新并重新打开 CredPivot 后重试")?;
    let payload = match response {
        AgentResponse::Ok { payload, .. } => payload,
        AgentResponse::Err { code, message, .. } => {
            // socket 先于安装完成就绪；拒绝过期组件时等固定入口更新，只重定向一次。
            // 此时尚未创建连接会话，可以安全地由新版程序重新发起。
            if code == "peer_denied" && std::env::var_os("CREDPIVOT_CONNECT_REDIRECTED").is_none() {
                let started = Instant::now();
                while started.elapsed() < Duration::from_secs(15) {
                    redirect_to_latest(&args)?;
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            return Err(message);
        }
    };
    // App 完成安装和身份确认后再检查副本，避免撞上 askpass 的替换窗口。
    if !expect.is_file() || !askpass.is_file() {
        return Err("连接组件不完整，请更新并重新打开 CredPivot App".into());
    }
    let session = payload["session_id"].as_str().filter(|id| !id.is_empty()).ok_or("App 返回的连接会话无效")?;
    let host = payload["host"].as_str().ok_or("App 返回的主机无效")?;
    let user = payload["user"].as_str().ok_or("App 返回的账号无效")?;
    let port = payload["port"].as_u64().filter(|port| *port > 0 && *port <= 65535).ok_or("App 返回的端口无效")?;
    eprintln!("正在连接 {user}@{host}:{port}…");
    let error = Command::new("/usr/bin/expect").arg(expect)
        .args(["--user", user, "--host", host, "--port", &port.to_string(), "--session-id", session, "--askpass"])
        .arg(askpass).exec();
    Err(format!("无法启动 SSH：{error}"))
}

fn redirect_to_latest(args: &[String]) -> Result<(), String> {
    if std::env::var_os("CREDPIVOT_CONNECT_REDIRECTED").is_some() { return Ok(()); }
    let installed = runtime_dir().join("credpivot-connect");
    if let (Ok(current), Ok(latest)) = (std::env::current_exe().and_then(std::fs::canonicalize), std::fs::canonicalize(installed)) {
        if current != latest {
            return Err(Command::new(latest).args(args).env("CREDPIVOT_CONNECT_REDIRECTED", "1").exec().to_string());
        }
    }
    Ok(())
}

fn ensure_app() -> Result<(), String> {
    let socket = agent_socket_path();
    if std::os::unix::net::UnixStream::connect(&socket).is_ok() { return Ok(()); }
    let path = std::fs::read_to_string(runtime_dir().join("terminal-app.path"))
        .map_err(|_| "请先打开一次 CredPivot App，安装终端连接组件")?;
    let app = std::path::Path::new(path.trim());
    if !app.is_absolute() || app.extension().and_then(|s| s.to_str()) != Some("app") || !app.is_dir() {
        return Err("App 路径已失效，请重新打开 CredPivot App".into());
    }
    let info = Command::new("/usr/bin/plutil").args(["-extract", "CFBundleIdentifier", "raw", "-o", "-"])
        .arg(app.join("Contents/Info.plist")).output().map_err(|_| "无法检查 CredPivot App")?;
    if !info.status.success() || String::from_utf8_lossy(&info.stdout).trim() != "com.credpivot.macos" {
        return Err("记录的 App 无效，请重新打开 CredPivot App".into());
    }
    eprintln!("正在启动 CredPivot…");
    if !Command::new("/usr/bin/open").args(["-g", "-a"]).arg(app)
        .args(["--args", "--credpivot-terminal-background"]).status().map_err(|_| "无法启动 CredPivot")?.success()
    { return Err("无法启动 CredPivot，请手动打开 App 后重试".into()); }
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() { return Ok(()); }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("等待 App 启动超时，请手动打开 CredPivot 后重试".into())
}
