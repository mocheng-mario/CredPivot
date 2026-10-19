use clap::{Parser, Subcommand};
use credpivot_core::{
    bootstrap_vault_dir, export_ovb_from_dir, parse_config, parse_ovb_file, read_vault_json,
    parse_recovery_display, recover_ovb_to_dir, CpvcConfig, RecoveryUnlock,
};
use ovb1_structure::parse_layout;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "credpivot-cli", about = "CredPivot vault inspect / verify / recover (M1)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 查看 vault.json 或 .ovb 元数据（不解密业务）
    Inspect {
        path: PathBuf,
    },
    /// 校验 CPVC MAC 或 OVB 结构
    Verify {
        path: PathBuf,
    },
    /// 用主密码试解 VMK（交互输入口令）
    UnlockTest {
        vault_dir: PathBuf,
    },
    /// 在空目录创建新 Vault（交互主密码）
    Init {
        target_dir: PathBuf,
    },
    /// 从工作目录导出 OVB（交互主密码）
    ExportOvb {
        vault_dir: PathBuf,
        output: PathBuf,
    },
    /// 从 OVB 恢复到空目录（主密码或恢复密钥，交互输入）
    Recover {
        ovb: PathBuf,
        target_dir: PathBuf,
        /// 使用恢复密钥而非主密码
        #[arg(long)]
        recovery: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Inspect { path } => cmd_inspect(&path),
        Commands::Verify { path } => cmd_verify(&path),
        Commands::UnlockTest { vault_dir } => cmd_unlock_test(&vault_dir),
        Commands::Init { target_dir } => cmd_init(&target_dir),
        Commands::ExportOvb { vault_dir, output } => cmd_export_ovb(&vault_dir, &output),
        Commands::Recover { ovb, target_dir, recovery } => cmd_recover(&ovb, &target_dir, recovery),
    };
    std::process::exit(code);
}

fn cmd_inspect(path: &PathBuf) -> i32 {
    if path.extension().and_then(|s| s.to_str()) == Some("ovb") {
        let data = fs::read(path).expect("read ovb");
        let (header, ct) = parse_ovb_file(&data).expect("parse");
        println!(
            "OVB1 vault={} archive_id={} slots={} ciphertext={} bytes",
            header.vault_id,
            hex_encode(header.archive_id),
            header.slots.len(),
            ct.len()
        );
        return 0;
    }
    if path.is_dir() {
        let cfg = read_vault_json(path).expect("vault.json");
        print_cpvc(&cfg);
        return 0;
    }
    let body = fs::read_to_string(path).expect("read");
    let cfg = parse_config(&body).expect("cpvc");
    print_cpvc(&cfg);
    0
}

fn print_cpvc(cfg: &CpvcConfig) {
    println!(
        "CPVC1 vault={} revision={} slots={}",
        cfg.vault_id,
        cfg.control_revision,
        cfg.key_slots.len()
    );
}

fn cmd_verify(path: &PathBuf) -> i32 {
    if path.extension().and_then(|s| s.to_str()) == Some("ovb") {
        let data = fs::read(path).expect("read");
        parse_layout(&data).expect("structure");
        println!("OVB1 structure OK");
        return 0;
    }
    let cfg = if path.is_dir() {
        read_vault_json(path).expect("vault")
    } else {
        parse_config(&fs::read_to_string(path).expect("read")).expect("cpvc")
    };
    let pw = rpassword::prompt_password("主密码: ").expect("tty");
    let vmk = cfg.unlock_master(&pw).expect("unlock");
    cfg.verify_mac(&*vmk).expect("mac");
    println!("CPVC1 MAC OK");
    0
}

fn cmd_unlock_test(vault_dir: &PathBuf) -> i32 {
    let cfg = read_vault_json(vault_dir).expect("vault");
    let pw = rpassword::prompt_password("主密码: ").expect("tty");
    let _vmk = cfg.unlock_master(&pw).expect("unlock");
    println!("unlock OK");
    0
}

fn cmd_init(target_dir: &PathBuf) -> i32 {
    let pw = rpassword::prompt_password("新主密码: ").expect("tty");
    let material = bootstrap_vault_dir(target_dir, &pw).expect("bootstrap");
    println!("vault_id={}", material.config.vault_id);
    println!("recovery_key={}", material.recovery_display);
    0
}

fn cmd_export_ovb(vault_dir: &PathBuf, output: &PathBuf) -> i32 {
    let pw = rpassword::prompt_password("主密码: ").expect("tty");
    let bytes = export_ovb_from_dir(vault_dir, &pw).expect("export");
    fs::write(output, bytes).expect("write ovb");
    println!("wrote {}", output.display());
    0
}

fn cmd_recover(ovb: &PathBuf, target_dir: &PathBuf, recovery: bool) -> i32 {
    let data = fs::read(ovb).expect("read ovb");
    if recovery {
        let display = rpassword::prompt_password("恢复密钥: ").expect("tty");
        let bytes = parse_recovery_display(display.trim()).expect("recovery key");
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        recover_ovb_to_dir(&data, target_dir, RecoveryUnlock::RecoverySecret(secret)).expect("recover");
    } else {
        let pw = rpassword::prompt_password("主密码: ").expect("tty");
        recover_ovb_to_dir(&data, target_dir, RecoveryUnlock::MasterPassword(pw)).expect("recover");
    }
    println!("recovered to {}", target_dir.display());
    0
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}
