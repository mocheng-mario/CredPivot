fn main() {
    match credpivot_agent::git_ssh::run_adapter() {
        Ok(code)=>std::process::exit(code),
        Err(message)=>{ eprintln!("{message}"); std::process::exit(1); }
    }
}
