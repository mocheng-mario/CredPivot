use credpivot_agent::AgentRequest;
use credpivot_agent::{call_in_process, AgentRuntime};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Mutex;
use tokio::runtime::Runtime;

struct FfiState {
    runtime: Runtime,
    agent: Option<AgentRuntime>,
}

static STATE: Mutex<Option<FfiState>> = Mutex::new(None);

fn with_state<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce(&mut FfiState) -> Result<T, String>,
{
    let mut guard = STATE.lock().map_err(|_| "ffi lock poisoned")?;
    if guard.is_none() {
        let runtime = Runtime::new().map_err(|e| e.to_string())?;
        *guard = Some(FfiState {
            runtime,
            agent: None,
        });
    }
    f(guard.as_mut().unwrap())
}

#[no_mangle]
pub extern "C" fn credpivot_agent_start() -> i32 {
    with_state(|st| {
        if st.agent.is_some() {
            return Ok(());
        }
        let agent = st
            .runtime
            .block_on(AgentRuntime::start())
            .map_err(|e| e.to_string())?;
        st.agent = Some(agent);
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or(-1)
}

/// 1 = running, 0 = not started, -1 = internal error
#[no_mangle]
pub extern "C" fn credpivot_agent_is_running() -> i32 {
    with_state(|st| Ok(if st.agent.is_some() { 1 } else { 0 }))
        .unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn credpivot_agent_restart() -> i32 {
    with_state(|st| {
        if let Some(agent) = st.agent.take() {
            st.runtime.block_on(agent.shutdown());
        }
        let agent = st
            .runtime
            .block_on(AgentRuntime::start())
            .map_err(|e| e.to_string())?;
        st.agent = Some(agent);
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn credpivot_agent_stop() -> i32 {
    with_state(|st| {
        if let Some(agent) = st.agent.take() {
            st.runtime.block_on(agent.shutdown());
        }
        Ok(())
    })
    .map(|_| 0)
    .unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn credpivot_agent_request_json(request_json: *const c_char) -> *mut c_char {
    let req_str = unsafe {
        if request_json.is_null() {
            return json_err("null request");
        }
        CStr::from_ptr(request_json).to_string_lossy()
    };
    let result = with_state(|st| {
        let agent = st
            .agent
            .as_ref()
            .ok_or_else(|| "agent_not_started".to_string())?;
        let req: AgentRequest =
            serde_json::from_str(&req_str).map_err(|e| format!("bad json: {e}"))?;
        let resp = st
            .runtime
            .block_on(call_in_process(&agent.state, req));
        serde_json::to_string(&resp).map_err(|e| e.to_string())
    });
    match result {
        Ok(json) => CString::new(json).map(CString::into_raw).unwrap_or(std::ptr::null_mut()),
        Err(e) => json_err(&e),
    }
}

fn json_err(message: &str) -> *mut c_char {
    let code = if message == "agent_not_started" {
        "agent_not_started"
    } else {
        "ffi_error"
    };
    let body = format!(
        r#"{{"type":"err","protocol_version":1,"code":"{code}","message":"{}"}}"#,
        message.replace('"', "\\\"")
    );
    CString::new(body)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn credpivot_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}
