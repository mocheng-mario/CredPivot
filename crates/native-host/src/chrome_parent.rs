use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParentCheckError {
    #[error("could not identify browser parent process")]
    ParentUnknown,
    #[error("parent process is not a trusted Google Chrome browser")]
    SignatureRejected,
    #[error("browser signature verification is unavailable")]
    VerificationUnavailable,
}
impl ParentCheckError {
    pub fn event(&self) -> &'static str {
        match self {
            Self::ParentUnknown => "parent process unavailable",
            Self::SignatureRejected => "browser signature rejected",
            Self::VerificationUnavailable => "browser verification unavailable",
        }
    }
}

pub fn verify_chrome_parent() -> Result<(), ParentCheckError> {
    #[cfg(target_os = "macos")]
    {
        let pid = unsafe { libc::getppid() };
        if pid <= 1 { return Err(ParentCheckError::ParentUnknown); }
        verify_browser_process(pid)
    }
    #[cfg(not(target_os = "macos"))]
    { Ok(()) }
}

/// 验证正在运行的代码对象，避免 Chrome 更新后磁盘路径改变导致误拒绝。
/// 仅接受 Google 签名的 Chrome/Canary 及其 Helper，不信任进程名或任意祖先进程。
#[cfg(target_os = "macos")]
fn verify_browser_process(pid: i32) -> Result<(), ParentCheckError> {
    use std::ffi::{c_char, c_void, CString};
    use std::ptr::null;
    type Ref = *const c_void;
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(value: Ref);
        fn CFNumberCreate(allocator: Ref, kind: isize, value: Ref) -> Ref;
        fn CFStringCreateWithCString(allocator: Ref, value: *const c_char, encoding: u32) -> Ref;
        fn CFDictionaryCreate(allocator: Ref, keys: *const Ref, values: *const Ref, count: isize, key_callbacks: Ref, value_callbacks: Ref) -> Ref;
    }
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecGuestAttributePid: Ref;
        fn SecCodeCopyGuestWithAttributes(host: Ref, attributes: Ref, flags: u32, guest: *mut Ref) -> i32;
        fn SecRequirementCreateWithString(text: Ref, flags: u32, requirement: *mut Ref) -> i32;
        fn SecCodeCheckValidity(code: Ref, flags: u32, requirement: Ref) -> i32;
    }
    struct Owned(Ref);
    impl Owned {
        fn new(value: Ref) -> Result<Self, ParentCheckError> {
            if value.is_null() { Err(ParentCheckError::VerificationUnavailable) } else { Ok(Self(value)) }
        }
    }
    impl Drop for Owned { fn drop(&mut self) { unsafe { CFRelease(self.0); } } }
    let text = CString::new(concat!(
        "anchor apple generic and certificate leaf[subject.OU] = \"EQHXZ8M8AV\" and (",
        "identifier \"com.google.Chrome\" or identifier \"com.google.Chrome.canary\" or ",
        "identifier \"com.google.Chrome.helper\" or identifier \"com.google.Chrome.helper.GPU\" or ",
        "identifier \"com.google.Chrome.helper.renderer\" or identifier \"com.google.Chrome.helper.Renderer\" or ",
        "identifier \"com.google.Chrome.canary.helper\" or identifier \"com.google.Chrome.canary.helper.GPU\" or ",
        "identifier \"com.google.Chrome.canary.helper.renderer\" or identifier \"com.google.Chrome.canary.helper.Renderer\")"
    )).expect("static requirement");
    unsafe {
        let number = Owned::new(CFNumberCreate(null(), 3, &pid as *const i32 as Ref))?;
        let keys = [kSecGuestAttributePid]; let values = [number.0];
        // 回调为空时字典不持有元素，number 在代码对象查询完成前保持存活。
        let attributes = Owned::new(CFDictionaryCreate(null(), keys.as_ptr(), values.as_ptr(), 1, null(), null()))?;
        let mut guest = null();
        if SecCodeCopyGuestWithAttributes(null(), attributes.0, 0, &mut guest) != 0 {
            return Err(ParentCheckError::ParentUnknown);
        }
        let guest = Owned::new(guest)?;
        let expression = Owned::new(CFStringCreateWithCString(null(), text.as_ptr(), 0x08000100))?;
        let mut requirement = null();
        if SecRequirementCreateWithString(expression.0, 0, &mut requirement) != 0 {
            return Err(ParentCheckError::VerificationUnavailable);
        }
        let requirement = Owned::new(requirement)?;
        if SecCodeCheckValidity(guest.0, 0, requirement.0) == 0 { Ok(()) }
        else { Err(ParentCheckError::SignatureRejected) }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    #[test]
    fn ordinary_local_process_cannot_impersonate_chrome() {
        assert!(matches!(verify_browser_process(std::process::id() as i32), Err(ParentCheckError::SignatureRejected)));
    }
    #[test]
    fn vanished_browser_parent_is_rejected() {
        assert!(verify_browser_process(-1).is_err());
    }
    #[test]
    #[ignore = "requires an explicitly supplied PID of a running Google Chrome"]
    fn running_google_chrome_signature_is_accepted() {
        let pid = std::env::var("CREDPIVOT_TEST_CHROME_PID").expect("browser PID").parse().unwrap();
        verify_browser_process(pid).expect("running Chrome signature");
    }
}
