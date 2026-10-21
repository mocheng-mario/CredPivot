(() => {
  // 静态注入和按需注入可能同时发生，避免重复监听和重置文档标识。
  if (globalThis.__credpivotContentReady) return;
  const fillDocumentId =
    globalThis.crypto?.randomUUID?.() ?? `doc-${Date.now()}-${Math.random().toString(16).slice(2)}`;

  function findLoginFields() {
    const user = document.querySelector(
      'input[type="email"], input[type="text"][autocomplete="username"], input[name="username"], input[name="login"], input[name="email"], input[id="username"], input[id="email"]'
    );
    const pass = document.querySelector('input[type="password"]');
    return { user, pass };
  }

  function findOtpField() {
    return document.querySelector(
      'input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="totp" i], input[id*="otp" i], input[id*="mfa" i], input[inputmode="numeric"]'
    );
  }

  function setValue(el, value) {
    if (!el || value == null || value === "") return false;
    el.focus();
    el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === "capture_login") {
      if (window !== window.top) return;
      const {user, pass} = findLoginFields();
      // 仅在用户点击扩展中的读取表单按钮后响应，不监听提交，也不持久化密码。
      const changedPassword = document.querySelector('input[type="password"][autocomplete="new-password"]');
      sendResponse({documentId:fillDocumentId,origin:location.origin,username:user?.value ?? "",password:(changedPassword ?? pass)?.value ?? ""});
      return;
    }
    if (msg.type === "fill_context") {
      if (window !== window.top) {
        return;
      }
      sendResponse({
        documentId: fillDocumentId,
        origin: location.origin,
        frameId: 0,
      });
      return;
    }
    if (msg.type !== "deliver_secret") return;
    if (msg.document_id && msg.document_id !== fillDocumentId) {
      sendResponse({ filled: false, reason: "document_mismatch" });
      return;
    }
    if (msg.origin && msg.origin !== location.origin) {
      sendResponse({ filled: false, reason: "origin_mismatch" });
      return;
    }

    const mode = msg.mode || "all";
    const { user, pass } = findLoginFields();
    let loginFilled = false;
    let otpFilled = false;

    if (mode === "login" || mode === "all") {
      if (msg.username && setValue(user, msg.username)) loginFilled = true;
      if (msg.password && setValue(pass, msg.password)) loginFilled = true;
      if (mode === "login") {
        if (!loginFilled) {
          sendResponse({ filled: false, reason: "no_login_fields" });
          return;
        }
        sendResponse({ filled: true, login_filled: true });
        return;
      }
    }

    if (mode === "otp" || mode === "all") {
      if (msg.totp_code) {
        const otp = findOtpField();
        if (setValue(otp, msg.totp_code)) otpFilled = true;
      }
      if (mode === "otp") {
        if (!otpFilled) {
          sendResponse({ filled: false, reason: "no_otp_field" });
          return;
        }
        sendResponse({ filled: true, otp_filled: true });
        return;
      }
    }

    if (mode === "all") {
      if (!loginFilled && !otpFilled) {
        sendResponse({ filled: false, reason: "no_input_fields" });
        return;
      }
      sendResponse({ filled: true, login_filled: loginFilled, otp_filled: otpFilled });
    }
  });
  globalThis.__credpivotContentReady = true;
})();
