(() => {
  // 静态注入和按需注入可能同时发生，避免重复监听和重置文档标识。
  if (globalThis.__credpivotContentReady) return;
  const fillDocumentId =
    globalThis.crypto?.randomUUID?.() ?? `doc-${Date.now()}-${Math.random().toString(16).slice(2)}`;

  function usableInput(el) {
    if (el.disabled || el.type === "hidden" || !el.getClientRects().length) return false;
    const style = getComputedStyle(el);
    return style.visibility !== "hidden" && style.visibility !== "collapse";
  }

  function findLoginFields(capture = false) {
    const passwords = [...document.querySelectorAll('input[type="password"]')].filter(usableInput);
    const pass = (capture && passwords.find((el) => el.autocomplete === "new-password")) ||
      passwords.find((el) => el.autocomplete === "current-password") ||
      passwords.find((el) => el.autocomplete !== "new-password");
    // 同页可能有订阅邮箱或其他表单，优先在密码框所属表单中寻找账号。
    const scope = pass?.form ?? document;
    // Jenkins / Spring Security 使用 j_username，且可能显式关闭 autocomplete。
    let user = [...scope.querySelectorAll(
      'input[type="email"], input[type="text"][autocomplete="username"], input[name="username"], input[name="j_username"], input[name="login"], input[name="email"], input[id="username"], input[id="j_username"], input[id="email"]'
    )].find(usableInput);
    if (!user && pass?.form) {
      // 缺少语义属性时，只回退到同一表单中位于密码框之前的文本框。
      user = [...pass.form.querySelectorAll('input[type="text"], input:not([type])')]
        .filter((el) => usableInput(el) && el.autocomplete !== "one-time-code" &&
          !/otp|totp|mfa|captcha|search/i.test(`${el.name} ${el.id}`) &&
          (el.compareDocumentPosition(pass) & Node.DOCUMENT_POSITION_FOLLOWING))
        .at(-1);
    }
    return { user, pass };
  }

  function findOtpField() {
    const explicit = [...document.querySelectorAll(
      'input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="totp" i], input[id*="otp" i], input[id*="mfa" i]'
    )].find((el) => usableInput(el) && !el.readOnly);
    if (explicit) return explicit;
    const numeric = [...document.querySelectorAll('input[inputmode="numeric"]')]
      .filter((el) => usableInput(el) && !el.readOnly && ["text", "tel", "number"].includes(el.type));
    // 不能因前面有任意数字输入框，就忽略后面明确标记的验证码框。
    return numeric.length === 1 ? numeric[0] : null;
  }

  function setValue(el, value) {
    if (!el || el.readOnly || !usableInput(el) || value == null || value === "") return false;
    el.focus();
    // 绕过框架在元素上包装的 setter，让 input 事件能同步到受控表单状态。
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return el.value === value;
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === "capture_login") {
      if (window !== window.top) return;
      const {user, pass} = findLoginFields(true);
      // 仅在用户点击扩展中的读取表单按钮后响应，不监听提交，也不持久化密码。
      sendResponse({documentId:fillDocumentId,origin:location.origin,username:user?.value ?? "",password:pass?.value ?? ""});
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
    let usernameFilled = false;
    let passwordFilled = false;
    let otpFilled = false;

    if (mode === "login" || mode === "all") {
      usernameFilled = Boolean(msg.username && setValue(user, msg.username));
      passwordFilled = Boolean(msg.password && setValue(pass, msg.password));
      loginFilled = usernameFilled || passwordFilled;
      if (mode === "login") {
        if (!loginFilled) {
          sendResponse({ filled: false, reason: "no_login_fields" });
          return;
        }
        sendResponse({ filled: true, login_filled: true, username_filled: usernameFilled, password_filled: passwordFilled,
          partial: Boolean((msg.username && !usernameFilled) || (msg.password && !passwordFilled)) });
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
