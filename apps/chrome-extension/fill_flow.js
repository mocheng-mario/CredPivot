/** 在 service worker 中执行，popup 关闭后仍可完成填充。 */

function gateHint(resp) {
  if (!resp) return null;
  const code = resp.code ?? (resp.ok === false ? resp.code : null);
  if (code === "extension_gate_required") {
    return resp.message || "请在 CredPivot App 中完成指纹确认后重试";
  }
  return null;
}

export async function requestPageContext(tabId) {
  try {
    return await chrome.tabs.sendMessage(tabId, { type: "fill_context" }, { frameId: 0 });
  } catch (e) {
    // 扩展重载后，已打开的标签页可能没有接收端；只重试不含秘密的上下文请求。
    if (!String(e).includes("Receiving end does not exist")) throw e;
    try {
      await chrome.scripting.executeScript({
        target: { tabId, frameIds: [0] },
        files: ["content.js"],
        world: "ISOLATED",
      });
      return await chrome.tabs.sendMessage(tabId, { type: "fill_context" }, { frameId: 0 });
    } catch (_) {
      throw new Error("无法连接页面，请确认已允许扩展访问此网站；浏览器限制页面不支持填充。若页面正在跳转，请加载完成后重试。");
    }
  }
}

async function loadPageContext(tabId, origin) {
  let ctx;
  try {
    ctx = await requestPageContext(tabId);
  } catch (e) {
    return {
      error: {
        ok: false,
        error: "无法与页面通信",
        detail: String(e),
      },
    };
  }
  if (!ctx?.documentId || !ctx?.origin) {
    return { error: { ok: false, error: "无法读取目标页面上下文" } };
  }
  if (ctx.origin !== origin) {
    return { error: { ok: false, error: "页面 origin 不一致" } };
  }
  return { ctx };
}

async function suggestFirstCredential(origin, sendNative, selectedId) {
  const suggest = await sendNative({
    action: "credential.suggest_for_origin",
    origin,
  });
  const gate = gateHint(suggest);
  if (gate) {
    return { error: { ok: false, error: gate, raw: suggest, needs_gate: true } };
  }
  if (!suggest?.ok) {
    return {
      error: {
        ok: false,
        error: suggest?.message || suggest?.code || "suggest 失败",
        raw: suggest,
      },
    };
  }
  const candidates = suggest?.payload?.candidates ?? [];
  const selected = candidates.find((c) => c.id === selectedId);
  const credentialId = selected?.id;
  if (!credentialId) {
    return {
      error: {
        ok: false,
        error: "请先选择当前站点的登录账户",
        origin,
      },
    };
  }
  return { credentialId: selected.id, candidate: selected, candidates };
}

async function consumeLoginSecrets(tabId, ctx, credentialId, sendNative) {
  const prep = await sendNative({
    action: "credential.fill_prepare",
    credential_id: credentialId,
    origin: ctx.origin,
    tab_id: tabId,
    frame_id: ctx.frameId ?? 0,
    document_id: ctx.documentId,
  });
  const gate = gateHint(prep);
  if (gate) {
    return { error: { ok: false, error: gate, raw: prep, needs_gate: true } };
  }
  if (!prep?.ok || !prep?.payload?.prepared) {
    return {
      error: { ok: false, error: prep?.message || prep?.code || "prepare 失败", raw: prep },
    };
  }
  const requestId = prep.payload?.request_id || prep.request_id;
  const consume = await sendNative({
    action: "credential.fill_consume",
    request_id: requestId,
    origin: ctx.origin,
    frame_id: ctx.frameId ?? 0,
    document_id: ctx.documentId,
  });
  const gate2 = gateHint(consume);
  if (gate2) {
    return { error: { ok: false, error: gate2, raw: consume, needs_gate: true } };
  }
  if (!consume?.ok) {
    return {
      error: { ok: false, error: consume?.message || consume?.code || "consume 失败", raw: consume },
    };
  }
  return { secrets: consume.payload ?? consume };
}

export async function runFillLoginOnTab(tabId, sendNative, selectedId) {
  const tab = await chrome.tabs.get(tabId);
  if (!tab?.url || !tab.url.startsWith("http")) {
    return { ok: false, error: "请在普通 http(s) 网页标签页中使用填充" };
  }
  const origin = new URL(tab.url).origin;
  const { ctx, error } = await loadPageContext(tabId, origin);
  if (error) return error;

  const suggested = await suggestFirstCredential(ctx.origin, sendNative, selectedId);
  if (suggested.error) return suggested.error;

  const consumed = await consumeLoginSecrets(tabId, ctx, suggested.credentialId, sendNative);
  if (consumed.error) return consumed.error;
  const secrets = consumed.secrets;
  if (!secrets?.username && !secrets?.password) {
    return { ok: false, error: "未拿到用户名或密码", raw: consumed };
  }

  let deliver;
  try {
    deliver = await chrome.tabs.sendMessage(
      tabId,
      {
        type: "deliver_secret",
        mode: "login",
        document_id: ctx.documentId,
        origin: ctx.origin,
        username: secrets.username,
        password: secrets.password,
      },
      { frameId: ctx.frameId ?? 0 }
    );
  } catch (e) {
    return { ok: false, error: "投递到页面失败", detail: String(e) };
  }
  if (!deliver?.login_filled && !deliver?.filled) {
    return {
      ok: false,
      error: deliver?.reason || "页面上未找到账号或密码输入框",
      deliver,
    };
  }
  return { ok: true, filled: true, origin: ctx.origin, login_filled: true, credential_id: suggested.credentialId };
}

export async function runFillOtpFromVaultOnTab(tabId, sendNative, selectedId) {
  const tab = await chrome.tabs.get(tabId);
  if (!tab?.url || !tab.url.startsWith("http")) {
    return { ok: false, error: "请在普通 http(s) 网页标签页中使用填充" };
  }
  const origin = new URL(tab.url).origin;
  const { ctx, error } = await loadPageContext(tabId, origin);
  if (error) return error;

  const suggested = await suggestFirstCredential(ctx.origin, sendNative, selectedId);
  if (suggested.error) return suggested.error;
  const forOtp = suggested;
  const totpId = forOtp.candidate?.linked_totp_id;
  if (!totpId) {
    return {
      ok: false,
      error:
        "当前站点登录未关联 MFA。请在 CredPivot「凭据 → 登录密码」中编辑对应项并选择「关联 MFA / TOTP」（服务器页的 MFA 关联不用于浏览器填充）。",
    };
  }

  let codeResp = await sendNative({action: "credential.totp_code", credential_id: forOtp.credentialId, origin: ctx.origin});
  if (codeResp?.ok && codeResp.payload?.wait_seconds != null) {
    await new Promise((resolve) => setTimeout(resolve, (codeResp.payload.wait_seconds + 1) * 1000));
    codeResp = await sendNative({action: "credential.totp_code", credential_id: forOtp.credentialId, origin: ctx.origin});
  }
  const gate = gateHint(codeResp);
  if (gate) {
    return { ok: false, error: gate, raw: codeResp, needs_gate: true };
  }
  if (!codeResp?.ok) {
    return {
      ok: false,
      error: codeResp?.message || codeResp?.code || "读取 MFA 失败",
      raw: codeResp,
    };
  }
  const code = codeResp?.payload?.code;
  if (typeof code !== "string" || !code) {
    return { ok: false, error: "MFA 验证码为空" };
  }

  let deliver;
  try {
    deliver = await chrome.tabs.sendMessage(
      tabId,
      {
        type: "deliver_secret",
        mode: "otp",
        document_id: ctx.documentId,
        origin: ctx.origin,
        totp_code: code,
      },
      { frameId: ctx.frameId ?? 0 }
    );
  } catch (e) {
    return { ok: false, error: "投递到页面失败", detail: String(e) };
  }
  if (!deliver?.otp_filled && !deliver?.filled) {
    return {
      ok: false,
      error: deliver?.reason || "页面上未找到 MFA 输入框",
      deliver,
    };
  }
  return { ok: true, filled: true, origin: ctx.origin, otp_filled: true, credential_id: suggested.credentialId };
}

/** @deprecated 使用 runFillLoginOnTab + runFillOtpFromVaultOnTab */
export async function runFillOnTab(tabId, sendNative, selectedId) {
  return runFillLoginOnTab(tabId, sendNative, selectedId);
}

export async function runOtpFillOnTab(tabId, totpCode, sendNative) {
  const tab = await chrome.tabs.get(tabId);
  if (!tab?.url || !tab.url.startsWith("http")) {
    return { ok: false, error: "请在普通 http(s) 网页标签页中使用填充" };
  }
  const origin = new URL(tab.url).origin;
  const { ctx, error } = await loadPageContext(tabId, origin);
  if (error) return error;
  const deliver = await chrome.tabs.sendMessage(
    tabId,
    {
      type: "deliver_secret",
      mode: "otp",
      document_id: ctx.documentId,
      origin: ctx.origin,
      totp_code: totpCode,
    },
    { frameId: ctx.frameId ?? 0 }
  );
  if (!deliver?.otp_filled && !deliver?.filled) {
    return { ok: false, error: deliver?.reason || "未找到 MFA 输入框" };
  }
  return { ok: true };
}
