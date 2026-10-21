import {
  runFillLoginOnTab,
  runFillOtpFromVaultOnTab,
  runOtpFillOnTab,
  requestPageContext,
} from "./fill_flow.js";

const HOST_NAME = "com.credpivot.chrome.m0";
const NATIVE_IDLE_DISCONNECT_MS = 5 * 60 * 1000;
const PROTOCOL_VERSION = 2;
const NATIVE_REQUEST_TIMEOUT_MS = 30_000;

/** @type {chrome.runtime.Port | null} */
let nativePort = null;
/** @type {string | null} */
let lastNativeError = null;
/** @type {Map<string, { resolve: Function, reject: Function, listener: Function, timer: ReturnType<typeof setTimeout> }>} */
const inflight = new Map();

function uuid() {
  return crypto.randomUUID();
}

function selectedAccountKey(tabId, origin) {
  return `selected_account:${tabId}:${origin}`;
}

// 仅保存账号 ID；不同标签页和网站分别记录，秘密不会写入扩展存储。
async function rememberSelectedAccount(tabId, origin, credentialId) {
  await chrome.storage.session.set({ [selectedAccountKey(tabId, origin)]: credentialId });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  (async () => {
    const stored = await chrome.storage.session.get(null);
    const keys = Object.keys(stored).filter((key) => key.startsWith(`selected_account:${tabId}:`));
    if (keys.length) await chrome.storage.session.remove(keys);
  })().catch(() => {});
});

/** 凭据操作只信任标签页真实 URL，不用消息自报的 origin。 */
async function originFromSender(sender, msg) {
  const tabId = msg?.tab_id ?? sender?.tab?.id;
  if (tabId != null) {
    try {
      const tab = await chrome.tabs.get(tabId);
      if (tab?.url?.startsWith("http")) {
        return new URL(tab.url).origin;
      }
    } catch (_) {
      return null;
    }
  }
  const url = sender?.tab?.url;
  if (url?.startsWith("http")) {
    try {
      return new URL(url).origin;
    } catch (_) {
      return null;
    }
  }
  return null;
}

function rejectAllInflight(reason) {
  for (const [id, entry] of inflight) {
    clearTimeout(entry.timer);
    nativePort?.onMessage.removeListener(entry.listener);
    entry.reject(reason);
    inflight.delete(id);
  }
}

function connectNativeIfNeeded() {
  if (nativePort) return nativePort;
  lastNativeError = null;
  try {
    nativePort = chrome.runtime.connectNative(HOST_NAME);
  } catch (e) {
    lastNativeError = String(e);
    nativePort = null;
    throw e;
  }
  if (chrome.runtime.lastError) {
    lastNativeError = chrome.runtime.lastError.message;
    nativePort = null;
    throw new Error(lastNativeError);
  }
  nativePort.onDisconnect.addListener(() => {
    const msg = chrome.runtime.lastError?.message;
    if (msg) {
      lastNativeError = msg;
    }
    nativePort = null;
    rejectAllInflight(new Error(lastNativeError || "native host disconnected"));
  });
  return nativePort;
}

// session storage 跨后台休眠保留，浏览器退出、扩展重载或更新后自动失效。
let browserSessionPromise;
function browserSessionId() {
  return browserSessionPromise ??= (async () => {
    const stored = await chrome.storage.session.get("browser_session_id");
    if (stored.browser_session_id) return stored.browser_session_id;
    const id = uuid();
    await chrome.storage.session.set({ browser_session_id: id });
    return id;
  })().catch((error) => { browserSessionPromise = null; throw error; });
}

async function sendNative(message) {
  message.browser_session_id = await browserSessionId();
  return new Promise((resolve, reject) => {
    try {
      connectNativeIfNeeded();
    } catch (e) {
      reject(e);
      return;
    }
    const requestId = message.request_id || uuid();
    message.request_id = requestId;
    const listener = (response) => {
      if (!response?.request_id || response.request_id !== requestId) {
        return;
      }
      const entry = inflight.get(requestId);
      if (!entry) return;
      clearTimeout(entry.timer);
      nativePort.onMessage.removeListener(listener);
      inflight.delete(requestId);
      touchNativeActivity();
      resolve(response);
    };
    const timer = setTimeout(() => {
      nativePort?.onMessage.removeListener(listener);
      inflight.delete(requestId);
      reject(new Error("native request timeout"));
    }, NATIVE_REQUEST_TIMEOUT_MS);
    inflight.set(requestId, { resolve, reject, listener, timer });
    touchNativeActivity();
    nativePort.postMessage(message);
    nativePort.onMessage.addListener(listener);
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      // 只有扩展自己的界面能发起操作；网页及内容脚本不能自行保存或领取秘密。
      if (sender.id !== chrome.runtime.id || sender.tab || !sender.url?.startsWith(chrome.runtime.getURL(""))) {
        sendResponse({ok:false,code:"forbidden",message:"请从扩展面板操作"}); return;
      }
      if (msg.type === "handshake") {
        const resp = await sendNative({
          action: "handshake",
          protocol_version: PROTOCOL_VERSION,
        });
        sendResponse({
          ok: resp?.ok === true,
          code: resp?.code,
          message: resp?.message,
          payload: resp?.payload,
          protocol_version: resp?.protocol_version,
          lastNativeError,
        });
        return;
      }
      if (msg.type === "agent_status") {
        const resp = await sendNative({ action: "status" });
        sendResponse(resp);
        return;
      }
      if (msg.type === "select_account") {
        const origin = await originFromSender(sender, msg);
        if (!origin || origin !== msg.origin || typeof msg.credential_id !== "string") {
          sendResponse({ ok: false, message: "页面已改变，请重新打开插件面板" });
          return;
        }
        await rememberSelectedAccount(msg.tab_id, origin, msg.credential_id);
        sendResponse({ ok: true });
        return;
      }
      connectNativeIfNeeded();
      if (msg.type === "suggest_credentials") {
        const origin = await originFromSender(sender, msg);
        if (!origin) {
          sendResponse({ ok: false, code: "bad_origin", message: "无法确定页面 origin" });
          return;
        }
        const resp = await sendNative({
          action: "credential.suggest_for_origin",
          origin,
        });
        if (resp?.ok) {
          const key = selectedAccountKey(msg.tab_id, origin);
          const stored = await chrome.storage.session.get(key);
          const selected = stored[key];
          const valid = (resp.payload?.candidates ?? []).some((row) => row.id === selected);
          resp.payload = { ...resp.payload, selected_credential_id: valid ? selected : null };
          if (selected && !valid) await chrome.storage.session.remove(key);
        }
        sendResponse(resp);
        return;
      }
      if (msg.type === "save_credential" || msg.type === "update_credential") {
        const origin = await originFromSender(sender, msg);
        if (!origin) {
          sendResponse({ ok: false, code: "bad_origin", message: "无法确定页面 origin" });
          return;
        }
        const page = await requestPageContext(msg.tab_id);
        if (page?.documentId !== msg.document_id || page?.origin !== origin) {
          sendResponse({ok:false,message:"页面已改变，请重新读取表单"}); return;
        }
        const resp = await sendNative({
          action: msg.type === "update_credential" ? "credential.update" : "credential.save",
          credential_id: msg.credential_id, expected_revision: msg.expected_revision,
          origin, username: msg.username, password: msg.password,
        });
        sendResponse(resp);
        return;
      }
      if (msg.type === "fill_prepare") {
        const tabId = msg.tab_id ?? sender.tab?.id ?? 0;
        const frameId = msg.frame_id ?? 0;
        const documentId = msg.document_id ?? "";
        const origin = await originFromSender(sender, msg);
        if (!origin) {
          sendResponse({ ok: false, code: "bad_origin", message: "无法确定页面 origin" });
          return;
        }
        const resp = await sendNative({
          action: "credential.fill_prepare",
          credential_id: msg.credential_id,
          origin,
          tab_id: tabId,
          frame_id: frameId,
          document_id: documentId,
        });
        sendResponse(resp);
        return;
      }
      if (msg.type === "fill_consume") {
        const origin = (await originFromSender(sender, msg)) ?? "";
        const resp = await sendNative({
          action: "credential.fill_consume",
          request_id: msg.request_id,
          origin,
          frame_id: msg.frame_id ?? 0,
          document_id: msg.document_id ?? "",
        });
        sendResponse(resp);
        return;
      }
      if (msg.type === "fill_login_tab" || msg.type === "fill_active_tab") {
        const tabId = msg.tab_id;
        if (!tabId) {
          sendResponse({ ok: false, error: "缺少 tab_id" });
          return;
        }
        const result = await runFillLoginOnTab(tabId, sendNative, msg.credential_id);
        // 后台负责记录，popup 因指纹验证失焦关闭后仍能保留本次成功使用的账号。
        if (result.ok) {
          try {
            await rememberSelectedAccount(tabId, result.origin, result.credential_id);
          } catch (_) {
            result.selection_remembered = false;
          }
        }
        sendResponse(result);
        return;
      }
      if (msg.type === "fill_otp_vault_tab") {
        const tabId = msg.tab_id;
        if (!tabId) {
          sendResponse({ ok: false, error: "缺少 tab_id" });
          return;
        }
        const result = await runFillOtpFromVaultOnTab(tabId, sendNative, msg.credential_id);
        if (result.ok) {
          try {
            await rememberSelectedAccount(tabId, result.origin, result.credential_id);
          } catch (_) {
            result.selection_remembered = false;
          }
        }
        sendResponse(result);
        return;
      }
      if (msg.type === "fill_otp_tab") {
        const tabId = msg.tab_id;
        const code = msg.totp_code;
        if (!tabId || !code) {
          sendResponse({ ok: false, error: "缺少 tab_id 或验证码" });
          return;
        }
        const result = await runOtpFillOnTab(tabId, code, sendNative);
        sendResponse(result);
        return;
      }
      sendResponse({ ok: false, error: "unknown message" });
    } catch (e) {
      sendResponse({
        ok: false,
        error: String(e),
        lastNativeError,
        hint: "在 Mac App 填写扩展 ID 并点击「安装 Chrome Native Host」，然后完全退出 Chrome 再打开",
      });
    }
  })();
  return true;
});

let lastNativeActivity = Date.now();

function touchNativeActivity() {
  lastNativeActivity = Date.now();
}

// 仅在长时间空闲时断开，避免 popup 关闭后立刻掉线。
setInterval(() => {
  if (!nativePort) return;
  if (inflight.size > 0) return;
  if (Date.now() - lastNativeActivity < NATIVE_IDLE_DISCONNECT_MS) return;
  nativePort.disconnect();
  nativePort = null;
}, 60_000);
