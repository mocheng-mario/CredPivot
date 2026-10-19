const HOST_NAME = "com.credpivot.chrome.m0";
const PROTOCOL_VERSION = 1;

/** @type {chrome.runtime.Port | null} */
let nativePort = null;
/** @type {string | null} */
let lastNativeError = null;
/** @type {Map<string, object>} */
const inflight = new Map();

function uuid() {
  return crypto.randomUUID();
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
    for (const [id] of inflight) {
      inflight.delete(id);
    }
  });
  return nativePort;
}

function sendNative(message) {
  return new Promise((resolve, reject) => {
    try {
      connectNativeIfNeeded();
    } catch (e) {
      reject(e);
      return;
    }
    const requestId = message.request_id || uuid();
    message.request_id = requestId;
    inflight.set(requestId, { createdAt: Date.now(), message });
    nativePort.postMessage(message);
    const listener = (response) => {
      if (response.request_id && response.request_id !== requestId) return;
      nativePort.onMessage.removeListener(listener);
      inflight.delete(requestId);
      resolve(response);
    };
    nativePort.onMessage.addListener(listener);
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg.type === "handshake") {
        const resp = await sendNative({
          action: "handshake",
          protocol_version: PROTOCOL_VERSION,
        });
        sendResponse({ ok: true, resp, lastNativeError });
        return;
      }
      if (msg.type === "agent_status") {
        const resp = await sendNative({ action: "status" });
        sendResponse(resp);
        return;
      }
      connectNativeIfNeeded();
      if (msg.type === "suggest_credentials") {
        const resp = await sendNative({
          action: "credential.suggest_for_origin",
          origin: msg.origin,
        });
        sendResponse(resp);
        return;
      }
      if (msg.type === "save_credential") {
        const resp = await sendNative({
          action: "credential.save",
          origin: msg.origin,
          username: msg.username,
          password: msg.password,
        });
        sendResponse(resp);
        return;
      }
      if (msg.type === "fill_prepare") {
        const tabId = sender.tab?.id ?? 0;
        const frameId = sender.frameId ?? 0;
        const documentId = sender.documentId ?? "";
        const resp = await sendNative({
          action: "credential.fill_prepare",
          credential_id: msg.credential_id,
          origin: msg.origin,
          tab_id: tabId,
          frame_id: frameId,
          document_id: documentId,
        });
        sendResponse(resp);
        return;
      }
      if (msg.type === "fill_consume") {
        const resp = await sendNative({
          action: "credential.fill_consume",
          request_id: msg.request_id,
          frame_id: sender.frameId ?? 0,
          document_id: sender.documentId ?? "",
        });
        sendResponse(resp);
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

setInterval(() => {
  if (!nativePort) return;
  if (inflight.size === 0) {
    nativePort.disconnect();
    nativePort = null;
  }
}, 30_000);
