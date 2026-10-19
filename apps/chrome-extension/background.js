const HOST_NAME = "com.credpivot.chrome.m0";
const PROTOCOL_VERSION = 1;

/** @type {chrome.runtime.Port | null} */
let nativePort = null;
/** @type {Map<string, object>} */
const inflight = new Map();

function uuid() {
  return crypto.randomUUID();
}

function sendNative(message) {
  return new Promise((resolve, reject) => {
    if (!nativePort) {
      reject(new Error("native port not connected"));
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

function connectNativeIfNeeded() {
  if (nativePort) return nativePort;
  nativePort = chrome.runtime.connectNative(HOST_NAME);
  nativePort.onDisconnect.addListener(() => {
    nativePort = null;
    // MV3: service worker 回收后不得续期未完成请求
    for (const [id] of inflight) {
      inflight.delete(id);
    }
  });
  return nativePort;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      connectNativeIfNeeded();
      if (msg.type === "handshake") {
        const resp = await sendNative({
          action: "handshake",
          protocol_version: PROTOCOL_VERSION,
        });
        sendResponse({ ok: true, resp });
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
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true;
});

// 空闲断开 Native 端口（M0：仅在有 inflight 时保持）
setInterval(() => {
  if (!nativePort) return;
  if (inflight.size === 0) {
    nativePort.disconnect();
    nativePort = null;
  }
}, 30_000);
