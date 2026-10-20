import { runFillOnTab } from "./fill_flow.js";

const HOST_NAME = "com.credpivot.chrome.m0";
const NATIVE_IDLE_DISCONNECT_MS = 5 * 60 * 1000;
const PROTOCOL_VERSION = 1;
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
        const tabId = msg.tab_id ?? sender.tab?.id ?? 0;
        const frameId = msg.frame_id ?? 0;
        const documentId = msg.document_id ?? "";
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
          origin: msg.origin ?? "",
          frame_id: msg.frame_id ?? 0,
          document_id: msg.document_id ?? "",
        });
        sendResponse(resp);
        return;
      }
      if (msg.type === "fill_active_tab") {
        const tabId = msg.tab_id;
        if (!tabId) {
          sendResponse({ ok: false, error: "缺少 tab_id" });
          return;
        }
        const result = await runFillOnTab(tabId, sendNative);
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
