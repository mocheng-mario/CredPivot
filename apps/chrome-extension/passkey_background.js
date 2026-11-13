const ENABLED_SITES = "passkey_enabled_sites";
let afterSiteChange = async () => {};
export function onPasskeySitesChanged(listener) { afterSiteChange = listener; }
const active = new Map();
const PAGE_SCRIPT = "credpivot-passkey-page";

function rpIdMatchesHost(rpId, host) {
  if (rpId == null || rpId === "") return true;
  // 此处只预筛选主机关系，Core 会用 PSL 拒绝公共后缀 RP。
  return host === rpId || (host.endsWith(`.${rpId}`) && host.length > rpId.length + 1);
}

async function sessionLinkedLoginId(tabId, origin) {
  if (!tabId || !origin?.startsWith("https://")) return undefined;
  const key = `selected_account:${tabId}:${origin}`;
  const stored = await chrome.storage.session.get(key);
  const id = stored[key];
  // 显式保存的空串表示「独立账号」，不向 App 建议关联。
  return typeof id === "string" && id ? id : undefined;
}

function siteEnabledInMap(sites, origin) {
  if (Object.prototype.hasOwnProperty.call(sites, origin)) return sites[origin] === true;
  return true;
}

export async function syncPasskeyScripts() {
  // 默认在所有 HTTPS 页面注入；仅用户手动关闭的站点在 handlePasskey 中回退浏览器。
  const matches = ["https://*/*"];
  const exists = (await chrome.scripting.getRegisteredContentScripts({ids:[PAGE_SCRIPT]})).length > 0;
  const script = {id:PAGE_SCRIPT,matches,js:["passkey_page.js"],world:"MAIN",runAt:"document_start",allFrames:false,persistAcrossSessions:true};
  const write = async (entry) => {
    if (exists) await chrome.scripting.updateContentScripts([entry]);
    else await chrome.scripting.registerContentScripts([entry]);
  };
  try {
    await write(script);
  } catch (error) {
    // Firefox 的 scripting schema 若拒绝该 Chrome 字段，去掉后重试；其他错误保持原样抛出。
    const message = String(error?.message || error);
    if (!script.persistAcrossSessions || !message.includes("persistAcrossSessions")) throw error;
    delete script.persistAcrossSessions;
    await write(script);
  }
  // 已打开的页面须刷新，确保拦截脚本和通信桥使用有效的扩展上下文。
}

export async function enablePasskeySiteIfUnset(origin) {
  const stored = await chrome.storage.local.get(ENABLED_SITES);
  const sites = stored[ENABLED_SITES] || {};
  return siteEnabledInMap(sites, origin);
}

export async function passkeySiteState(origin) {
  const stored = await chrome.storage.local.get(ENABLED_SITES);
  return siteEnabledInMap(stored[ENABLED_SITES] || {}, origin);
}

export async function setPasskeySiteState(origin, enabled) {
  const stored = await chrome.storage.local.get(ENABLED_SITES);
  const sites = stored[ENABLED_SITES] || {};
  sites[origin] = enabled === true;
  await syncPasskeyScripts();
  await chrome.storage.local.set({[ENABLED_SITES]: sites});
  try { await afterSiteChange(); } catch (_) { /* 本机 App 未连接时保留浏览器里的开关。 */ }
  for (const request of active.values()) {
    if (request.origin === origin && !enabled) request.cancelled = true;
  }
}

async function checkDocument(request) {
  if (request.cancelled) throw new Error("请求已取消");
  const tab = await chrome.tabs.get(request.tabId);
  if (!tab.url || new URL(tab.url).origin !== request.origin) throw new Error("网页来源已改变");
  const response = await chrome.tabs.sendMessage(request.tabId, {type:"passkey_document_check"}, {documentId:request.documentId,frameId:0});
  if (response?.document_token !== request.documentToken) throw new Error("页面已跳转，请重新操作");
  if (request.cancelled) throw new Error("请求已取消");
}

function supported(kind, options, origin) {
  if (!options || typeof options !== "object" || JSON.stringify(options).length > 64 * 1024) return false;
  const host = new URL(origin).hostname;
  const rpId = kind === "create" ? options.rp?.id : options.rpId;
  if (!rpIdMatchesHost(rpId, host)) return false;
  if (options.extensions && Object.keys(options.extensions).some((key) => key !== "credProps" &&
      !(key === "appid" && kind === "get") && !(key === "appidExclude" && kind === "create"))) return false;
  const attachment = options.authenticatorSelection?.authenticatorAttachment;
  if (attachment !== undefined && attachment !== "platform") return false;
  if (options.attestation === "enterprise") return false;
  if (kind === "create" && (!Array.isArray(options.pubKeyCredParams) || !options.pubKeyCredParams.some((p) => p?.type === "public-key" && p.alg === -7))) return false;
  return true;
}

export function cancelPasskey(message, sender) {
  const request = active.get(message.request_id);
  if (request?.tabId === sender.tab?.id && request.documentId === sender.documentId) request.cancelled = true;
}

export async function handlePasskey(message, sender, sendNative, gateGeneration = () => 0) {
  if (sender.frameId !== 0 || !sender.documentId || !sender.tab?.id || !/^https:\/\//.test(sender.url || "") ||
      !["create","get"].includes(message.kind) || typeof message.request_id !== "string" ||
      !/^[0-9a-f-]{36}$/.test(message.request_id) || typeof message.document_token !== "string") {
    return {error:{name:"SecurityError",message:"通行密钥仅支持顶层 HTTPS 页面"}};
  }
  const origin = new URL(sender.url).origin;
  if ([...active.values()].some((r) => r.tabId === sender.tab.id) || active.size >= 8) {
    return {error:{name:"NotAllowedError",message:"已有通行密钥请求正在处理"}};
  }
  const request = {tabId:sender.tab.id,documentId:sender.documentId,documentToken:message.document_token,origin,cancelled:false};
  active.set(message.request_id,request);
  const options = message.options;
  const requested = Number(options?.timeout);
  const expires = Date.now() + (Number.isFinite(requested) && requested > 0 ? Math.min(requested,120_000) : 120_000);
  let started = false;
  let sent = false;
  let waitingForGate = false, gateRequested = false;
  let expectedGateGeneration;
  try {
    if (!await passkeySiteState(origin) || !supported(message.kind,options,origin)) return {fallback:true};
    // 以 Chrome 提供的发送方 URL/documentId 为准，忽略网页自报的 origin。
    while (Date.now() < expires) {
      await checkDocument(request);
      if (waitingForGate) {
        // 取消验证后只读状态并结束；不能再次 begin 重建待验证标记，导致指纹反复弹出。
        const state = await sendNative({action:"status"});
        await checkDocument(request);
        if (expectedGateGeneration !== gateGeneration()) {
          return {error:{name:"NotAllowedError",message:"已有其他验证请求，请重新发起本次操作"}};
        }
        if (!state?.ok) return {error:{name:"NotAllowedError",message:state?.message || "无法读取本机验证状态"}};
        if (state.payload?.extension_gate_active && state.payload?.unlocked && state.payload?.database_attached) {
          waitingForGate = false;
        } else {
          if (state.payload?.extension_gate_pending !== true) {
            return {error:{name:"NotAllowedError",message:state.payload?.extension_gate_pending === false
              ? "验证已取消，请重新发起通行密钥操作" : "请更新 App，或先在插件面板完成验证后重试"}};
          }
          await new Promise((resolve) => setTimeout(resolve,500));
          continue;
        }
      }
      sent = true;
      let beginPayload = {action:"passkey.begin",passkey_request_id:message.request_id,origin,kind:message.kind,options};
      if (!started && message.kind === "create") {
        const linked = await sessionLinkedLoginId(request.tabId, origin);
        if (linked) beginPayload = {...beginPayload, suggested_linked_login_id: linked};
      }
      const response = await sendNative(started ? {action:"passkey.poll",passkey_request_id:message.request_id,origin} : beginPayload);
      await checkDocument(request);
      if (!response?.ok) {
        // 仅首次连接可等待解锁；操作中途失去授权立即失败，不静默重新签名。
        if (!started && !gateRequested && response?.code === "extension_gate_required") {
          gateRequested = true;
          waitingForGate = true;
          expectedGateGeneration = gateGeneration();
          await new Promise((resolve) => setTimeout(resolve,500));
          continue;
        }
        return {error:{name:"NotAllowedError",message:response?.message || "CredPivot 操作失败"}};
      }
      const result = response.payload;
      if (result?.state === "fallback") return {fallback:true};
      if (result?.state === "done") {
        if (!result.error && message.kind === "create") await enablePasskeySiteIfUnset(origin);
        return result.error ? {error:result.error} : {credential:result.credential};
      }
      if (result?.state !== "pending") throw new Error("无效的通行密钥响应");
      started = true;
      await new Promise((resolve) => setTimeout(resolve,350));
    }
    return {error:{name:"NotAllowedError",message:"通行密钥请求已超时"}};
  } catch (_) {
    return {error:{name:"NotAllowedError",message:"页面已改变、操作已取消或本机连接中断，请重试"}};
  } finally {
    active.delete(message.request_id);
    if (sent) {
      try { await sendNative({action:'extension.cancel',gate_request_id:message.request_id}); } catch (_) { /* 不重新发起验证。 */ }
    }
    // 包括取消早于 begin 响应的情形；不能让后台残留待授权请求。
    if (sent) {
      try { await sendNative({action:"passkey.cancel",passkey_request_id:message.request_id}); } catch (_) { /* Agent 会自动过期。 */ }
    }
  }
}
