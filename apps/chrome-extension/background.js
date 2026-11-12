import {
  runFillLoginOnTab,
  runFillOtpFromVaultOnTab,
  runOtpFillOnTab,
  requestPageContext,
} from "./fill_flow.js";
import {handlePasskey, cancelPasskey, passkeySiteState, setPasskeySiteState, syncPasskeyScripts, enablePasskeySiteIfUnset, onPasskeySitesChanged} from "./passkey_background.js";
import {addMfa, cancelMfa, cancelMfaIfOriginChanged} from "./mfa_background.js";

chrome.runtime.onInstalled.addListener(() => {
  void syncPasskeyScripts().catch(() => {});
  void publishPasskeySites();
  // 更新后旧标签页的脚本上下文可能失效，主动升级非敏感 UI，不重放填充或认证。
  void chrome.tabs.query({}).then((tabs) => Promise.allSettled(tabs
    .filter((tab) => tab.id && /^https?:\/\//.test(tab.url || ''))
    .map((tab) => chrome.scripting.executeScript({target:{tabId:tab.id,frameIds:[0]},files:['content.js'],world:'ISOLATED'}))))
    .catch(() => {});
});
chrome.runtime.onStartup.addListener(() => {
  void syncPasskeyScripts().catch(() => {});
  void publishPasskeySites();
});

const HOST_NAME = "com.credpivot.chrome.m0";
const NATIVE_IDLE_DISCONNECT_MS = 5 * 60 * 1000;
const PROTOCOL_VERSION = 2;
const NATIVE_REQUEST_TIMEOUT_MS = 30_000;
const mfaResults = new Map();
let nativeGateGeneration = 0;

/** @type {chrome.runtime.Port | null} */
let nativePort = null;
/** @type {string | null} */
let lastNativeError = null;
/** @type {Map<string, { resolve: Function, reject: Function, listener: Function, timer: ReturnType<typeof setTimeout> }>} */
const inflight = new Map();

const METADATA_CACHE_PREFIX = "metadata_cache:";
const METADATA_CACHE_TTL_MS = 5 * 60 * 1000;
async function clearMetadataCache() {
  try {
    const stored = await chrome.storage.session.get(null);
    const keys = Object.keys(stored).filter((key) => key.startsWith(METADATA_CACHE_PREFIX));
    if (keys.length) await chrome.storage.session.remove(keys);
  } catch (_) { /* 缓存不可用不影响实时凭据操作。 */ }
}

// 严格白名单：即便响应将来增加字段，也不能把密码、密钥或验证码写入扩展存储。
function metadataPayload(payload, mfa) {
  const fields = mfa ? ["id", "issuer", "account", "linked", "match_rank", "partition_id", "partition_name"] :
    ["id", "origin", "username", "display_name", "current_revision", "partition_id", "partition_name"];
  return {
    candidates: (payload.candidates ?? []).map((row) => Object.fromEntries(
      fields.filter((field) => Object.hasOwn(row, field)).map((field) => [field, row[field]]))),
    ...(mfa ? {can_check_other_matches: Boolean(payload.can_check_other_matches), all_matches: Boolean(payload.all_matches)} : {}),
  };
}

async function suggestMetadata(request, mfa = false) {
  // 授权、锁定和修订始终向 Agent 实时查询，缓存只用于列表展示。
  const state = await sendNative({action: "status"});
  const status = state?.payload;
  if (!state?.ok || !status?.unlocked || !status.database_attached || !status.extension_gate_active || !status.data_revision) {
    await clearMetadataCache();
    return await sendNative({...request});
  }
  const key = METADATA_CACHE_PREFIX + JSON.stringify([request.action, request.origin, request.credential_id ?? "", Boolean(request.include_other_matches)]);
  let cached;
  try { cached = (await chrome.storage.session.get(key))[key]; } catch (_) { /* 读取失败退回实时查询。 */ }
  if (cached && cached.revision === status.data_revision && cached.lockGeneration === status.vault_lock_generation &&
      Date.now() - cached.created >= 0 && Date.now() - cached.created < METADATA_CACHE_TTL_MS) {
    return {ok: true, payload: metadataPayload(cached.payload, mfa)};
  }
  const response = await sendNative({...request});
  if (response?.ok) {
    const payload = metadataPayload(response.payload ?? {}, mfa);
    try {
      const entries = await chrome.storage.session.get(null);
      const old = Object.entries(entries).filter(([name]) => name.startsWith(METADATA_CACHE_PREFIX))
        .sort((a, b) => (a[1].created ?? 0) - (b[1].created ?? 0));
      if (old.length >= 32) await chrome.storage.session.remove(old.slice(0, old.length - 31).map(([name]) => name));
      if (JSON.stringify(payload).length <= 256 * 1024) await chrome.storage.session.set({[key]: {
        created: Date.now(), revision: status.data_revision, lockGeneration: status.vault_lock_generation, payload,
      }});
    } catch (_) { /* 缓存写入失败不使查询失败。 */ }
  } else { await clearMetadataCache(); }
  return response;
}

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
  void cancelMfa(tabId, sendNative).catch(() => {});
  mfaResults.delete(tabId);
  for (const record of inlineSessions.values()) if (record.tabId === tabId) cancelInline(record,false);
  (async () => {
    const stored = await chrome.storage.session.get(null);
    const keys = Object.keys(stored).filter((key) => key.startsWith(`selected_account:${tabId}:`) || key.startsWith(`selected_mfa:${tabId}:`));
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

// 每个请求绑定创建它的 Port，迟到的旧连接回调不能清理新连接。
function closeNativePort(port, error, disconnect = true) {
  if (nativePort === port) {
    nativePort = null;
    lastNativeError = error.message;
    void clearMetadataCache();
  }
  for (const [id, entry] of inflight) {
    if (entry.port !== port) continue;
    clearTimeout(entry.timer);
    port.onMessage.removeListener(entry.listener);
    inflight.delete(id);
    entry.reject(error);
  }
  if (disconnect) { try { port.disconnect(); } catch (_) { /* 已断开。 */ } }
}

function connectionError(message) {
  const error = new Error(message);
  error.nativeConnection = true;
  return error;
}

function connectNativeIfNeeded() {
  if (nativePort) return nativePort;
  lastNativeError = null;
  let port;
  try { port = chrome.runtime.connectNative(HOST_NAME); }
  catch (_) { throw connectionError("无法启动本机连接，请在 App 中更新 Native Host 后重试"); }
  nativePort = port;
  port.onDisconnect.addListener(() => {
    const message = chrome.runtime.lastError?.message || "native host disconnected";
    closeNativePort(port, connectionError(message), false);
  });
  return port;
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

const AUTO_VERIFICATION_BLOCKED = 'automatic_verification_blocked';
let verificationStarting = false;
let verificationWatch = null;
const cancelledVerifications = new Set();

async function watchBrowserVerification(watch) {
  const deadline = Date.now() + 120_000;
  try {
    while (verificationWatch === watch && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve,1000));
      if (verificationWatch !== watch) return;
      const state = await sendNative({action:'status'});
      if (verificationWatch !== watch || !state?.ok) return;
      if (state.payload?.extension_gate_active && state.payload?.unlocked && state.payload?.database_attached) {
        // 工具栏可能因系统指纹窗口而关闭，成功状态仍由后台收尾。
        if (verificationStarting) continue;
        verificationStarting = true;
        try {
          await chrome.storage.session.remove(AUTO_VERIFICATION_BLOCKED);
          if (verificationWatch === watch) verificationWatch = null;
        } finally { verificationStarting = false; }
        return;
      }
      if (state.payload?.extension_gate_pending !== true ||
          (state.payload?.extension_gate_request_id && state.payload.extension_gate_request_id !== watch.requestId)) return;
    }
  } catch (_) { /* 无法确认验证成功时，保留手动入口，不自动重试验证。 */ }
}

async function requestBrowserVerification(requestId, automatic = false, validate = null) {
  if (verificationStarting) return {ok:false,code:'extension_gate_paused',message:'正在检查验证状态，请稍后点击「连接与验证」'};
  verificationStarting = true;
  try {
    const state = await sendNative({action:'status'});
    if (cancelledVerifications.has(requestId)) return {ok:false,code:'extension_gate_cancelled'};
    if (!state?.ok) return state;
    if (state.payload?.extension_gate_active && state.payload?.unlocked && state.payload?.database_attached) {
      await chrome.storage.session.remove(AUTO_VERIFICATION_BLOCKED);
      verificationWatch = null;
      return state;
    }
    const stored = await chrome.storage.session.get(AUTO_VERIFICATION_BLOCKED);
    if (automatic && stored[AUTO_VERIFICATION_BLOCKED] === true) {
      return {ok:false,code:'extension_gate_paused',message:'自动验证已暂停，请点击「连接与验证」手动继续'};
    }
    // 在发起验证前就记录本次尝试，防止取消后重开面板或后台重启又自动弹窗。
    await chrome.storage.session.set({[AUTO_VERIFICATION_BLOCKED]:true});
    const watch = {requestId};
    verificationWatch = watch;
    if (validate) await validate();
    if (cancelledVerifications.has(requestId)) return {ok:false,code:'extension_gate_cancelled'};
    const response = await sendNative({action:'handshake',protocol_version:PROTOCOL_VERSION,request_id:requestId});
    if (response?.ok) {
      await chrome.storage.session.remove(AUTO_VERIFICATION_BLOCKED);
      verificationWatch = null;
    } else if (response?.code === 'extension_gate_required') {
      void watchBrowserVerification(watch);
    }
    return response;
  } finally { verificationStarting = false; }
}

function sendNativeOnce(message) {
  return new Promise((resolve, reject) => {
    let port;
    try { port = connectNativeIfNeeded(); }
    catch (error) { reject(error); return; }
    const requestId = message.request_id || uuid();
    const listener = (response) => {
      if (response?.request_id !== requestId) return;
      const entry = inflight.get(requestId);
      if (!entry || entry.port !== port) return;
      clearTimeout(entry.timer);
      port.onMessage.removeListener(listener);
      inflight.delete(requestId);
      touchNativeActivity();
      // 更新 App 后旧 Host 可能仍存活；释放它，下次由 Chrome 按新清单启动。
      if (["peer_denied", "protocol_mismatch", "host_outdated", "browser_parent_denied"].includes(response.code)) {
        closeNativePort(port, connectionError("本机组件已变化，请在 App 更新 Native Host 后重试"));
      }
      resolve(response);
    };
    const timer = setTimeout(() => {
      closeNativePort(port, connectionError("本机连接超时，连接已重置，请重试"));
    }, NATIVE_REQUEST_TIMEOUT_MS);
    inflight.set(requestId, { resolve, reject, listener, timer, port });
    touchNativeActivity();
    port.onMessage.addListener(listener);
    try { port.postMessage({...message, request_id: requestId}); }
    catch (_) { closeNativePort(port, connectionError("本机连接已断开，请重试")); }
  });
}

async function sendNative(message) {
  const verificationStartedMs = Date.now();
  const session = await browserSessionId();
  const verification = ['handshake','extension.connect','extension.cancel','passkey.begin'].includes(message.action);
  const request = {...message, browser_session_id: session,
    ...(verification ? {verification_started_ms:verificationStartedMs} : {})};
  // 验证握手会唤起系统弹窗，响应丢失后也不能自动重放。
  const retryable = ["status", "agent.status", "passkey.sites_report",
    "credential.suggest_for_origin", "mfa.suggest_for_origin"].includes(message.action);
  for (let attempt = 0; ; attempt++) {
    try {
      const response = await sendNativeOnce(request);
      if (retryable && attempt === 0 && ["app_unreachable", "agent_unavailable", "agent_timeout", "host_outdated"].includes(response?.code)) {
        if (nativePort) closeNativePort(nativePort, connectionError("正在重新连接本机 App"));
        continue;
      }
      if (response?.code === 'extension_gate_required' &&
          ['handshake','extension.connect','passkey.begin'].includes(message.action)) nativeGateGeneration++;
      return response;
    } catch (error) {
      if (!retryable || attempt > 0 || !error.nativeConnection) throw error;
    }
  }
}

let publishingPasskeySites = false;
async function publishPasskeySites() {
  if (publishingPasskeySites) return;
  publishingPasskeySites = true;
  try {
    const stored = await chrome.storage.local.get("passkey_enabled_sites");
    const response = await sendNative({action: "passkey.sites_report", sites: stored.passkey_enabled_sites || {}});
    const pending = response?.payload?.pending;
    if (!Array.isArray(pending) || pending.length === 0) return;
    for (const origin of pending) {
      if (typeof origin === "string") await enablePasskeySiteIfUnset(origin);
    }
    const again = await chrome.storage.local.get("passkey_enabled_sites");
    await sendNative({action: "passkey.sites_report", sites: again.passkey_enabled_sites || {}});
  } catch (_) { /* App 未运行时保留插件本地开关。 */ }
  finally { publishingPasskeySites = false; }
}
onPasskeySitesChanged(publishPasskeySites);

// 页面入口只建立短期操作；候选界面和选取操作必须来自扩展自己的 iframe。
const inlineSessions = new Map();
const INLINE_HIDDEN_SITES = 'inline_hidden_sites';
const INLINE_TTL_MS = 5 * 60 * 1000;
function inlineUIUrl() { return chrome.runtime.getURL('inline.html'); }
function inlineError(message, code) { return Object.assign(new Error(message),{code}); }
function inlineSafeError(response) {
  const reason = response?.error || response?.message || response?.code;
  const messages = {target_changed:'输入框已改变，请重新点击填充图标',document_mismatch:'页面已跳转，请重新填充',
    no_login_fields:'未找到可填写的登录框',no_otp_field:'未找到完整、可填写的验证码输入框',
    locked:'保险库已锁定，请点击「连接与验证」解锁。',
    extension_gate_required:'需要身份验证，请点击「连接与验证」。',
    extension_gate_cancelled:'验证已取消，需要继续时请点击「连接与验证」。',
    extension_gate_paused:'自动验证已暂停，请点击「连接与验证」手动继续。',
    host_outdated:'本机组件已更新，请关闭面板后重新打开；若仍失败，请在 App 更新 Native Host。',
    agent_timeout:'App 响应超时，请检查 App 后重试；刚才的填充不会自动重复。',
    agent_unavailable:'App 连接已中断，请点击「连接与验证」重试。',
    app_unreachable:'无法连接 App，请先打开 CredPivot，再点击「连接与验证」。'};
  return inlineError(messages[response?.code] || messages[reason] || (typeof reason === 'string' ? reason : '填充未完成，请重试'),response?.code);
}
function inlineRecord(token) {
  const record = inlineSessions.get(token);
  if (!record || record.cancelled || Date.now() > record.expires) {
    if (record) cancelInline(record);
    throw inlineError('本次操作已过期，请重新点击输入框旁的图标','inline_session_expired');
  }
  return record;
}
function cancelInline(record, close = true) {
  record.cancelled = true;
  inlineSessions.delete(record.token);
  if (record.gateRequestId) void sendNative({action:'extension.cancel',gate_request_id:record.gateRequestId}).catch(() => {});
  if (close) void chrome.tabs.sendMessage(record.tabId,
    {type:'inline_close',token:record.token},{frameId:0,documentId:record.chromeDocumentId}).catch(() => {});
}
async function checkInline(record, allowNativePrompt = false) {
  if (inlineRecord(record.token) !== record) throw inlineError('请求已取消');
  const tab = await chrome.tabs.get(record.tabId);
  if (!tab?.active || tab.url !== record.url) throw inlineError('页面或标签页已改变，请重新填充');
  if (!allowNativePrompt && !(await chrome.windows.get(record.windowId)).focused) throw inlineError('请回到原来的浏览器窗口重新填充');
  const page = await requestPageContext(record.tabId,record.targetId);
  if (page?.documentId !== record.documentId || page.url !== record.url || page.targetId !== record.targetId || !page.targetValid) {
    throw inlineError('页面或目标输入框已改变，请重新填充');
  }
  if (inlineRecord(record.token) !== record) throw inlineError('请求已取消');
}
async function authoriseInline(record, verify = false, automatic = false) {
  await checkInline(record);
  if (record.authorised) {
    await checkInlineAuthorisation(record); return;
  }
  const currentState = await sendNative({action:'status'});
  await checkInline(record);
  if (!currentState?.ok) throw inlineSafeError(currentState);
  if (currentState.payload?.extension_gate_active && currentState.payload?.unlocked) {
    acceptInlineAuthorisation(record,currentState); return;
  }
  if (!verify) throw inlineError('尚未连接保险库，请点击「连接与验证」','extension_gate_required');
  const requestId = uuid();
  record.gateRequestId = requestId;
  try {
    const response = await requestBrowserVerification(requestId,automatic,() => checkInline(record));
    await checkInline(record,true);
    if (response?.ok) {
      const state = await sendNative({action:'status'});
      acceptInlineAuthorisation(record,state); return;
    }
    if (response?.code !== 'extension_gate_required') throw inlineSafeError(response);
    const gateGeneration = nativeGateGeneration;
    const deadline = Date.now() + 120_000;
    // 只发起一次验证，随后只读状态；取消不能通过重复握手又唤起一次指纹。
    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve,1000));
      await checkInline(record,true);
      const state = await sendNative({action:'status'});
      if (gateGeneration !== nativeGateGeneration) throw inlineError('本次验证请求已变化，请重新连接并验证','extension_gate_cancelled');
      if (!state?.ok) throw inlineSafeError(state);
      if (state.payload?.extension_gate_active && state.payload?.unlocked) {
        acceptInlineAuthorisation(record,state);
        // 主密码验证可能临时前台显示 App；回到原 Chrome 窗口后再投递，不填后台窗口。
        const focusDeadline = Date.now() + 20_000;
        while (Date.now() < focusDeadline) {
          await checkInline(record,true);
          if ((await chrome.windows.get(record.windowId)).focused) return;
          await new Promise((resolve) => setTimeout(resolve,250));
        }
        throw inlineError('验证已完成，请回到原网页重新点击填充图标');
      }
      if (state.payload?.extension_gate_pending === false ||
          (state.payload?.extension_gate_request_id && state.payload.extension_gate_request_id !== requestId)) {
        throw inlineError('验证已取消或未能启动，请确认 App 没有其他验证窗口后重新连接','extension_gate_cancelled');
      }
      if (state.payload?.extension_gate_pending === undefined) {
        throw inlineError('请更新本机 App 以支持页面内验证，或先通过插件面板完成验证后重试');
      }
    }
    throw inlineError('等待验证超时，请重新验证','extension_gate_cancelled');
  } finally {
    if (record.gateRequestId === requestId) record.gateRequestId = null;
    // 只清理本次待验证标记；迟到的清理不能取消新面板的验证或撤销已完成的授权。
    try { await sendNative({action:'extension.cancel',gate_request_id:requestId}); } catch (_) { /* App 也会清理完成的请求。 */ }
  }
}
function acceptInlineAuthorisation(record,state) {
  const payload = state?.payload;
  if (!state?.ok || !payload?.unlocked || !payload.database_attached || !payload.extension_gate_active ||
      (record.authorised && (record.lockGeneration !== payload.vault_lock_generation || record.vaultId !== payload.vault_id))) {
    record.authorised = false;
    throw inlineError('保险库或浏览器授权已改变，请重新验证','extension_gate_required');
  }
  record.authorised = true; record.lockGeneration = payload.vault_lock_generation; record.vaultId = payload.vault_id;
}
async function checkInlineAuthorisation(record) {
  acceptInlineAuthorisation(record,await sendNative({action:'status'}));
}
async function inlineMetadata(record, accountId) {
  await checkInline(record);
  const response = await suggestMetadata({action:'credential.suggest_for_origin',origin:record.origin});
  if (!response?.ok) throw inlineSafeError(response);
  const accounts = metadataPayload(response.payload || {},false).candidates;
  if (accountId !== undefined && accountId !== '' && !accounts.some((row) => row.id === accountId)) {
    throw inlineError('这个账号已不适用于当前网站，请重新选择');
  }
  const key = selectedAccountKey(record.tabId,record.origin);
  const stored = await chrome.storage.session.get(key);
  const remembered = stored[key];
  if (record.accountChosen && record.accountId && !accounts.some((row) => row.id === record.accountId)) {
    throw inlineError('已选账号发生变化，请重新打开候选面板');
  }
  const independent = Object.hasOwn(stored,key) && remembered === '';
  const selected = accountId ?? (record.accountChosen ? record.accountId : independent ? '' :
    accounts.find((row) => row.id === record.accountId)?.id || accounts.find((row) => row.id === remembered)?.id ||
    (accounts.length === 1 ? accounts[0].id : ''));
  if (accountId !== undefined) record.accountChosen = true;
  record.accountChoiceKnown = record.accountChosen || independent || accounts.some((row) => row.id === remembered);
  record.accountId = selected; record.accounts = accounts;
  record.candidates = accounts; record.more = false;
  if (record.mode === 'otp') {
    const mfaKey = `selected_mfa:${record.tabId}:${record.origin}:${selected}`;
    const rememberedMfa = (await chrome.storage.session.get(mfaKey))[mfaKey];
    let mfas = await suggestMetadata({action:'mfa.suggest_for_origin',origin:record.origin,
      credential_id:selected,include_other_matches:record.includeOther === true},true);
    if (!mfas?.ok) throw inlineSafeError(mfas);
    if (rememberedMfa && !record.includeOther && !(mfas.payload?.candidates || []).some((row) => row.id === rememberedMfa)) {
      mfas = await suggestMetadata({action:'mfa.suggest_for_origin',origin:record.origin,
        credential_id:selected,include_other_matches:true},true);
      if (!mfas?.ok) throw inlineSafeError(mfas);
      record.includeOther = true;
    }
    record.candidates = metadataPayload(mfas.payload || {},true).candidates;
    record.more = Boolean(mfas.payload?.can_check_other_matches) && !mfas.payload?.all_matches;
    record.selectedMfa = record.candidates.some((row) => row.id === rememberedMfa) ? rememberedMfa : '';
  }
  await checkInline(record);
  return {ok:true,origin:record.origin,mode:record.mode,accounts,candidates:record.candidates,
    account_id:record.accountId,selected_id:record.mode === 'login' ? record.accountId : record.selectedMfa,more:record.more};
}
async function fillInline(record, id) {
  const binding = {documentId:record.documentId,url:record.url,targetId:record.targetId,
    validate:async () => { await checkInline(record); await checkInlineAuthorisation(record); }};
  await checkInline(record);
  const result = record.mode === 'login'
    ? await runFillLoginOnTab(record.tabId,sendNative,id,binding)
    : await runFillOtpFromVaultOnTab(record.tabId,sendNative,record.accountId,id,binding);
  if (!result?.ok) throw inlineSafeError(result);
  record.completed = true;
  try {
    if (record.mode === 'login') await rememberSelectedAccount(record.tabId,record.origin,id);
    else {
      await rememberSelectedAccount(record.tabId,record.origin,record.accountId || '');
      await chrome.storage.session.set({[`selected_mfa:${record.tabId}:${record.origin}:${record.accountId || ''}`]:id});
    }
  } catch (_) { /* 本次已经填充成功，记忆失败不能重放秘密。 */ }
  return {ok:true,filled:true,partial:result.partial === true,
    message:result.partial ? '仅填入了当前步骤可用的字段。进入下一步后，可继续使用同一账号。' :
      record.mode === 'otp' ? 'MFA 验证码已填充，请在网页确认后继续。' : '账号与密码已填充，请在网页确认后继续。'};
}
async function setInlineHidden(origin, hidden) {
  const stored = await chrome.storage.local.get(INLINE_HIDDEN_SITES);
  const sites = {...(stored[INLINE_HIDDEN_SITES] || {})};
  if (hidden) {
    if (!sites[origin] && Object.keys(sites).length >= 512) throw inlineError('隐藏的网站过多，请先在插件中恢复部分网站');
    sites[origin] = true;
  } else delete sites[origin];
  await chrome.storage.local.set({[INLINE_HIDDEN_SITES]:sites});
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    try {
      if (new URL(tab.url).origin === origin) {
        void chrome.tabs.sendMessage(tab.id,{type:'inline_preference',hidden},{frameId:0}).catch(() => {});
      }
    } catch (_) { /* 跳过浏览器内部页面。 */ }
  }
}
async function handleInlineMessage(message, sender) {
  if (sender.id !== chrome.runtime.id) throw inlineError('来源未授权');
  const fromPopup = !sender.tab && sender.url?.split('#')[0] === chrome.runtime.getURL('popup.html');
  const fromPage = sender.frameId === 0 && sender.tab?.id && sender.documentId && /^https?:\/\//.test(sender.url || '');
  if (message.type === 'inline_resume') {
    // 后台休眠或重启后只恢复面板与当前文档的绑定，不恢复授权，也不重放填充。
    const token = message.token;
    const tabId = sender.tab?.id ?? message.tab_id;
    if (typeof token !== 'string' || !/^[0-9a-f-]{36}$/.test(token) || !sender.documentId ||
        sender.url !== `${inlineUIUrl()}#${token}` || !Number.isInteger(tabId)) throw inlineError('请重新点击网页填充图标');
    if (inlineSessions.has(token)) {
      const record = inlineRecord(token);
      if (record.panelDocumentId !== sender.documentId || record.tabId !== tabId) throw inlineError('候选面板已失效，请重新打开');
      await checkInline(record,true); return {ok:true,origin:record.origin};
    }
    const tab = await chrome.tabs.get(tabId);
    const page = await requestPageContext(tabId);
    if (!tab.active || page?.url !== tab.url || page.panelToken !== token || !page.targetId || !page.targetValid) {
      throw inlineError('网页或输入框已变化，请重新点击填充图标','target_changed');
    }
    const [top] = await chrome.scripting.executeScript({target:{tabId,frameIds:[0]},world:'ISOLATED',func:()=>null});
    if (!top?.documentId || (await chrome.tabs.get(tabId)).url !== tab.url) throw inlineError('网页已跳转，请重新点击填充图标','document_mismatch');
    const current = await requestPageContext(tabId,page.targetId);
    if (current.documentId !== page.documentId || current.panelToken !== token) throw inlineError('页面已变化，请重新点击填充图标','document_mismatch');
    if (inlineSessions.size >= 8) throw inlineError('已有填充操作正在处理，请先关闭其他面板');
    const record = {token,tabId,windowId:tab.windowId,url:tab.url,origin:page.origin,
      chromeDocumentId:top.documentId,documentId:page.documentId,targetId:page.targetId,panelDocumentId:sender.documentId,
      mode:page.targetKind === 'otp' ? 'otp' : 'login',expires:Date.now()+INLINE_TTL_MS,
      busy:false,cancelled:false,completed:false,autoUsed:true,panelReady:true,accountId:'',accounts:[],candidates:[]};
    inlineSessions.set(token,record);
    return {ok:true,origin:record.origin,resumed:true};
  }
  if (['inline_site_state','inline_site_set'].includes(message.type)) {
    if (!fromPopup && (!fromPage || message.type === 'inline_site_set')) throw inlineError('请从插件设置操作');
    const origin = fromPopup ? await originFromSender(sender,message) : new URL(sender.url).origin;
    if (!origin || (fromPopup && message.origin !== origin)) throw inlineError('网站已改变，请重新操作');
    if (message.type === 'inline_site_set') await setInlineHidden(origin,message.hidden === true);
    const stored = await chrome.storage.local.get(INLINE_HIDDEN_SITES);
    return {ok:true,hidden:stored[INLINE_HIDDEN_SITES]?.[origin] === true};
  }
  if (message.type === 'inline_open') {
    if (!fromPage || typeof message.target_id !== 'string' || message.target_id.length > 80) throw inlineError('请点击输入框旁的填充图标');
    const tab = await chrome.tabs.get(sender.tab.id);
    const page = await requestPageContext(tab.id,message.target_id);
    if (!tab.active || tab.url !== sender.url || page?.documentId !== message.document_id ||
        page.url !== tab.url || page.targetId !== message.target_id || !page.targetValid) throw inlineError('目标输入框已改变');
    for (const record of inlineSessions.values()) {
      if (record.tabId === tab.id || Date.now() > record.expires) cancelInline(record);
    }
    if (inlineSessions.size >= 8) throw inlineError('已有填充操作正在处理，请先关闭其他面板');
    const record = {token:uuid(),tabId:tab.id,windowId:tab.windowId,url:tab.url,origin:page.origin,
      chromeDocumentId:sender.documentId,documentId:page.documentId,targetId:page.targetId,
      mode:page.targetKind === 'otp' ? 'otp' : 'login',expires:Date.now()+INLINE_TTL_MS,
      busy:false,cancelled:false,completed:false,autoUsed:false,accountId:'',accounts:[],candidates:[]};
    inlineSessions.set(record.token,record);
    return {ok:true,token:record.token};
  }
  const record = inlineRecord(message.token);
  if (fromPage && message.type === 'inline_cancel' && sender.tab.id === record.tabId &&
      sender.documentId === record.chromeDocumentId && message.document_id === record.documentId) {
    cancelInline(record); return {ok:true};
  }
  // 只接收随扩展发布的候选面板；普通内容脚本没有候选选择和取密权限。
  const tabId = sender.tab?.id ?? message.tab_id;
  if (sender.url !== `${inlineUIUrl()}#${record.token}` || tabId !== record.tabId || !sender.documentId ||
      (record.panelDocumentId && record.panelDocumentId !== sender.documentId)) throw inlineError('候选面板已失效，请重新操作');
  record.panelDocumentId ??= sender.documentId;
  if (message.type === 'inline_cancel') { cancelInline(record); return {ok:true}; }
  if (message.type === 'inline_feedback') {
    await checkInline(record,true);
    await chrome.tabs.sendMessage(record.tabId,{type:'inline_feedback',token:record.token,
      message:typeof message.message === 'string' ? message.message.slice(0,500) : ''},
      {frameId:0,documentId:record.chromeDocumentId});
    return {ok:true};
  }
  if (message.type === 'inline_ping') {
    await checkInline(record,true);
    if (!record.panelReady) {
      record.panelReady = true;
      await chrome.tabs.sendMessage(record.tabId,{type:'inline_ready',token:record.token},
        {frameId:0,documentId:record.chromeDocumentId});
    }
    return {ok:true,origin:record.origin};
  }
  if (record.completed) throw inlineError('本次填充已完成，请继续操作网页');
  if (record.busy) throw inlineError('正在处理，请稍候');
  record.busy = true;
  try {
    if (message.type === 'inline_hide_site') {
      await checkInline(record); await setInlineHidden(record.origin,true);
      cancelInline(record); return {ok:true};
    }
    if (!['inline_load','inline_connect','inline_account','inline_more','inline_fill'].includes(message.type)) throw inlineError('未知操作');
    const automatic = message.type === 'inline_load' && message.automatic === true;
    await authoriseInline(record,message.type === 'inline_connect' || automatic,automatic);
    if (message.type === 'inline_more') record.includeOther = true;
    const previousAccount = record.accountId;
    const metadata = await inlineMetadata(record,message.type === 'inline_account' ? message.credential_id : undefined);
    if (message.type === 'inline_fill') {
      if (record.mode === 'otp' && previousAccount !== record.accountId) throw inlineError('账号候选已改变，请重新读取候选并选择 MFA');
      const id = typeof message.candidate_id === 'string' ? message.candidate_id : '';
      if (!record.candidates.some((row) => row.id === id)) throw inlineError('此记录已不适用于当前网站，请刷新候选');
      return await fillInline(record,id);
    }
    const firstLoad = ['inline_load','inline_connect'].includes(message.type) && !record.autoUsed;
    record.autoUsed = true;
    // 只有一个无歧义候选才一次点击填充；多账号或多 MFA 始终由用户选择。
    if (firstLoad && record.candidates.length === 1 && !record.more &&
        (record.mode === 'login' || record.accounts.length === 0 || record.accountChoiceKnown)) {
      return await fillInline(record,record.candidates[0].id);
    }
    return metadata;
  } finally { record.busy = false; }
}
function installInlineMenus() {
  if (!chrome.contextMenus) return;
  chrome.contextMenus.removeAll(() => {
    if (chrome.runtime.lastError) return;
    const options = {contexts:['editable'],documentUrlPatterns:['https://*/*','http://*/*']};
    const create = (item) => chrome.contextMenus.create({...options,...item},() => { void chrome.runtime.lastError; });
    create({id:'credpivot-fill',title:'CredPivot'});
    create({id:'credpivot-login',parentId:'credpivot-fill',title:'填充账号与密码'});
    create({id:'credpivot-otp',parentId:'credpivot-fill',title:'填充 MFA 验证码'});
    create({id:'credpivot-add-mfa-qr',title:'识别此页面的 MFA 二维码',contexts:['page','image']});
  });
}
async function recordMfaResult(tabId, response) {
  const message = response?.ok ? 'MFA 已保存。网站要求时，请使用验证码完成启用。' : response?.message || '请从插件面板点击「连接与验证」后重新识别。';
  mfaResults.set(tabId, {ok: response?.ok === true, message});
  await chrome.action.setBadgeText({tabId, text: response?.ok ? '✓' : '!'});
  await chrome.action.setTitle({tabId, title: `CredPivot · ${message}`});
}

function requestPageCapturePermission() {
  if (typeof chrome.tabs.captureVisibleTab === "function") return Promise.resolve(true);
  if (!chrome.permissions?.request) return Promise.resolve(false);
  // 必须在右键回调里立刻调用，浏览器才把它当成用户手势并弹出授权。
  return chrome.permissions.request({origins: ["<all_urls>"]}).catch(() => false);
}

async function explainCapturePermission(tabId, granted) {
  const message = granted
    ? "网站访问权限已生效。请重新加载扩展后，再从右键菜单识别二维码。"
    : "未授予网站访问权限，无法截取页面二维码。请在插件面板点击「识别页面二维码」完成授权。";
  await recordMfaResult(tabId, {ok: false, message});
  try { await chrome.tabs.sendMessage(tabId, {type: "page_notice", message}, {frameId: 0}); } catch (_) {}
  await chrome.storage.session.set({mfaPermissionPrompt: message});
  try { await chrome.action.openPopup(); } catch (_) {}
}

chrome.contextMenus?.onClicked.addListener((info,tab) => {
  if (info.menuItemId === 'credpivot-add-mfa-qr' && tab?.id) {
    const tabId = tab.id;
    const asking = requestPageCapturePermission();
    void (async () => {
      const granted = await asking;
      if (typeof chrome.tabs.captureVisibleTab !== "function") {
        await explainCapturePermission(tabId, granted === true);
        return;
      }
      await chrome.action.setBadgeText({tabId, text: 'MFA'});
      const response = await addMfa(tabId, null, sendNative, requestBrowserVerification, clearMetadataCache);
      if (response?.code === 'mfa_pending') return;
      await recordMfaResult(tabId, response);
    })().catch(() => {});
    return;
  }
  if (!['credpivot-login','credpivot-otp'].includes(info.menuItemId) || info.frameId !== 0 || !tab?.id) return;
  (async () => {
    await requestPageContext(tab.id);
    const page = await chrome.tabs.sendMessage(tab.id,
      {type:'inline_menu_context',mode:info.menuItemId === 'credpivot-otp' ? 'otp' : 'login'},{frameId:0});
    if (!page?.menuTarget) return;
    await chrome.tabs.sendMessage(tab.id,
      {type:'inline_show',document_id:page.documentId,target_id:page.menuTarget},{frameId:0});
  })().catch(() => {});
});
chrome.tabs.onUpdated?.addListener((tabId,change) => {
  if (change.url) void cancelMfaIfOriginChanged(tabId, change.url, sendNative).catch(() => {});
  if (!change.url && change.status !== 'loading') return;
  for (const record of inlineSessions.values()) if (record.tabId === tabId) cancelInline(record);
});
chrome.tabs.onActivated?.addListener(({tabId,windowId}) => {
  for (const record of inlineSessions.values()) if (record.windowId === windowId && record.tabId !== tabId) cancelInline(record);
  void refreshInlinePage(tabId);
});
chrome.windows?.onFocusChanged?.addListener((windowId) => {
  if (windowId < 0) return; // 系统指纹弹窗不属于 Chrome 窗口，不能因此取消合法验证。
  for (const record of inlineSessions.values()) if (record.windowId !== windowId) cancelInline(record);
});
installInlineMenus();
async function refreshInlinePage(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (/^https?:\/\//.test(tab?.url || '')) await requestPageContext(tabId);
  } catch (_) { /* 浏览器限制页面保持原状，不发起任何验证。 */ }
}
// 更新插件后给已打开的活动页补装入口，其他标签页在激活时按需恢复。
if (chrome.tabs.query) void chrome.tabs.query({active:true,currentWindow:true})
  .then((tabs) => { if (tabs[0]?.id) return refreshInlinePage(tabs[0].id); }).catch(() => {});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (typeof msg?.type === 'string' && msg.type.startsWith('inline_')) {
        try { sendResponse(await handleInlineMessage(msg,sender)); }
        catch (error) { sendResponse({ok:false,code:error.code,message:error.message || '操作未完成，请重试'}); }
        return;
      }
      if (sender.id === chrome.runtime.id && sender.tab && ["passkey_request","passkey_cancel"].includes(msg?.type)) {
        if (msg.type === "passkey_cancel") { cancelPasskey(msg,sender); sendResponse({ok:true}); }
        else sendResponse(await handlePasskey(msg,sender,sendNative,() => nativeGateGeneration));
        return;
      }
      // 只有扩展自己的界面能发起操作；网页及内容脚本不能自行保存或领取秘密。
      if (sender.id !== chrome.runtime.id || sender.tab || sender.url?.split("#")[0] !== chrome.runtime.getURL("popup.html")) {
        sendResponse({ok:false,code:"forbidden",message:"请从扩展面板操作"}); return;
      }
      if (msg.type === "add_mfa_qr") {
        const tabId = msg.tab_id;
        const pageScan = msg.image == null;
        // 页面框选会关掉面板。先应答，结果留给角标和下次打开面板。
        if (pageScan) sendResponse({ok: true, pending: true});
        if (pageScan) await chrome.action.setBadgeText({tabId, text: 'MFA'}).catch(() => {});
        const response = await addMfa(tabId, msg.image ?? null, sendNative, requestBrowserVerification, clearMetadataCache);
        // 重复发起不覆盖进行中的角标；上传图片的结果已在面板显示，不再留给下次打开。
        if (pageScan && response?.code !== 'mfa_pending') await recordMfaResult(tabId, response).catch(() => {});
        if (!pageScan) sendResponse(response);
        return;
      }
      if (msg.type === "cancel_mfa_qr") {
        sendResponse(await cancelMfa(msg.tab_id, sendNative));
        return;
      }
      if (msg.type === "mfa_result") {
        sendResponse({ok:true,result:mfaResults.get(msg.tab_id) ?? null});
        mfaResults.delete(msg.tab_id);
        void chrome.action.setBadgeText({tabId:msg.tab_id,text:''}).catch(() => {});
        return;
      }
      if (msg.type === "handshake") {
        if (typeof msg.gate_request_id !== 'string' || !/^[0-9a-f-]{36}$/.test(msg.gate_request_id)) {
          sendResponse({ok:false,code:'invalid_request',message:'请重新打开插件后验证'}); return;
        }
        const resp = await requestBrowserVerification(msg.gate_request_id,msg.automatic === true);
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
      if (msg.type === 'cancel_verification') {
        if (typeof msg.gate_request_id !== 'string' || !/^[0-9a-f-]{36}$/.test(msg.gate_request_id)) {
          sendResponse({ok:false,code:'invalid_request'}); return;
        }
        // 取消可能先于异步状态检查返回；记住请求标识，禁止随后才发起系统验证。
        cancelledVerifications.add(msg.gate_request_id);
        while (cancelledVerifications.size > 64) cancelledVerifications.delete(cancelledVerifications.values().next().value);
        if (msg.explicit === true) await chrome.storage.session.set({[AUTO_VERIFICATION_BLOCKED]:true});
        sendResponse(await sendNative({action:'extension.cancel',gate_request_id:msg.gate_request_id}));
        return;
      }
      if (msg.type === "agent_status") {
        const resp = await sendNative({ action: "status" });
        sendResponse(resp);
        return;
      }
      if (msg.type === "passkey_site_state" || msg.type === "passkey_site_set") {
        const origin = await originFromSender(sender,msg);
        if (!origin?.startsWith("https://") || origin !== msg.origin) { sendResponse({ok:false,message:"网站已改变，或当前页面不是 HTTPS 网站"}); return; }
        if (msg.type === "passkey_site_set") await setPasskeySiteState(origin,msg.enabled === true);
        sendResponse({ok:true,enabled:await passkeySiteState(origin)});
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
      if (msg.type === "suggest_mfas" || msg.type === "select_mfa") {
        const origin = await originFromSender(sender, msg);
        if (!origin) { sendResponse({ok:false,message:"无法确定页面来源"}); return; }
        const credentialId = typeof msg.credential_id === "string" ? msg.credential_id : "";
        const key = `selected_mfa:${msg.tab_id}:${origin}:${credentialId}`;
        const stored = await chrome.storage.session.get(key);
        const remembered = stored[key];
        const request = {action:"mfa.suggest_for_origin",origin,credential_id:credentialId,
          include_other_matches: msg.type === "select_mfa" || msg.include_other_matches === true};
        let resp = await suggestMetadata(request, true);
        // 用户曾手动选过次级/独立匹配时，重新检查全部规则后再恢复选择。
        if (resp?.ok && remembered && !request.include_other_matches &&
            !(resp.payload?.candidates ?? []).some((row) => row.id === remembered)) {
          resp = await suggestMetadata({...request, include_other_matches:true}, true);
        }
        if (resp?.ok) {
          const candidates = resp.payload?.candidates ?? [];
          if (msg.type === "select_mfa") {
            if (!candidates.some((row) => row.id === msg.totp_id)) { sendResponse({ok:false,message:"MFA 已不适用于当前网站"}); return; }
            await chrome.storage.session.set({[key]:msg.totp_id});
          } else {
            const valid = candidates.some((row) => row.id === remembered);
            resp.payload = {...resp.payload,selected_totp_id:valid ? remembered : null};
            if (remembered && !valid) await chrome.storage.session.remove(key);
          }
        }
        sendResponse(resp); return;
      }
      if (msg.type === "suggest_credentials") {
        const origin = await originFromSender(sender, msg);
        if (!origin) {
          sendResponse({ ok: false, code: "bad_origin", message: "无法确定页面 origin" });
          return;
        }
        const resp = await suggestMetadata({action: "credential.suggest_for_origin", origin});
        if (resp?.ok) {
          const key = selectedAccountKey(msg.tab_id, origin);
          const stored = await chrome.storage.session.get(key);
          const selected = stored[key];
          const valid = (resp.payload?.candidates ?? []).some((row) => row.id === selected);
          const independent = Object.hasOwn(stored,key) && selected === '';
          resp.payload = { ...resp.payload, selected_credential_id: valid || independent ? selected : null,
            account_selection_set: valid || independent };
          if (selected && !valid) await chrome.storage.session.remove(key);
        }
        sendResponse(resp);
        return;
      }
      if (msg.type === "list_partitions") {
        sendResponse(await sendNative({action: "partitions.list"}));
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
          display_name: msg.display_name ?? "", partition_id: msg.partition_id ?? "",
        });
        if (resp?.ok) await clearMetadataCache();
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
        const result = await runFillOtpFromVaultOnTab(tabId, sendNative, msg.credential_id, msg.totp_id);
        if (result.ok) {
          try {
            await rememberSelectedAccount(tabId, result.origin, result.credential_id || "");
            await chrome.storage.session.set({[`selected_mfa:${tabId}:${result.origin}:${result.credential_id || ""}`]:result.totp_id});
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
        hint: "请确认正在运行所需版本的 App，在浏览器设置中更新 Native Host，然后点击插件「连接与验证」重试",
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
  closeNativePort(nativePort, connectionError("本机连接空闲，已释放"));
}, 60_000);
