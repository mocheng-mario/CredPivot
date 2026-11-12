import { requestPageContext } from "./fill_flow.js";

const $ = (id) => document.getElementById(id);
const accountEl = $("account");
let targetTab = null;
let targetOrigin = null;
let candidates = [];
let selectedId = "";
let mfaCandidates = [];
let selectedTotpId = "";
let mfaGeneration = 0;
let hasMoreMfas = false;
let allMfaMatches = false;
let selectionSource = "";
let captured = null;
let ready = false;
let busy = false;
let stopWaiting = false;
let gateRequestId = null;
let passkeyEnabled = false;
let inlineHidden = false;

$("ver").textContent = `v${chrome.runtime.getManifest().version}`;

function selectedAccount() {
  return candidates.find((row) => row.id === selectedId);
}

function setStatus(message, state = "idle") {
  $("status").textContent = message;
  $("status").dataset.state = state;
  $("errorDetails").hidden = true;
  $("errorDetails").open = false;
  $("errorDetail").textContent = "";
}

function showError(result) {
  const code = result?.code ?? result?.raw?.code;
  const reason = result?.deliver?.reason || result?.error;
  const messages = {
    extension_gate_required: "请点击「连接与验证」，完成指纹或 App 内的主密码验证。",
    extension_gate_cancelled: "验证已取消。需要继续时，请点击「连接与验证」。",
    extension_gate_paused: "自动验证已暂停，请点击「连接与验证」手动继续。",
    locked: "保险库已锁定，请点击「连接与验证」解锁。",
    browser_parent_denied: "浏览器身份验证未通过，请确认使用正式 Google Chrome 或 Canary；可在 App 诊断中查看失败分类。",
    host_outdated: "本机组件已更新，请重新连接；保存、更新等操作不会自动重复。",
    agent_timeout: "App 响应超时，请检查 App 后重试；刚才的写入操作不会自动重复。",
    agent_unavailable: "App 连接已中断，请点击「连接与验证」重试。",
    peer_denied: "本机连接尚未授权，请在 App 的浏览器设置中检查 Native Host 配置。",
    no_login_fields: "当前页面未找到账号或密码输入框，请进入登录页面后重试。",
    no_otp_field: "当前页面未找到验证码输入框，请进入 MFA 验证页面后重试。",
    document_mismatch: "页面已跳转，请在新页面重新填充。",
    origin_mismatch: "网站已发生变化，请重新打开插件面板。",
    "partitions.errors.notFound": "所选分区不存在，请重新读取表单后再保存。",
  };
  const gated = result?.needs_gate || ['extension_gate_required','extension_gate_cancelled','extension_gate_not_started','extension_gate_paused','locked'].includes(code);
  if (gated || result?.lastNativeError) {
    ready = false;
    candidates = [];
    selectedId = "";
    mfaCandidates = []; selectedTotpId = ""; hasMoreMfas = false; allMfaMatches = false; mfaGeneration++;
    renderMfas();
    clearCapturedForm();
    renderAccounts();
    $("connectionState").textContent = gated ? "需要验证" : "连接中断";
    $("connectionState").dataset.state = "warning";
    $("connect").textContent = "连接与验证";
  }
  const message = messages[code] || messages[result?.message] || messages[reason] || result?.message || result?.error || "操作未完成，请重试。";
  setStatus(message, "error");
  // 只提供排障字段，不展示包含凭据或验证码的原始响应。
  const details = [code, result?.detail, result?.lastNativeError].filter(Boolean).join("\n");
  $("errorDetail").textContent = details;
  $("errorDetails").hidden = !details;
}

function updateControls() {
  const row = selectedAccount();
  accountEl.title = row?.username || "选择登录账号";
  $("connect").disabled = busy;
  accountEl.disabled = busy || !ready || !candidates.length;
  $("accountSearch").disabled = busy || !ready;
  $("fillLogin").disabled = busy || !ready || !row;
  $("fillOtp").disabled = busy || !ready || !mfaCandidates.some((m) => m.id === selectedTotpId);
  $("otp").disabled = busy || !ready || !mfaCandidates.length || (mfaCandidates.length === 1 && Boolean(selectedTotpId));
  $("otherMfas").disabled = busy || !ready;
  $("scanMfa").disabled = busy || !ready || !targetOrigin;
  $("uploadMfa").disabled = busy || !ready || !targetOrigin;
  $("cancelMfa").disabled = !targetOrigin;
  $("passkeyToggle").disabled = busy || !targetOrigin?.startsWith("https://");
  $("otherMfas").hidden = !ready || !hasMoreMfas || allMfaMatches;
  $("capture").disabled = busy || !ready || !targetOrigin;
  const partitionReady = Boolean($("savePartition").value);
  $("saveUsername").disabled = busy || !captured;
  $("saveDisplayName").disabled = busy || !captured;
  $("savePartition").disabled = busy || !captured || !$("savePartition").options.length;
  $("saveNew").disabled = busy || !ready || !captured || !partitionReady;
  $("update").disabled = busy || !ready || !row || !captured;
  if (captured) {
    $("saveTarget").textContent = row
      ? `更新将写入「${row.partition_name || "当前分区"}」的 ${row.display_name || row.username || "所选账号"}，不修改名称和分区。`
      : "未选择已有账号，只能保存为新账号。";
  }
  $("fillLoginHint").textContent = row ? `使用 ${row.username || "无用户名账号"}` : "先选择登录账号";
  const mfa = mfaCandidates.find((m) => m.id === selectedTotpId);
  $("fillOtpHint").textContent = mfa ? `${mfa.issuer || "MFA"} · ${mfa.account || "无账号标签"}` : "选择当前网站的 MFA";
  const linkedCount = mfaCandidates.filter((m) => m.linked).length;
  $("mfa").hidden = !row;
  $("mfa").textContent = linkedCount ? `${linkedCount} 个可用 MFA` : "无网站 MFA 关联";
  $("mfa").dataset.available = String(linkedCount > 0);
  $("selectionNote").textContent = !row ? "没有登录记录也可在下方选择独立 MFA。" : selectionSource === "remembered" ? "已恢复此标签页使用的账号，MFA 按当前网站匹配。" : "切换账号会重新匹配适用的 MFA。";
  document.body.setAttribute("aria-busy", String(busy));
}

function setBusy(value) {
  busy = value;
  updateControls();
}

function clearCapturedForm() {
  captured = null;
  $("saveForm").hidden = true;
  $("captureInfo").textContent = "";
  $("saveOrigin").textContent = "";
  $("saveUsername").value = "";
  $("saveDisplayName").value = "";
  $("savePartition").replaceChildren();
  $("saveTarget").textContent = "";
  updateControls();
}

function showCapturedForm(value, partitions) {
  let host = value.origin;
  try { host = new URL(value.origin).host; } catch { /* 保留 origin。 */ }
  $("saveOrigin").textContent = value.origin;
  $("saveOrigin").title = value.origin;
  $("captureInfo").textContent = "密码已读取，不在面板中显示";
  $("saveUsername").value = value.username || "";
  $("saveDisplayName").value = host;
  const select = $("savePartition");
  select.replaceChildren();
  for (const row of partitions?.partitions ?? []) {
    if (!row?.id) continue;
    const option = document.createElement("option");
    option.value = row.id;
    option.textContent = row.name || row.id;
    select.append(option);
  }
  const preferred = partitions?.default_partition_id;
  if ([...select.options].some((option) => option.value === preferred)) select.value = preferred;
  $("saveForm").hidden = false;
  updateControls();
}

function renderAccounts() {
  const query = $("accountSearch").value.trim().toLowerCase();
  const matches = candidates.filter((row) => (row.username || "").toLowerCase().includes(query));
  accountEl.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = !ready ? "连接后加载账号" : "不关联登录账号，选择独立 MFA";
  placeholder.disabled = !ready;
  accountEl.append(placeholder);
  // 搜索只过滤列表，不清空已选账号，避免后续 MFA 填充丢失选择。
  const rows = [...matches];
  const selected = selectedAccount();
  if (selected && !rows.some((row) => row.id === selectedId)) rows.unshift(selected);
  for (const row of rows) {
    const option = document.createElement("option");
    option.value = row.id;
    const filtered = !matches.includes(row) ? " · 当前已选" : "";
    option.textContent = `${row.partition_name ? `[${row.partition_name}] ` : ""}${row.username || "（无用户名）"}${filtered}`;
    accountEl.append(option);
  }
  accountEl.value = selected ? selectedId : "";
  $("accountCount").textContent = query ? `${matches.length} / ${candidates.length} 个账号` : `${candidates.length} 个账号`;
  $("searchField").hidden = candidates.length < 2;
  updateControls();
}

function renderMfas() {
  const select = $("otp");
  select.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = !ready ? "连接后加载 MFA" : mfaCandidates.length ? "请选择 MFA" : "此网站暂无可用 MFA";
  placeholder.disabled = true;
  select.append(placeholder);
  for (const linked of [true, false]) {
    const rows = mfaCandidates.filter((m) => Boolean(m.linked) === linked);
    if (!rows.length) continue;
    const group = document.createElement("optgroup");
    group.label = linked ? "当前账号关联" : "独立匹配网站";
    for (const row of rows) {
      const option = document.createElement("option"); option.value = row.id;
      option.textContent = `${row.partition_name ? `[${row.partition_name}] ` : ""}${row.issuer || "MFA"} · ${row.account || "无账号标签"}（${["精确来源", "通配符", "正则"][row.match_rank] || "网站匹配"}）`;
      group.append(option);
    }
    select.append(group);
  }
  select.value = selectedTotpId;
  $("otpCount").textContent = `${mfaCandidates.length} 个 MFA`;
  $("otpNote").textContent = selectedTotpId ? "仅在点击填充后读取验证码，不会自动提交。" : mfaCandidates.length > 1 ? "有多个匹配项，请选择本次登录所需的 MFA。" : "请在 App 中配置 MFA 的适用网站；账号关联不会覆盖网站限制。";
  updateControls();
}

async function refreshMfas(includeOtherMatches = false) {
  const version = ++mfaGeneration;
  const credentialId = selectedId;
  const tab = await getTargetTab();
  const previous = selectedTotpId;
  mfaCandidates = []; selectedTotpId = ""; hasMoreMfas = false; allMfaMatches = false; renderMfas();
  const response = await chrome.runtime.sendMessage({type:"suggest_mfas",tab_id:tab.id,credential_id:credentialId,include_other_matches:includeOtherMatches});
  if (version !== mfaGeneration || selectedId !== credentialId) return false;
  await getTargetTab();
  if (!response?.ok) { showError(response); return false; }
  mfaCandidates = response.payload?.candidates ?? [];
  hasMoreMfas = Boolean(response.payload?.can_check_other_matches);
  allMfaMatches = Boolean(response.payload?.all_matches);
  const remembered = response.payload?.selected_totp_id;
  const linked = mfaCandidates.filter((m) => m.linked);
  selectedTotpId = mfaCandidates.find((m) => m.id === previous)?.id || mfaCandidates.find((m) => m.id === remembered)?.id ||
    (linked.length === 1 ? linked[0].id : !credentialId && mfaCandidates.length === 1 ? mfaCandidates[0].id : "");
  renderMfas(); return true;
}

async function getTargetTab() {
  if (!targetTab?.id || !targetOrigin) throw new Error("请在普通 http(s) 网页中打开插件。");
  const tab = await chrome.tabs.get(targetTab.id);
  if (!/^https?:\/\//.test(tab?.url ?? "") || new URL(tab.url).origin !== targetOrigin) {
    throw new Error("网站已发生变化，请重新打开插件面板。");
  }
  return tab;
}

async function refreshAccounts() {
  const tab = await getTargetTab();
  const response = await chrome.runtime.sendMessage({ type: "suggest_credentials", tab_id: tab.id });
  if (!response?.ok) { ready = false; showError(response); return false; }
  await getTargetTab();
  candidates = response.payload?.candidates ?? [];
  const previous = candidates.find((row) => row.id === selectedId);
  const remembered = candidates.find((row) => row.id === response.payload?.selected_credential_id);
  const independent = (selectionSource === "manual" && selectedId === "") ||
    (response.payload?.account_selection_set === true && response.payload?.selected_credential_id === "");
  selectedId = independent ? "" : previous?.id || remembered?.id || (candidates.length === 1 ? candidates[0].id : "");
  selectionSource = !previous && remembered ? "remembered" : selectionSource;
  renderAccounts();
  return await refreshMfas();
}

async function handshake(verify = false) {
  if (busy) return;
  stopWaiting = false;
  ready = false;
  candidates = [];
  mfaCandidates = []; selectedTotpId = ""; hasMoreMfas = false; allMfaMatches = false; mfaGeneration++; renderMfas();
  clearCapturedForm();
  renderAccounts();
  setBusy(true);
  $("connectionState").textContent = "连接中…";
  $("connectionState").dataset.state = "pending";
  setStatus("正在连接本机保险库…", "pending");
  const requestId = verify ? crypto.randomUUID() : null;
  gateRequestId = requestId;
  $("stopWaiting").hidden = !verify;
  try {
    await getTargetTab();
    if (stopWaiting) { showError({code:'extension_gate_cancelled'}); return; }
    // 首次打开可自动验证一次；取消后的自动抑制由后台统一管理，手动点击始终可重试。
    let response = await chrome.runtime.sendMessage(verify
      ? {type:"handshake",gate_request_id:requestId,automatic:verify === 'automatic'} : {type:"agent_status"});
    if (stopWaiting) { showError({code:'extension_gate_cancelled'}); return; }
    if (!response?.ok && response?.code === "extension_gate_required") {
      setStatus("请完成系统指纹验证；如需主密码，请在 App 中输入。完成后会自动继续。", "pending");
      $("stopWaiting").hidden = false;
      for (let i = 0; i < 120; i++) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        if (stopWaiting) {
          showError({code:'extension_gate_cancelled'});
          return;
        }
        const state = await chrome.runtime.sendMessage({ type: "agent_status" });
        if (stopWaiting) { showError({code:'extension_gate_cancelled'}); return; }
        if (!state?.ok) { showError(state); return; }
        if (state?.payload?.extension_gate_active === true) { response = { ok: true, payload: state.payload }; break; }
        if (state.payload?.extension_gate_pending !== true ||
            (state.payload?.extension_gate_request_id && state.payload.extension_gate_request_id !== requestId)) {
          showError({code:'extension_gate_not_started',message:'验证已取消或未能启动。请确认 App 没有其他验证窗口，再点击「连接与验证」。'}); return;
        }
      }
    }
    if (!response?.ok) { showError(response); return; }
    let payload = response.payload ?? {};
    // 同协议的旧 App 握手尚不包含完整状态；新 App 则省去这次重复查询。
    if (!Object.hasOwn(payload, "database_attached")) {
      const state = await chrome.runtime.sendMessage({type: "agent_status"});
      if (!state?.ok) { showError(state); return; }
      payload = {...payload, ...state.payload};
    }
    const extensionVersion = chrome.runtime.getManifest().version;
    $('componentVersions').textContent = `插件 ${extensionVersion} · Agent ${payload.agent_version || '未知'} · Native Host ${payload.native_host_version || '未知'} · 协议 ${payload.protocol_version || '未知'} · Schema ${payload.schema_user_version || '未知'}`;
    $('componentUpdate').textContent = payload.expected_extension_version && extensionVersion !== payload.expected_extension_version
      ? `App 配套插件为 ${payload.expected_extension_version}。请在 App 打开插件目录，在扩展管理页重新加载，再重新连接。`
      : '更新 App 后请重新加载配套插件；本机组件不一致时，在 App 更新 Native Host，再重新连接。';
    if (!payload.unlocked || !payload.database_attached || !payload.extension_gate_active) {
      showError({ code: !payload.unlocked ? "locked" : !payload.database_attached ? "database_unavailable" : "extension_gate_required", message: "保险库未就绪，请在 App 中重新解锁后连接。" });
      return;
    }
    ready = true;
    if (!await refreshAccounts()) return;
    $("connectionState").textContent = "已连接 · 已验证";
    $("connectionState").dataset.state = "success";
    $("connect").textContent = "刷新连接";
    setStatus(!candidates.length ? (mfaCandidates.length ? "此网站有独立 MFA，可直接选择并填充验证码。" : "此网站暂无账号或 MFA，请在 App 中配置匹配网站。") : selectedAccount() ? "账号已就绪，选择下方按钮填充。" : "此网站有多个账号，请先选择要使用的账号。");
  } catch (e) {
    ready = false;
    candidates = [];
    renderAccounts();
    showError({ error: e.message });
  } finally {
    if (requestId) {
      try { await chrome.runtime.sendMessage({type:'cancel_verification',gate_request_id:requestId}); } catch (_) { /* 本机断开时不重发验证。 */ }
    }
    if (gateRequestId === requestId) gateRequestId = null;
    $("stopWaiting").hidden = true;
    if (!ready) {
      $("connectionState").textContent = "尚未连接";
      $("connectionState").dataset.state = "warning";
      $("connect").textContent = "连接与验证";
    }
    setBusy(false);
  }
}

$("accountSearch").addEventListener("input", renderAccounts);
accountEl.addEventListener("change", async () => {
  selectedId = accountEl.value;
  selectedTotpId = ""; mfaCandidates = []; renderMfas();
  selectionSource = "manual";
  setStatus(selectedId ? "已切换账号，密码和 MFA 将使用当前选择。" : "已切换为独立 MFA，按当前网站匹配各分区的验证器。");
  setBusy(true);
  try {
    const tab = await getTargetTab();
    const response = await chrome.runtime.sendMessage({ type: "select_account", tab_id: tab.id, origin: targetOrigin, credential_id: selectedId });
    if (!response?.ok) showError(response);
    else await refreshMfas();
  } catch (e) { showError({ error: e.message }); }
  finally { setBusy(false); }
});

$("otherMfas").addEventListener("click", async () => {
  if (busy || !ready) return;
  setBusy(true);
  try {
    if (await refreshMfas(true)) setStatus("已列出当前网站的全部匹配 MFA，包括其他匹配层级和未关联的验证器。");
  } catch (e) { showError({error:e.message}); }
  finally { setBusy(false); }
});

$("otp").addEventListener("change", async () => {
  selectedTotpId = $("otp").value; setBusy(true);
  try {
    const tab = await getTargetTab();
    const response = await chrome.runtime.sendMessage({type:"select_mfa",tab_id:tab.id,credential_id:selectedId,totp_id:selectedTotpId});
    if (!response?.ok) { selectedTotpId = ""; renderMfas(); showError(response); }
    else setStatus("已选择 MFA，可直接填充验证码。");
  } catch (e) { selectedTotpId = ""; renderMfas(); showError({error:e.message}); }
  finally { setBusy(false); }
});

async function fill(mode) {
  const account = selectedAccount();
  if (busy || !ready || (mode === "login" ? !account : !selectedTotpId)) return;
  setBusy(true);
  setStatus(mode === "otp" ? "正在获取并填充 MFA；验证码即将过期时会等待下一组…" : "正在填充账号与密码…", "pending");
  try {
    const tab = await getTargetTab();
    const result = await chrome.runtime.sendMessage({ type: mode === "otp" ? "fill_otp_vault_tab" : "fill_login_tab", tab_id: tab.id, credential_id: account?.id || "", totp_id: mode === "otp" ? selectedTotpId : undefined });
    if (!result?.ok) { showError(result); return; }
    selectionSource = "remembered";
    if (mode === "login" && result.partial) {
      const field = result.password_filled ? "密码" : "用户名";
      setStatus(`仅填充了${field}，另一个字段未找到或不可填写。如果是分步登录，请进入下一步后再次填充。`, "warning");
      return;
    }
    const next = mode === "login" && mfaCandidates.length > 0 ? "进入验证码页面后，可直接填充 MFA。" : "请在网页确认后继续。";
    setStatus(result.selection_remembered === false ? "填充成功，但未能记住选择，下次打开时请重新选择。" : `${mode === "otp" ? "MFA 验证码" : "账号与密码"}已填充。${next}`, result.selection_remembered === false ? "warning" : "success");
  } catch (e) { showError({ error: e.message }); }
  finally { setBusy(false); }
}

$("fillLogin").addEventListener("click", () => fill("login"));
$("fillOtp").addEventListener("click", () => fill("otp"));
$("connect").addEventListener("click", () => void handshake(true));
$("stopWaiting").addEventListener("click", () => {
  stopWaiting = true;
  if (gateRequestId) void chrome.runtime.sendMessage({type:'cancel_verification',gate_request_id:gateRequestId,explicit:true}).catch(() => {});
  $("stopWaiting").hidden = true;
  setStatus("正在停止等待…", "pending");
});

$("capture").addEventListener("click", async () => {
  if (busy || !ready) return;
  clearCapturedForm();
  setBusy(true);
  setStatus("正在读取当前登录表单…", "pending");
  try {
    const tab = await getTargetTab();
    const page = await requestPageContext(tab.id);
    if (!page?.documentId || page.origin !== targetOrigin) throw new Error("页面已改变，请重新读取表单。");
    const value = await chrome.tabs.sendMessage(tab.id, { type: "capture_login" }, { frameId: 0 });
    if (!value?.password || value.documentId !== page.documentId || value.origin !== page.origin) throw new Error("未找到已填写的密码，或页面已改变。");
    captured = { ...value, tabId: tab.id };
    const listed = await chrome.runtime.sendMessage({type: "list_partitions"});
    if (!listed?.ok && (listed?.needs_gate || ["extension_gate_required", "locked"].includes(listed?.code))) {
      showError(listed);
      return;
    }
    showCapturedForm(value, listed?.ok ? listed.payload : null);
    setStatus(listed?.ok ? "表单已读取。填写名称和分区后可保存为新账号，或更新当前所选账号。" : (listed?.message || "表单已读取，但分区列表加载失败，暂时不能保存为新账号。"), listed?.ok ? "idle" : "warning");
  } catch (e) { showError({ error: e.message }); }
  finally { setBusy(false); }
});

async function saveCaptured(update) {
  if (busy || !ready || !captured) return;
  const account = selectedAccount();
  if (update && !account) return;
  const value = captured;
  const typedName = $("saveUsername").value.trim();
  // 改密页面可能没有用户名输入框，不能因此清空已选账号的名称。
  const username = update ? typedName || account.username : typedName;
  const displayName = update ? "" : $("saveDisplayName").value.trim();
  const partitionId = update ? "" : $("savePartition").value;
  if (!update && ([...displayName].length > 200 || [...displayName].some((ch) => ch.charCodeAt(0) < 32))) {
    setStatus("名称过长或包含无法保存的字符。", "error");
    return;
  }
  if (!update && !partitionId) { setStatus("请选择分区。", "error"); return; }
  setBusy(true);
  setStatus("正在保存…", "pending");
  try {
    await getTargetTab();
    const response = await chrome.runtime.sendMessage({ type: update ? "update_credential" : "save_credential", tab_id: value.tabId, document_id: value.documentId, username, password: value.password, credential_id: account?.id, expected_revision: account?.current_revision, display_name: displayName, partition_id: partitionId });
    if (!response?.ok) { showError(response); return; }
    const saved = response.payload?.credential;
    const ignored = !update && (saved?.partition_id !== partitionId || (saved?.display_name ?? "") !== displayName);
    if (await refreshAccounts()) {
      setStatus(ignored ? "账号已保存，但当前本机组件没有按所选分区或名称写入。请更新 App 中的 Native Host 后重新连接。" : update ? "所选账号已更新。" : "新账号已保存。", ignored ? "warning" : "success");
    }
  } catch (e) { showError({ error: e.message }); }
  finally { clearCapturedForm(); setBusy(false); }
}

$("saveNew").addEventListener("click", () => saveCaptured(false));
$("update").addEventListener("click", () => saveCaptured(true));

async function refreshPasskeyState() {
  if (!targetOrigin?.startsWith("https://")) {
    $("passkeyState").textContent = "需要 HTTPS";
    return;
  }
  const response = await chrome.runtime.sendMessage({type:"passkey_site_state",tab_id:targetTab.id,origin:targetOrigin});
  if (!response?.ok) return;
  passkeyEnabled = response.enabled === true;
  $("passkeyState").textContent = passkeyEnabled ? "此网站已启用" : "未启用";
  $("passkeyToggle").textContent = passkeyEnabled ? "在此网站停用" : "在此网站启用";
}

async function startPageScan() {
  if (busy || !ready) return;
  try {
    const tab = await getTargetTab();
    const response = await chrome.runtime.sendMessage({type: "add_mfa_qr", tab_id: tab.id});
    if (!response?.pending) { showError(response || {error: "请重新打开插件后识别"}); return; }
    // 面板挡住页面时无法框选，应答后立即关闭，把焦点还给网页。
    window.close();
  } catch (error) { showError({error: error.message}); }
}

async function addMfaImage(image = null) {
  if (busy || !ready) return;
  setBusy(true);
  setStatus("请在 CredPivot App 中确认识别结果，并选择是否关联当前网站的账密。", "pending");
  try {
    const tab = await getTargetTab();
    const response = await chrome.runtime.sendMessage({type: "add_mfa_qr", tab_id: tab.id, image});
    if (!response?.ok) { showError(response); return; }
    await refreshMfas();
    setStatus("MFA 已保存。网站要求时，请使用生成的验证码完成网站上的启用步骤。", "success");
  } catch (error) { showError({error: error.message}); }
  finally { setBusy(false); }
}

async function addMfaFile(file) {
  if (!file || busy || !ready) return;
  if (!["image/png", "image/jpeg"].includes(file.type) || file.size > 1500 * 1024) {
    setStatus("请选择不超过 1.5 MB 的 PNG 或 JPEG 图片。", "error"); return;
  }
  const reader = new FileReader();
  reader.onload = () => { void addMfaImage(reader.result); };
  reader.onerror = () => setStatus("二维码图片读取失败，请重试。", "error");
  reader.readAsDataURL(file);
}

$("scanMfa").addEventListener("click", () => {
  if (busy || !ready) return;
  // 必须在点击当次调用，Firefox 才把这次操作视为用户手势。
  const missing = typeof chrome.tabs.captureVisibleTab !== "function";
  const asking = missing && chrome.permissions?.request
    ? chrome.permissions.request({origins: ["<all_urls>"]}).catch(() => false)
    : Promise.resolve(true);
  void (async () => {
    try {
      const granted = await asking;
      if (typeof chrome.tabs.captureVisibleTab !== "function") {
        if (!granted) throw new Error("未授予网站访问权限，无法截取页面二维码。请在扩展管理中允许访问所有网站，然后重新加载扩展。");
        setStatus("网站访问权限已生效。扩展即将重载，请再次点击「识别页面二维码」。", "pending");
        chrome.runtime.reload();
        return;
      }
      await startPageScan();
    } catch (error) { showError({error: error.message}); }
  })();
});
$("uploadMfa").addEventListener("click", () => $("mfaImage").click());
$("mfaImage").addEventListener("change", (event) => {
  void addMfaFile(event.target.files?.[0]); event.target.value = "";
});
$("cancelMfa").addEventListener("click", async () => {
  try {
    const tab = await getTargetTab();
    await chrome.runtime.sendMessage({type: "cancel_mfa_qr", tab_id: tab.id});
    setStatus("已取消待处理的 MFA 添加。");
  } catch (error) { showError({error: error.message}); }
});
document.addEventListener("paste", (event) => {
  const image = [...(event.clipboardData?.items || [])].find((item) => item.kind === "file" && item.type.startsWith("image/"));
  if (image && ready && !busy) { event.preventDefault(); void addMfaFile(image.getAsFile()); }
});

$("passkeyToggle").addEventListener("click", async () => {
  if (busy) return;
  setBusy(true);
  try {
    const tab = await getTargetTab();
    const response = await chrome.runtime.sendMessage({type:"passkey_site_set",tab_id:tab.id,origin:targetOrigin,enabled:!passkeyEnabled});
    if (!response?.ok) throw new Error(response?.message || "设置失败");
    await refreshPasskeyState();
    setStatus(passkeyEnabled ? "已启用。请刷新网页，再到网站安全设置中新建通行密钥。" : "已停用，将使用浏览器原有的通行密钥方式。");
  } catch (e) { showError({error:e.message}); }
  finally { setBusy(false); }
});

async function init() {
  [targetTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (/^https?:\/\//.test(targetTab?.url ?? "")) {
    targetOrigin = new URL(targetTab.url).origin;
    $("site").textContent = new URL(targetTab.url).host;
    $("site").title = targetOrigin;
  } else {
    $("site").textContent = "请选择普通网页";
  }
  renderAccounts();
  if (targetOrigin) {
    try { await refreshInlinePreference(); }
    catch (_) { $('inlineToggle').textContent = '网站设置暂不可用'; }
  }
  await refreshPasskeyState();
  await handshake('automatic');
  const mfaResult = await chrome.runtime.sendMessage({type:'mfa_result',tab_id:targetTab?.id});
  if (mfaResult?.result) setStatus(mfaResult.result.message,mfaResult.result.ok ? 'success' : 'error');
  const prompt = await chrome.storage.session.get("mfaPermissionPrompt");
  if (prompt.mfaPermissionPrompt) {
    await chrome.storage.session.remove("mfaPermissionPrompt");
    setStatus(String(prompt.mfaPermissionPrompt), "warning");
  }
}
async function refreshInlinePreference() {
  const response = await chrome.runtime.sendMessage({type:'inline_site_state',tab_id:targetTab.id,origin:targetOrigin});
  if (!response?.ok) throw new Error(response?.message || '读取网站设置失败');
  inlineHidden = response.hidden === true;
  $('inlineToggle').textContent = inlineHidden ? '恢复此网站的填充图标' : '隐藏此网站的填充图标';
  $('inlineToggle').disabled = false;
  try {
    const page = await requestPageContext(targetTab.id);
    const state = page?.inline_status;
    const kinds = {username:'用户名',password:'密码',otp:'验证码'};
    const detail = state?.error || (inlineHidden ? '此网站已隐藏页面入口' :
      state?.target_kind ? `已识别${kinds[state.target_kind] || '登录'}输入框` : '点击账号、密码或验证码输入框显示 CP 图标');
    $('inlineStatus').textContent = `页面脚本 ${page?.content_version || '未知版本'} · ${detail}`;
  } catch (_) {
    $('inlineStatus').textContent = '无法连接页面入口，请检查扩展的网站访问权限；仍可尝试工具栏填充。';
  }
}
$('inlineToggle').addEventListener('click',async () => {
  $('inlineToggle').disabled = true;
  try {
    const tab = await getTargetTab();
    const response = await chrome.runtime.sendMessage({type:'inline_site_set',tab_id:tab.id,origin:targetOrigin,hidden:!inlineHidden});
    if (!response?.ok) throw new Error(response?.message || '设置失败');
    await refreshInlinePreference();
  } catch (error) { setStatus(error.message,'error'); }
  finally { $('inlineToggle').disabled = !targetOrigin; }
});
init().catch((e) => showError({ error: e.message }));
