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
let passkeyEnabled = false;

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
  };
  const gated = result?.needs_gate || code === "extension_gate_required" || code === "locked";
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
  const message = messages[code] || messages[reason] || result?.message || result?.error || "操作未完成，请重试。";
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
  accountEl.disabled = busy || !ready || candidates.length < 2;
  $("accountSearch").disabled = busy || !ready;
  $("fillLogin").disabled = busy || !ready || !row;
  $("fillOtp").disabled = busy || !ready || !mfaCandidates.some((m) => m.id === selectedTotpId);
  $("otp").disabled = busy || !ready || !mfaCandidates.length || (mfaCandidates.length === 1 && Boolean(selectedTotpId));
  $("otherMfas").disabled = busy || !ready;
  $("passkeyToggle").disabled = busy || !targetOrigin?.startsWith("https://");
  $("otherMfas").hidden = !ready || !hasMoreMfas || allMfaMatches;
  $("capture").disabled = busy || !ready || !targetOrigin;
  $("saveNew").disabled = busy || !ready || !captured;
  $("update").disabled = busy || !ready || !row || !captured;
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
  $("captureInfo").textContent = "";
  updateControls();
}

function renderAccounts() {
  const query = $("accountSearch").value.trim().toLowerCase();
  const matches = candidates.filter((row) => (row.username || "").toLowerCase().includes(query));
  accountEl.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = !ready ? "连接后加载账号" : !candidates.length ? "此网站暂无已保存账号" : !matches.length ? "未找到匹配账号" : "请选择登录账号";
  placeholder.disabled = true;
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
  selectedId = previous?.id || remembered?.id || (candidates.length === 1 ? candidates[0].id : "");
  selectionSource = !previous && remembered ? "remembered" : selectionSource;
  renderAccounts();
  return await refreshMfas();
}

async function handshake() {
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
  try {
    await getTargetTab();
    let response = await chrome.runtime.sendMessage({ type: "handshake" });
    if (!response?.ok && response?.code === "extension_gate_required") {
      setStatus("请完成系统指纹验证；如需主密码，请在 App 中输入。完成后会自动继续。", "pending");
      $("stopWaiting").hidden = false;
      for (let i = 0; i < 90; i++) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        if (stopWaiting) {
          setStatus("已停止等待。完成验证后，可点击「连接与验证」重新连接。");
          return;
        }
        const state = await chrome.runtime.sendMessage({ type: "agent_status" });
        if (state?.payload?.extension_gate_active === true) { response = { ok: true, payload: state.payload }; break; }
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
  setStatus("已切换账号，密码和 MFA 将使用当前选择。");
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
$("connect").addEventListener("click", handshake);
$("stopWaiting").addEventListener("click", () => {
  stopWaiting = true;
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
    $("captureInfo").textContent = `已读取：${value.username || "（无用户名）"} · 密码已隐藏`;
    setStatus("表单已读取，请选择保存新账号或更新所选账号。");
  } catch (e) { showError({ error: e.message }); }
  finally { setBusy(false); }
});

async function saveCaptured(update) {
  if (busy || !ready || !captured) return;
  const account = selectedAccount();
  if (update && !account) return;
  const confirmation = update ? `确认更新 ${account.username}？保存账号为 ${captured.username || account.username}，请确认新密码已在网站生效。` : `将 ${captured.username || "此账号"} 保存到 ${captured.origin}？`;
  if (!confirm(confirmation)) return;
  const value = captured;
  setBusy(true);
  setStatus("正在保存…", "pending");
  try {
    await getTargetTab();
    // 改密页面可能没有用户名输入框，不能因此清空已选账号的名称。
    const username = update ? value.username || account.username : value.username;
    const response = await chrome.runtime.sendMessage({ type: update ? "update_credential" : "save_credential", tab_id: value.tabId, document_id: value.documentId, username, password: value.password, credential_id: account?.id, expected_revision: account?.current_revision });
    if (!response?.ok) { showError(response); return; }
    if (await refreshAccounts()) setStatus(update ? "所选账号已更新。" : "新账号已保存。", "success");
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
  await refreshPasskeyState();
  await handshake();
}
init().catch((e) => showError({ error: e.message }));
