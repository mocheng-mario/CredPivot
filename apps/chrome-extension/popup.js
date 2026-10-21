const statusEl = document.getElementById("status");
const mfaEl = document.getElementById("mfa");
const manifest = chrome.runtime.getManifest();

document.getElementById("ver").textContent = `扩展版本 ${manifest.version}`;

async function currentTabOrigin() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !tab.url.startsWith("http")) return null;
  return new URL(tab.url).origin;
}

async function refreshMfaHint() {
  const origin = await currentTabOrigin();
  if (!origin) {
    mfaEl.hidden = true;
    return;
  }
  const suggest = await chrome.runtime.sendMessage({
    type: "suggest_credentials",
    origin,
  });
  if (!suggest?.ok) {
    mfaEl.hidden = true;
    return;
  }
  const candidates = suggest?.payload?.candidates ?? [];
  const first = candidates.find((c) => c?.linked_totp_id) ?? candidates[0];
  const totpId = first?.linked_totp_id;
  if (!totpId) {
    mfaEl.textContent = "登录密码未关联 MFA（在 App 凭据→登录密码中关联）";
    mfaEl.hidden = false;
    return;
  }
  const codeResp = await chrome.runtime.sendMessage({
    type: "totp_code",
    totp_id: totpId,
  });
  if (!codeResp?.ok) {
    mfaEl.textContent = `MFA：${codeResp?.message || codeResp?.code || "读取失败"}`;
    mfaEl.hidden = false;
    return;
  }
  const code = codeResp?.payload?.code ?? codeResp?.payload;
  mfaEl.textContent = `预览 MFA：${code}\n（登录：${first.username || first.id})`;
  mfaEl.hidden = false;
}

async function handshakeOnce() {
  return chrome.runtime.sendMessage({ type: "handshake" });
}

async function handshake() {
  statusEl.textContent = "连接 Agent…";
  let resp = await handshakeOnce();
  if (!resp?.ok && resp?.code === "extension_gate_required") {
    statusEl.textContent =
      "请在 CredPivot App 完成指纹或保险库主密码验证。\n" +
      "可点系统弹窗「取消」关闭；完成后点「连接」或等待自动检测（不会反复抢焦点）。";
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      const st = await chrome.runtime.sendMessage({ type: "agent_status" });
      if (st?.payload?.extension_gate_active === true) {
        resp = { ok: true, payload: st.payload };
        break;
      }
    }
  }
  if (!resp?.ok) {
    statusEl.textContent = JSON.stringify(resp, null, 2);
    mfaEl.hidden = true;
    return;
  }
  const connectPayload = resp.payload ?? {};
  const st = await chrome.runtime.sendMessage({ type: "agent_status" });
  const payload = { ...connectPayload, ...(st?.payload ?? {}) };
  const unlocked = payload.unlocked === true;
  const attached = payload.database_attached === true;
  const count = payload.credential_count ?? 0;
  const gate = payload.extension_gate_active === true;
  const idle = payload.extension_gate_idle_secs ?? 300;
  statusEl.textContent =
    `Agent 已连接\n` +
    `Vault: ${unlocked ? (attached ? "已解锁" : "解锁状态异常，请在 App 重试") : "已锁定"}\n` +
    `扩展授权: ${gate ? `已通过（${idle}s 无操作需重验）` : unlocked ? "未完成（请点连接并重试）" : "（请在 App 解锁并授权）"}\n` +
    `凭据数: ${count}`;
  if (unlocked && gate) {
    await refreshMfaHint();
  } else {
    mfaEl.hidden = true;
  }
}

function formatFillError(result) {
  if (result?.needs_gate) {
    return `${result.error}\n\n请在 CredPivot App 完成指纹或主密码验证后重试。`;
  }
  return JSON.stringify(result, null, 2);
}

document.getElementById("connect").addEventListener("click", handshake);

document.getElementById("fillLogin").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    statusEl.textContent = "无活动标签页";
    return;
  }
  const hs = await handshakeOnce();
  if (!hs?.ok) {
    statusEl.textContent = formatFillError({
      ok: false,
      error: hs?.message || hs?.code || "请先连接并完成指纹",
      needs_gate: hs?.code === "extension_gate_required",
    });
    return;
  }
  statusEl.textContent = "填充账号密码…";
  const result = await chrome.runtime.sendMessage({
    type: "fill_login_tab",
    tab_id: tab.id,
  });
  statusEl.textContent = result?.ok
    ? `已填充账号密码：${result.origin}`
    : formatFillError(result);
});

document.getElementById("fillOtp").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    statusEl.textContent = "无活动标签页";
    return;
  }
  const hs = await handshakeOnce();
  if (!hs?.ok) {
    statusEl.textContent = formatFillError({
      ok: false,
      error: hs?.message || hs?.code || "请先连接并完成指纹",
      needs_gate: hs?.code === "extension_gate_required",
    });
    return;
  }
  statusEl.textContent = "填充 MFA…";
  const result = await chrome.runtime.sendMessage({
    type: "fill_otp_vault_tab",
    tab_id: tab.id,
  });
  statusEl.textContent = result?.ok
    ? `已填充 MFA：${result.origin}`
    : formatFillError(result);
});

handshake().catch(() => {});
