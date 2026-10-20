const statusEl = document.getElementById("status");

async function handshake() {
  const resp = await chrome.runtime.sendMessage({ type: "handshake" });
  if (!resp?.ok) {
    statusEl.textContent = JSON.stringify(resp, null, 2);
    return;
  }
  const st = await chrome.runtime.sendMessage({ type: "agent_status" });
  const payload = st?.payload ?? {};
  const unlocked = payload.unlocked === true;
  const attached = payload.database_attached === true;
  const count = payload.credential_count ?? 0;
  statusEl.textContent =
    `Agent 已连接\n` +
    `Vault: ${unlocked ? (attached ? "已解锁（可写库）" : "已解锁（须主密码写库）") : "已锁定"}\n` +
    `凭据数: ${count}\n` +
    `（连接由后台保持，可关闭本窗口）\n` +
    JSON.stringify(payload, null, 2);
}

document.getElementById("connect").addEventListener("click", handshake);

document.getElementById("saveDemo").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const origin = tab?.url ? new URL(tab.url).origin : "https://example.com";
  const resp = await chrome.runtime.sendMessage({
    type: "save_credential",
    origin,
    username: "demo@credpivot.local",
    password: "demo-password-m2",
  });
  statusEl.textContent = JSON.stringify(resp, null, 2);
});

document.getElementById("fillDemo").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    statusEl.textContent = "无活动标签页";
    return;
  }
  statusEl.textContent = "填充进行中…（可关闭本窗口，后台会继续）";
  const result = await chrome.runtime.sendMessage({
    type: "fill_active_tab",
    tab_id: tab.id,
  });
  statusEl.textContent = result?.ok
    ? `已填充：${result.origin}`
    : JSON.stringify(result, null, 2);
});

// 打开 popup 时自动探测一次状态
handshake().catch(() => {});
