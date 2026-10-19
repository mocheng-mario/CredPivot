const statusEl = document.getElementById("status");

async function handshake() {
  const resp = await chrome.runtime.sendMessage({ type: "handshake" });
  if (!resp?.ok) {
    statusEl.textContent = JSON.stringify(resp, null, 2);
    return;
  }
  const st = await chrome.runtime.sendMessage({ type: "agent_status" });
  const payload = st?.payload ?? st?.ok?.payload ?? {};
  const unlocked = payload.unlocked === true;
  const attached = payload.database_attached === true;
  const count = payload.credential_count ?? 0;
  statusEl.textContent =
    `Agent 已连接\n` +
    `Vault: ${unlocked ? (attached ? "已解锁（可写库）" : "已解锁（须主密码写库）") : "已锁定"}\n` +
    `凭据数: ${count}\n` +
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
  if (!tab?.id) return;
  const origin = tab.url ? new URL(tab.url).origin : "https://example.com";
  const suggest = await chrome.runtime.sendMessage({ type: "suggest_credentials", origin });
  const candidates =
    suggest?.payload?.candidates ?? suggest?.candidates ?? [];
  const credentialId = candidates[0]?.id;
  if (!credentialId) {
    statusEl.textContent = "该站点无已保存凭据，请先「保存演示」";
    return;
  }
  const prep = await chrome.runtime.sendMessage({
    type: "fill_prepare",
    credential_id: credentialId,
    origin,
  });
  statusEl.textContent = "prepare: " + JSON.stringify(prep);
  if (!prep?.payload?.prepared) return;
  const requestId = prep.payload?.request_id || prep.request_id;
  const consume = await chrome.runtime.sendMessage({
    type: "fill_consume",
    request_id: requestId,
  });
  const secrets = consume?.payload || consume;
  await chrome.tabs.sendMessage(
    tab.id,
    {
      type: "deliver_secret",
      username: secrets.username,
      password: secrets.password,
    },
    { frameId: 0 }
  );
  statusEl.textContent = "filled";
});
