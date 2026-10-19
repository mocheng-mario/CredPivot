const statusEl = document.getElementById("status");

async function handshake() {
  const resp = await chrome.runtime.sendMessage({ type: "handshake" });
  statusEl.textContent = JSON.stringify(resp, null, 2);
}

document.getElementById("connect").addEventListener("click", handshake);

document.getElementById("saveDemo").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const origin = tab?.url ? new URL(tab.url).origin : "https://example.com";
  const resp = await chrome.runtime.sendMessage({
    type: "save_credential",
    origin,
    username: "demo@credpivot.local",
    password: "fake-password-m0",
  });
  statusEl.textContent = JSON.stringify(resp, null, 2);
});

document.getElementById("fillDemo").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  const origin = tab.url ? new URL(tab.url).origin : "https://example.com";
  const prep = await chrome.runtime.sendMessage({
    type: "fill_prepare",
    credential_id: "placeholder",
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
