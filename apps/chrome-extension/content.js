const fillDocumentId = `${location.origin}#${document.URL}`;

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "fill_context") {
    sendResponse({
      documentId: fillDocumentId,
      origin: location.origin,
      frameId: 0,
    });
    return;
  }
  if (msg.type !== "deliver_secret") return;
  if (msg.document_id && msg.document_id !== fillDocumentId) {
    sendResponse({ filled: false, reason: "document_mismatch" });
    return;
  }
  if (msg.origin && msg.origin !== location.origin) {
    sendResponse({ filled: false, reason: "origin_mismatch" });
    return;
  }
  const user = document.querySelector('input[type="email"], input[name="username"], input[name="login"]');
  const pass = document.querySelector('input[type="password"]');
  if (user) user.value = msg.username || "";
  if (pass) pass.value = msg.password || "";
  sendResponse({ filled: true });
});
