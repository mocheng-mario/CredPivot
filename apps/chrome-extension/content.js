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
  const user = document.querySelector(
    'input[type="email"], input[type="text"][autocomplete="username"], input[name="username"], input[name="login"], input[name="email"], input[id="username"], input[id="email"]'
  );
  const pass = document.querySelector('input[type="password"]');
  if (!user && !pass) {
    sendResponse({ filled: false, reason: "no_input_fields" });
    return;
  }
  function setValue(el, value) {
    if (!el || value == null) return;
    el.focus();
    el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  setValue(user, msg.username || "");
  setValue(pass, msg.password || "");
  sendResponse({ filled: true });
});
