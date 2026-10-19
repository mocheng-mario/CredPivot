chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type !== "deliver_secret") return;
  const user = document.querySelector('input[type="email"], input[name="username"], input[name="login"]');
  const pass = document.querySelector('input[type="password"]');
  if (user) user.value = msg.username || "";
  if (pass) pass.value = msg.password || "";
  sendResponse({ filled: true });
});
