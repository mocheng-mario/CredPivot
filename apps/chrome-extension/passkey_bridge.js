// 隔离世界仅开放通行密钥入口；网页仍无权调用密码/MFA/管理接口。
(() => {
  if (window !== window.top || location.protocol !== "https:") return;
  const documentToken = crypto.randomUUID();
  let active = null;
  chrome.runtime.onMessage.addListener((message, _sender, respond) => {
    if (message?.type === "passkey_document_check") respond({document_token: documentToken});
  });
  window.addEventListener("message", (event) => {
    if (event.source !== window || event.origin !== location.origin || event.data?.channel !== "credpivot.passkey.v1" ||
        !["create", "get"].includes(event.data.kind) || event.ports.length !== 1) return;
    const port = event.ports[0];
    if (active) { port.postMessage({error:{name:"NotAllowedError",message:"已有通行密钥请求正在处理"}}); port.close(); return; }
    const requestId = crypto.randomUUID();
    active = requestId;
    const cancel = () => { void chrome.runtime.sendMessage({type:"passkey_cancel",request_id:requestId,document_token:documentToken}).catch(() => {}); };
    port.onmessage = (message) => { if (message.data?.cancel) cancel(); };
    port.start();
    const leave = () => cancel();
    window.addEventListener("pagehide", leave, {once:true});
    chrome.runtime.sendMessage({type:"passkey_request",request_id:requestId,document_token:documentToken,
      kind:event.data.kind,options:event.data.options}).then((response) => {
      port.postMessage(response);
    }).catch(() => {
      port.postMessage({error:{name:"NotAllowedError",message:"CredPivot 插件连接中断，请刷新页面后重试"}});
    }).finally(() => {
      window.removeEventListener("pagehide", leave);
      port.close();
      if (active === requestId) active = null;
    });
  });
})();
