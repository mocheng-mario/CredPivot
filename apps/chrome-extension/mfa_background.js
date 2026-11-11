const pending = new Map();

async function currentPage(tabId, url) {
  const tab = await chrome.tabs.get(tabId);
  if (!/^https?:\/\//.test(tab.url || "") || (url && tab.url !== url)) {
    throw new Error("网页已跳转，请在当前页面重新识别二维码。");
  }
  return tab;
}

export async function cancelMfa(tabId, sendNative) {
  const request = pending.get(tabId);
  if (!request) return {ok: true};
  request.cancelled = true;
  await sendNative({action: "mfa.cancel", mfa_request_id: request.id});
  return {ok: true};
}

export async function addMfa(tabId, image, sendNative, verify, clearCache) {
  if (pending.has(tabId)) return {ok: false, message: "此页面已有 MFA 添加请求，请在 App 中处理或取消。"};
  const request = {id: crypto.randomUUID(), cancelled: false};
  pending.set(tabId, request);
  let completed = false;
  try {
    const tab = await currentPage(tabId);
    const origin = new URL(tab.url).origin;
    let gate = await verify(crypto.randomUUID(), false);
    if (gate?.code === 'extension_gate_required') {
      const deadline = Date.now() + 120_000;
      while (!request.cancelled && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve,750));
        await currentPage(tabId,tab.url);
        const state = await sendNative({action:'status'});
        if (!state?.ok) return state;
        if (state.payload?.extension_gate_active) { gate = state; break; }
        if (state.payload?.extension_gate_pending !== true) break;
      }
    }
    if (!gate?.ok) return gate;
    if (request.cancelled) return {ok: false, message: "已取消添加 MFA。"};
    await currentPage(tabId, tab.url);
    if (image == null) {
      const [active] = await chrome.tabs.query({active: true, windowId: tab.windowId});
      if (active?.id !== tabId) throw new Error("请回到目标网页后重新识别二维码。");
      image = await chrome.tabs.captureVisibleTab(tab.windowId, {format: "jpeg", quality: 95});
      const [afterCapture] = await chrome.tabs.query({active: true, windowId: tab.windowId});
      if (afterCapture?.id !== tabId) throw new Error("当前标签页已改变，请重新识别。");
    }
    if (typeof image !== "string" || image.length > 2 * 1024 * 1024 || !/^data:image\/(png|jpeg);base64,/.test(image)) {
      throw new Error("图片过大或格式不受支持，请改用不超过 1.5 MB 的 PNG 或 JPEG 图片。");
    }
    await currentPage(tabId, tab.url);
    if (request.cancelled) return {ok: false, message: "已取消添加 MFA。"};
    const started = await sendNative({action: "mfa.begin", mfa_request_id: request.id, origin, image});
    // 图片只在本次内存通道中传递，不写入扩展存储。
    image = null;
    if (!started?.ok) return started;
    const deadline = Date.now() + 180_000;
    while (!request.cancelled && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 750));
      await currentPage(tabId, tab.url);
      const response = await sendNative({action: "mfa.poll", mfa_request_id: request.id, origin});
      if (!response?.ok) return response;
      if (response.payload?.state === "done") {
        completed = true;
        await clearCache();
        return {ok: true, payload: {saved: true}};
      }
      if (response.payload?.state === "cancelled") return {ok: false, message: "已在 App 中取消添加 MFA。"};
    }
    return {ok: false, message: request.cancelled ? "已取消添加 MFA。" : "添加 MFA 已超时，请重试。"};
  } catch (error) {
    return {ok: false, message: error.message || "二维码识别未完成，请重试。"};
  } finally {
    image = null;
    if (!completed) { try { await sendNative({action: "mfa.cancel", mfa_request_id: request.id}); } catch (_) {} }
    if (pending.get(tabId) === request) pending.delete(tabId);
  }
}
