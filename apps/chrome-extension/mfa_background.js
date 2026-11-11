const pending = new Map();
const MAX_IMAGE_LENGTH = 2 * 1024 * 1024;

export function pageOrigin(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.origin : "";
  } catch {
    return "";
  }
}

async function currentPage(tabId, origin) {
  const tab = await chrome.tabs.get(tabId);
  const current = pageOrigin(tab.url);
  // 同一网站内的路由、查询参数和 hash 变化仍是这次识别，只有换源才中断。
  if (!current || (origin && current !== origin)) {
    throw new Error("网页已跳转，请在当前页面重新识别二维码。");
  }
  return tab;
}

function dataUrlFromBlob(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error ?? new Error("image"));
    reader.readAsDataURL(blob);
  });
}

function validRegion(selection) {
  const rect = selection?.rect;
  const viewportWidth = Number(selection?.viewportWidth);
  const viewportHeight = Number(selection?.viewportHeight);
  return selection?.ok === true && rect
    && [rect.x, rect.y, rect.width, rect.height, viewportWidth, viewportHeight].every((value) => Number.isFinite(value))
    && rect.width >= 8 && rect.height >= 8
    && viewportWidth >= 8 && viewportHeight >= 8
    && viewportWidth <= 20000 && viewportHeight <= 20000;
}

async function requestRegion(tabId, request) {
  let settled = false;
  const watch = (async () => {
    while (!settled && !request.cancelled) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    if (request.cancelled) chrome.tabs.sendMessage(tabId, {type: "mfa_select_cancel"}).catch(() => {});
  })();
  void watch;
  try {
    const selection = await chrome.tabs.sendMessage(tabId, {type: "mfa_select_region"});
    if (!selection) throw new Error("请刷新网页后，再框选二维码区域。");
    if (selection.cancelled) throw new Error("已取消框选二维码区域。");
    if (selection.timedOut) throw new Error("框选已超时，请重新识别二维码。");
    if (!validRegion(selection)) throw new Error("请重新框选二维码区域。");
    return selection;
  } catch (error) {
    if (["已取消框选二维码区域。", "框选已超时，请重新识别二维码。", "请重新框选二维码区域。", "请刷新网页后，再框选二维码区域。"].includes(error?.message)) throw error;
    throw new Error("请刷新网页后，再框选二维码区域。");
  } finally {
    settled = true;
  }
}

async function cropCapturedImage(image, selection) {
  const bitmap = await createImageBitmap(await (await fetch(image)).blob());
  try {
    const rect = selection.rect;
    const scaleX = bitmap.width / selection.viewportWidth;
    const scaleY = bitmap.height / selection.viewportHeight;
    const x = Math.max(0, Math.min(bitmap.width - 1, Math.round(rect.x * scaleX)));
    const y = Math.max(0, Math.min(bitmap.height - 1, Math.round(rect.y * scaleY)));
    const width = Math.max(1, Math.min(bitmap.width - x, Math.round(rect.width * scaleX)));
    const height = Math.max(1, Math.min(bitmap.height - y, Math.round(rect.height * scaleY)));
    const canvas = new OffscreenCanvas(width, height);
    const context = canvas.getContext("2d", {alpha: false});
    if (!context) throw new Error("请重新框选二维码区域。");
    context.drawImage(bitmap, x, y, width, height, 0, 0, width, height);
    return await dataUrlFromBlob(await canvas.convertToBlob({type: "image/jpeg", quality: 0.92}));
  } finally {
    bitmap.close();
  }
}

async function captureSelected(windowId, selection) {
  let full = await chrome.tabs.captureVisibleTab(windowId, {format: "jpeg", quality: 80});
  try {
    return await cropCapturedImage(full, selection);
  } finally {
    full = null;
  }
}

async function compressCapturedImage(image) {
  if (typeof image !== "string" || image.length <= MAX_IMAGE_LENGTH) return image;
  const bitmap = await createImageBitmap(await (await fetch(image)).blob());
  try {
    let quality = 0.6;
    let scale = 1;
    for (let attempt = 0; attempt < 6 && image.length > MAX_IMAGE_LENGTH; attempt++) {
      const width = Math.max(1, Math.round(bitmap.width * scale));
      const height = Math.max(1, Math.round(bitmap.height * scale));
      const canvas = new OffscreenCanvas(width, height);
      const context = canvas.getContext("2d", {alpha: false});
      if (!context) break;
      context.drawImage(bitmap, 0, 0, width, height);
      const next = await dataUrlFromBlob(await canvas.convertToBlob({type: "image/jpeg", quality}));
      if (typeof next !== "string" || (next.length >= image.length && (scale < 1 || quality <= 0.45))) break;
      image = next;
      if (quality > 0.45) quality = Math.round((quality - 0.15) * 100) / 100;
      else scale *= 0.75;
    }
    return image;
  } finally {
    bitmap.close();
  }
}

export async function cancelMfa(tabId, sendNative) {
  const request = pending.get(tabId);
  if (!request) return {ok: true};
  request.cancelled = true;
  // 地址变化和收尾可能同时取消，只发一次，避免后一次把已经完成的结果清掉。
  if (!request.cancelTask) {
    request.cancelTask = sendNative({action: "mfa.cancel", mfa_request_id: request.id});
  }
  return request.cancelTask;
}

export async function cancelMfaIfOriginChanged(tabId, url, sendNative) {
  const request = pending.get(tabId);
  if (!request?.origin || pageOrigin(url) === request.origin) return {ok: true};
  return cancelMfa(tabId, sendNative);
}

export async function addMfa(tabId, image, sendNative, verify, clearCache) {
  if (pending.has(tabId)) return {ok: false, code: "mfa_pending", message: "此页面已有 MFA 添加请求，请在 App 中处理或取消。"};
  const request = {id: crypto.randomUUID(), cancelled: false, origin: ""};
  pending.set(tabId, request);
  let completed = false;
  let promoted = null;
  try {
    const tab = await currentPage(tabId);
    request.origin = pageOrigin(tab.url);
    let gate = await verify(crypto.randomUUID(), false);
    if (gate?.code === 'extension_gate_required') {
      const deadline = Date.now() + 120_000;
      while (!request.cancelled && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve,750));
        await currentPage(tabId, request.origin);
        const state = await sendNative({action:'status'});
        if (!state?.ok) return state;
        if (state.payload?.extension_gate_active) { gate = state; break; }
        if (state.payload?.extension_gate_pending !== true) break;
      }
    }
    if (!gate?.ok) return gate;
    if (request.cancelled) return {ok: false, message: "已取消添加 MFA。"};
    await currentPage(tabId, request.origin);
    if (image == null) {
      const [active] = await chrome.tabs.query({active: true, windowId: tab.windowId});
      if (active?.id !== tabId) throw new Error("请回到目标网页后重新识别二维码。");
      const selection = await requestRegion(tabId, request);
      if (request.cancelled) return {ok: false, message: "已取消添加 MFA。"};
      await currentPage(tabId, request.origin);
      const [afterSelect] = await chrome.tabs.query({active: true, windowId: tab.windowId});
      if (afterSelect?.id !== tabId) throw new Error("当前标签页已改变，请重新识别。");
      // 整页图只用于裁切，裁完立即丢掉，后续只保留选区。
      image = await captureSelected(tab.windowId, selection);
      try { image = await compressCapturedImage(image); }
      catch (_) { /* 压缩失败时保留选区图片，由下面的大小检查给出明确提示。 */ }
    }
    if (typeof image !== "string" || image.length > MAX_IMAGE_LENGTH || !/^data:image\/(png|jpeg);base64,/.test(image)) {
      throw new Error("图片过大或格式不受支持，请改用不超过 1.5 MB 的 PNG 或 JPEG 图片。");
    }
    await currentPage(tabId, request.origin);
    if (request.cancelled) return {ok: false, message: "已取消添加 MFA。"};
    const started = await sendNative({action: "mfa.begin", mfa_request_id: request.id, origin: request.origin, image});
    // 图片只在本次内存通道中传递，不写入扩展存储。
    image = null;
    if (!started?.ok) return started;
    const deadline = Date.now() + 180_000;
    while (!request.cancelled && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 750));
      await currentPage(tabId, request.origin);
      const response = await sendNative({action: "mfa.poll", mfa_request_id: request.id, origin: request.origin});
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
    if (!completed) {
      try {
        const cancelled = await cancelMfa(tabId, sendNative);
        // 保存已经落库时，地址变化或收尾取消不能再把成功报成失败。
        if (cancelled?.ok && cancelled.payload?.state === "done") {
          completed = true;
          await clearCache();
          promoted = {ok: true, payload: {saved: true}};
        }
      } catch (_) {}
    }
    if (pending.get(tabId) === request) pending.delete(tabId);
    if (promoted) return promoted;
  }
}
