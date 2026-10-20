/** 在 service worker 中执行，popup 关闭后仍可完成填充。 */

export async function runFillOnTab(tabId, sendNative) {
  const tab = await chrome.tabs.get(tabId);
  if (!tab?.url || !tab.url.startsWith("http")) {
    return { ok: false, error: "请在普通 http(s) 网页标签页中使用填充" };
  }
  const origin = new URL(tab.url).origin;

  let ctx;
  try {
    ctx = await chrome.tabs.sendMessage(tabId, { type: "fill_context" });
  } catch (e) {
    return {
      ok: false,
      error: "无法与页面通信（请刷新该页后重试）",
      detail: String(e),
    };
  }
  if (!ctx?.documentId || !ctx?.origin) {
    return { ok: false, error: "无法读取目标页面上下文" };
  }
  if (ctx.origin !== origin) {
    return { ok: false, error: "页面 origin 不一致" };
  }

  const suggest = await sendNative({
    action: "credential.suggest_for_origin",
    origin: ctx.origin,
  });
  if (!suggest?.ok) {
    return { ok: false, error: suggest?.message || suggest?.code || "suggest 失败", raw: suggest };
  }
  const candidates = suggest?.payload?.candidates ?? [];
  const credentialId = candidates[0]?.id;
  if (!credentialId) {
    return {
      ok: false,
      error: "当前站点无匹配的登录凭据（origin 须与保存时一致）",
      origin: ctx.origin,
    };
  }

  const prep = await sendNative({
    action: "credential.fill_prepare",
    credential_id: credentialId,
    origin: ctx.origin,
    tab_id: tabId,
    frame_id: ctx.frameId ?? 0,
    document_id: ctx.documentId,
  });
  if (!prep?.ok || !prep?.payload?.prepared) {
    return { ok: false, error: prep?.message || prep?.code || "prepare 失败", raw: prep };
  }
  const requestId = prep.payload?.request_id || prep.request_id;

  const consume = await sendNative({
    action: "credential.fill_consume",
    request_id: requestId,
    origin: ctx.origin,
    frame_id: ctx.frameId ?? 0,
    document_id: ctx.documentId,
  });
  if (!consume?.ok) {
    return { ok: false, error: consume?.message || consume?.code || "consume 失败", raw: consume };
  }
  const secrets = consume.payload ?? consume;
  if (!secrets?.username && !secrets?.password) {
    return { ok: false, error: "未拿到用户名或密码", raw: consume };
  }

  let deliver;
  try {
    deliver = await chrome.tabs.sendMessage(
      tabId,
      {
        type: "deliver_secret",
        document_id: ctx.documentId,
        origin: ctx.origin,
        username: secrets.username,
        password: secrets.password,
      },
      { frameId: ctx.frameId ?? 0 }
    );
  } catch (e) {
    return { ok: false, error: "投递到页面失败", detail: String(e) };
  }
  if (!deliver?.filled) {
    return {
      ok: false,
      error: deliver?.reason || "页面上未找到可填写的输入框",
      deliver,
    };
  }
  return { ok: true, filled: true, origin: ctx.origin };
}
