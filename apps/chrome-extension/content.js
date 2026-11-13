(() => {
  if (window !== window.top || !/^https?:$/.test(location.protocol)) return;
  const version = chrome.runtime.getManifest().version;
  // 显式补装也用于修复同版本插件重载后的失效上下文，不能仅凭版本标记跳过。
  try { globalThis.__credpivotContentCleanup?.(); } catch (_) { /* 旧扩展上下文可能已失效。 */ }
  // 普通 HTTP 页面没有 randomUUID，但仍提供 getRandomValues；文档与输入框绑定不能因此失效。
  function randomId() {
    return crypto.randomUUID?.() ?? [...crypto.getRandomValues(new Uint8Array(16))]
      .map((value) => value.toString(16).padStart(2, '0')).join('');
  }
  const documentId = randomId();
  const targets = new Map();
  const inputIds = new WeakMap();
  const listeners = [];
  let lastInput = null, contextInput = null, anchor = null, panel = null, token = null;
  let hidden = false, opening = false, delivering = false, generation = 0, frame = 0;
  let host = null, shadow = null, badge = null, notice = null, observer = null, panelTimer = null, noticeTimer = null;
  let inlineFailure = '';
  let regionTask = null, regionFinish = null;

  function runtimeMessage(message) {
    try { return chrome.runtime.sendMessage(message); }
    catch (error) { return Promise.reject(error); }
  }

  function listen(object, type, callback, options) {
    object.addEventListener(type, callback, options);
    listeners.push(() => object.removeEventListener(type, callback, options));
  }
  function usable(el, readable = false) {
    if (!(el instanceof HTMLInputElement) || !el.isConnected || el.disabled || (!readable && el.readOnly) || el.type === 'hidden' || !el.getClientRects().length) return false;
    const style = getComputedStyle(el);
    return style.visibility !== 'hidden' && style.visibility !== 'collapse' && Number(style.opacity) !== 0;
  }
  function hint(el) {
    return `${el.name} ${el.id} ${el.autocomplete} ${el.getAttribute('aria-label') || ''} ${el.placeholder || ''}`;
  }
  function otpHint(value) {
    return /(?:otp|totp|mfa|2fa|one.?time|verification.?code|auth.?code|验证码|动态码)/i.test(value);
  }
  function excluded(el) {
    return /captcha|recaptcha|search|cvv|cvc|card.?number/i.test(hint(el)) || el.autocomplete.startsWith('cc-');
  }
  function namedUsername(el) {
    return el.type === 'email' || el.autocomplete === 'username' || /username|j_username|identifier|user.?id|login/i.test(hint(el));
  }
  function scopeFor(el) {
    return el?.form || el?.closest('[role="form"]') || el?.parentElement?.parentElement || document;
  }
  function inputs(root, readable = false) { return [...root.querySelectorAll('input')].filter((input) => usable(input,readable)); }
  function role(el, manual = '') {
    if (!usable(el) || excluded(el)) return null;
    if (manual === 'otp') return ['text', 'tel', 'number'].includes(el.type) ||
      (el.type === 'password' && (el.autocomplete === 'one-time-code' || otpHint(hint(el)))) ? 'otp' : null;
    if (manual === 'login' && (el.autocomplete === 'one-time-code' || otpHint(hint(el)))) return null;
    if (el.autocomplete === 'one-time-code' || otpHint(hint(el))) return 'otp';
    if (el.maxLength === 1) {
      for (let root = el.parentElement, depth = 0; root && depth < 3; root = root.parentElement, depth++) {
        if (otpHint(`${root.id} ${root.className} ${root.getAttribute('aria-label') || ''}`)) return 'otp';
      }
    }
    if (el.type === 'password' && el.autocomplete !== 'new-password') return 'password';
    if (!['text', 'email', 'tel'].includes(el.type)) return null;
    if (manual === 'login' || el.autocomplete === 'username' || /username|j_username|identifier|user.?id|login/i.test(hint(el))) return 'username';
    const nearby = inputs(scopeFor(el));
    const password = nearby.find((input) => input.type === 'password' && input.autocomplete !== 'new-password' && !otpHint(hint(input)));
    if (password) {
      const eligible = nearby.filter((input) => ['text','email','tel'].includes(input.type) && !excluded(input) && !otpHint(hint(input)));
      const preferred = eligible.find(namedUsername);
      const fallback = eligible.filter((input) => Boolean(input.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING)).at(-1);
      return (preferred || fallback) === el ? 'username' : null;
    }
    if (el.type === 'email' && /login|signin|sign-in|登录/i.test(`${el.form?.action || ''} ${el.form?.id || ''}`)) return 'username';
    return null;
  }
  function bind(el, manual = '') {
    const kind = role(el, manual);
    if (!kind) return null;
    const old = targets.get(inputIds.get(el));
    if (old && old.kind === kind && old.url === location.href && old.form === el.form) return old;
    const target = {id: randomId(), el, kind, manual, form: el.form, url: location.href};
    targets.set(target.id, target); inputIds.set(el, target.id);
    while (targets.size > 32) targets.delete(targets.keys().next().value);
    return target;
  }
  function valid(target) {
    return target && targets.get(target.id) === target && target.url === location.href && target.el.form === target.form && role(target.el, target.manual) === target.kind;
  }
  function loginFields(capture = false, target = null) {
    const focused = valid(target) && target.kind !== 'otp' ? target.el : null;
    let candidates = inputs(focused ? scopeFor(focused) : document,capture);
    const passwords = candidates.filter((input) => input.type === 'password' && !otpHint(hint(input)));
    const pass = (capture && passwords.find((input) => input.autocomplete === 'new-password')) ||
      (focused?.type === 'password' ? focused : null) ||
      passwords.find((input) => input.autocomplete === 'current-password') || passwords.find((input) => input.autocomplete !== 'new-password');
    if (!focused && pass) candidates = inputs(scopeFor(pass),capture);
    let user = focused && target.kind === 'username' ? focused : candidates.find((input) =>
      ['text','email','tel'].includes(input.type) && namedUsername(input) && !excluded(input) && !otpHint(hint(input)));
    if (!user && pass) user = candidates.filter((input) => ['text', 'email', 'tel'].includes(input.type) && !excluded(input) &&
      !otpHint(hint(input)) && Boolean(input.compareDocumentPosition(pass) & Node.DOCUMENT_POSITION_FOLLOWING)).at(-1);
    return {user, pass};
  }
  function setValue(el, value) {
    if (!usable(el) || typeof value !== 'string' || !value) return false;
    el.focus();
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', {bubbles: true, composed: true}));
    el.dispatchEvent(new Event('change', {bubbles: true, composed: true}));
    return el.value === value;
  }
  function fillOtp(code, target) {
    if (typeof code !== 'string' || !/^\d+$/.test(code)) return false;
    const el = valid(target) && target.kind === 'otp' ? target.el : inputs(document).find((input) => role(input) === 'otp');
    if (!el) return false;
    if (el.maxLength !== 1) return (el.maxLength <= 0 || el.maxLength >= code.length) && setValue(el, code);
    // 分格验证码只能在同一表单/容器内填满整组，不把完整验证码塞进第一格。
    for (let root = el.parentElement, depth = 0; root && depth < 4; root = root.parentElement, depth++) {
      const pieces = inputs(root).filter((input) => input.form === el.form && input.maxLength === 1 &&
        ['text', 'tel', 'number', 'password'].includes(input.type) && !excluded(input));
      if (pieces.length === code.length) return pieces.every((input, index) => setValue(input, code[index]));
      if (pieces.length > code.length || root === el.form) break;
    }
    return false;
  }

  function closePanel(cancel = true) {
    generation++; opening = false;
    clearTimeout(panelTimer); panelTimer = null;
    clearTimeout(noticeTimer); if (notice) notice.hidden = true;
    const current = token; token = null;
    panel?.remove(); panel = null;
    if (cancel && current) void runtimeMessage({type:'inline_cancel', token:current, document_id:documentId}).catch(() => {});
  }
  function hideBadge() {
    if (badge) badge.hidden = true;
    clearTimeout(noticeTimer); if (notice) notice.hidden = true;
    anchor = null;
    observer?.disconnect();
  }
  function schedulePosition() {
    if (frame) return;
    frame = requestAnimationFrame(() => { frame = 0; position(); });
  }
  function position() {
    for (const [id,target] of targets) if (!target.el.isConnected) targets.delete(id);
    if (lastInput && !lastInput.isConnected) lastInput = null;
    if (contextInput && !contextInput.isConnected) contextInput = null;
    if (!anchor) return;
    if (!valid(anchor) || !host?.isConnected || (panel && !panel.isConnected)) {
      closePanel(); hideBadge(); return;
    }
    const rect = anchor.el.getBoundingClientRect();
    const outside = rect.bottom <= 0 || rect.top >= innerHeight || rect.right <= 0 || rect.left >= innerWidth;
    badge.hidden = hidden || outside;
    badge.style.left = `${Math.max(4, Math.min(rect.right + 5, innerWidth - 34))}px`;
    badge.style.top = `${Math.max(4, Math.min(rect.top + (rect.height - 26) / 2, innerHeight - 30))}px`;
    if (!badge.hidden) {
      const style = getComputedStyle(badge);
      if (!badge.getClientRects().length || style.visibility === 'hidden' ||
          style.visibility === 'collapse' || Number(style.opacity) === 0) {
        inlineFailure = '页面样式阻止了填充入口显示，请使用工具栏填充';
      }
    }
    if (notice && !notice.hidden) {
      const width = Math.min(320, innerWidth - 16);
      notice.style.width = `${width}px`;
      notice.style.left = `${Math.max(8, Math.min(rect.left, innerWidth - width - 8))}px`;
      notice.style.top = `${Math.max(8, Math.min(rect.bottom + 34, innerHeight - notice.offsetHeight - 8))}px`;
      notice.style.visibility = outside ? 'hidden' : 'visible';
    }
    if (panel) {
      const width = Math.max(220, Math.min(360, innerWidth - 16));
      const height = Math.max(150, Math.min(360, innerHeight - 24));
      panel.style.width = `${width}px`; panel.style.height = `${height}px`;
      panel.style.left = `${Math.max(8, Math.min(rect.left, innerWidth - width - 8))}px`;
      panel.style.top = `${Math.max(8, Math.min(rect.bottom + 6, innerHeight - height - 8))}px`;
      panel.hidden = outside;
    }
  }
  function ensureHost() {
    if (host?.isConnected) return;
    // 扩展重载后的新上下文不能调用旧闭包，移除带本扩展标记的残留入口。
    document.querySelectorAll('[data-credpivot-inline-root]').forEach((element) => element.remove());
    host = document.createElement('div');
    host.setAttribute('data-credpivot-inline-root','');
    // Shadow DOM 只隔离内部样式，宿主仍会命中网页的 div / 通配选择器。
    host.style.setProperty('all','initial','important');
    host.style.setProperty('display','block','important');
    host.style.setProperty('visibility','visible','important');
    host.style.setProperty('opacity','1','important');
    host.style.setProperty('position','fixed','important');
    host.style.setProperty('z-index','2147483647','important');
    host.style.setProperty('inset','0','important');
    host.style.setProperty('pointer-events','none','important');
    shadow = host.attachShadow({mode:'closed'});
    const styles = 'button{position:fixed;width:26px;height:26px;border:1px solid #d8dafa;border-radius:8px;background:#565dd9;color:white;font:600 10px system-ui;box-shadow:0 2px 8px #0002;cursor:pointer;pointer-events:auto}button:focus-visible{outline:2px solid #565dd9;outline-offset:2px}button[hidden],iframe[hidden],.notice[hidden]{display:none}iframe{position:fixed;border:1px solid #dce0eb;border-radius:12px;background:white;box-shadow:0 8px 32px #0003;pointer-events:auto}.notice{position:fixed;box-sizing:border-box;padding:10px 12px;border:1px solid #efc3a6;border-radius:10px;background:#fff8ef;color:#663d12;font:13px/1.5 system-ui;overflow-wrap:anywhere;box-shadow:0 4px 16px #0002;pointer-events:none}';
    try {
      const sheet = new CSSStyleSheet(); sheet.replaceSync(styles); shadow.adoptedStyleSheets = [sheet];
    } catch (_) {
      // 样式表 API 不可用时仍创建入口，避免显示层异常同时中断整个点击处理。
      const style = document.createElement('style'); style.textContent = styles; shadow.append(style);
    }
    badge = document.createElement('button'); badge.textContent = 'CP'; badge.type = 'button'; badge.hidden = true;
    badge.setAttribute('aria-label','使用 CredPivot 填充'); badge.title = 'CredPivot：填充账号或验证码';
    badge.addEventListener('mousedown', (event) => event.preventDefault());
    badge.addEventListener('click', (event) => {
      if (!event.isTrusted || !anchor) return;
      if (panel || opening) closePanel();
      else {
        // SPA 路由、表单更新或绑定被淘汰后，旧图标不能继续提交已过期的输入框标识。
        // 只在本次真实点击时重绑同一个输入框，不把旧面板授权转移给其他输入框。
        const current = bind(anchor.el, anchor.manual);
        if (!current) { closePanel(); hideBadge(); return; }
        showBadge(current);
        void open(current);
      }
    });
    notice = document.createElement('div'); notice.className = 'notice'; notice.hidden = true;
    notice.setAttribute('role','alert');
    shadow.append(badge,notice); document.documentElement.append(host);
    observer ??= new MutationObserver(schedulePosition);
  }
  function showFailure(message) {
    const raw = String(message || '页面填充面板未能打开，请再次点击图标或使用工具栏填充');
    inlineFailure = /Extension context invalidated|Receiving end does not exist|message port closed/i.test(raw)
      ? '插件连接已失效，请重新点击图标；若仍失败，请刷新网页后重试。' : raw;
    if (!badge || !notice) return;
    badge.textContent = '!'; badge.title = inlineFailure;
    badge.setAttribute('aria-label',`CredPivot：${inlineFailure}`);
    // 面板内已经显示同一原因时不再覆盖候选与验证按钮。
    notice.textContent = inlineFailure; notice.hidden = Boolean(panel);
    clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => { notice.hidden = true; },10000);
    position();
  }
  function showBadge(target) {
    if (hidden || !valid(target)) return;
    if (anchor?.id !== target.id) closePanel();
    try {
      ensureHost(); anchor = target; badge.hidden = false;
      observer.observe(document.documentElement, {childList:true,subtree:true});
      position();
    } catch (_) {
      inlineFailure = '页面填充入口创建失败，请使用工具栏填充';
      closePanel(); hideBadge();
    }
  }
  async function open(target, forced = false) {
    if (!valid(target) || opening || (hidden && !forced)) return {ok:false};
    closePanel(); opening = true;
    const current = ++generation;
    let openTimer;
    try {
      ensureHost(); anchor = target;
      inlineFailure = '';
      badge.textContent = 'CP'; badge.title = 'CredPivot：正在打开填充面板';
      badge.setAttribute('aria-label','使用 CredPivot 填充');
      const pending = runtimeMessage({type:'inline_open', document_id:documentId, target_id:target.id});
      // 只给创建面板的非敏感请求限时；不重放取密请求，也不截断用户的指纹验证。
      void pending.then((response) => {
        if ((generation !== current || !valid(target)) && response?.token)
          void runtimeMessage({type:'inline_cancel',token:response.token,document_id:documentId}).catch(() => {});
      }).catch(() => {});
      const response = await Promise.race([pending, new Promise((_, reject) => {
        openTimer = setTimeout(() => reject(new Error('打开填充面板超时，请再次点击图标重试')),8000);
      })]);
      if (generation !== current || !valid(target)) {
        if (response?.token) void runtimeMessage({type:'inline_cancel',token:response.token,document_id:documentId}).catch(() => {});
        return {ok:false};
      }
      if (!response?.ok) throw new Error(response?.message || '连接失败，请再次点击图标重试');
      inlineFailure = '';
      token = response.token;
      panel = document.createElement('iframe');
      panel.title = 'CredPivot 填充'; panel.referrerPolicy = 'no-referrer';
      // 账号候选属于扩展源，网页不能读取面板 DOM；地址中只有短期、绑定文档的操作标识。
      panel.src = `${chrome.runtime.getURL('inline.html')}#${token}`;
      shadow.append(panel);
      observer.observe(document.documentElement,{childList:true,subtree:true});
      position();
      panelTimer = setTimeout(() => {
        if (!token) return;
        closePanel();
        showFailure('此网站未能显示填充面板，请再次点击图标重试，或使用浏览器工具栏中的 CredPivot 插件。');
      },5000);
      return {ok:true};
    } catch (error) {
      if (generation !== current) return {ok:false};
      closePanel();
      showFailure(error?.message);
      return {ok:false,message:inlineFailure};
    }
    finally { clearTimeout(openTimer); if (generation === current) opening = false; }
  }
  function context(message) {
    const target = message.target_id ? targets.get(message.target_id) : (valid(anchor) ? anchor : bind(lastInput));
    return {documentId, origin:location.origin, url:location.href, frameId:0, content_version:version,
      // 仅报告入口状态，不包含输入值、账号信息或网页异常原文。
      inline_status:{hidden, error:inlineFailure, target_kind:valid(target) ? target.kind : null},
      panelToken:panel?.isConnected ? token : null,
      targetId:valid(target) ? target.id : null, targetKind:valid(target) ? target.kind : null,
      targetValid:message.target_id ? Boolean(valid(target)) : true};
  }
  function selectMfaRegion() {
    if (regionTask) return regionTask;
    regionTask = new Promise((resolve) => {
      const overlay = document.createElement('div');
      overlay.setAttribute('data-credpivot-region', '');
      for (const [property, value] of [['all', 'initial'], ['display', 'block'], ['position', 'fixed'], ['inset', '0'], ['z-index', '2147483647'], ['pointer-events', 'auto']]) {
        overlay.style.setProperty(property, value, 'important');
      }
      const root = overlay.attachShadow({mode: 'closed'});
      const style = document.createElement('style');
      style.textContent = '.shade{position:fixed;inset:0;cursor:crosshair;touch-action:none;background:rgba(0,0,0,.28)}.box{position:fixed;box-sizing:border-box;border:2px solid #fff;outline:1px solid #111;background:transparent;box-shadow:0 0 0 9999px rgba(0,0,0,.28)}.box[hidden]{display:none}.hint{position:fixed;top:16px;left:50%;transform:translateX(-50%);display:flex;gap:12px;align-items:center;padding:8px 10px 8px 14px;border-radius:10px;background:#1c1d27;color:#fff;font:13px/1.4 system-ui,sans-serif;box-shadow:0 6px 20px #0006}button{border:0;border-radius:8px;background:#fff;color:#1c1d27;font:600 13px system-ui,sans-serif;padding:6px 10px;cursor:pointer}';
      const shade = document.createElement('div');
      shade.className = 'shade';
      const box = document.createElement('div');
      box.className = 'box';
      box.hidden = true;
      const hint = document.createElement('div');
      hint.className = 'hint';
      const label = document.createElement('span');
      label.textContent = '拖动框选二维码区域，2 分钟后自动取消';
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.textContent = '取消';
      hint.append(label, cancel);
      root.append(style, shade, box, hint);
      document.documentElement.append(overlay);
      let start = null, done = false, timer = 0;
      const finish = (result) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        window.removeEventListener('keydown', onKey, true);
        overlay.remove();
        regionTask = null;
        regionFinish = null;
        // 先去掉遮罩再截图，避免把选框本身截进去。
        requestAnimationFrame(() => requestAnimationFrame(() => resolve(result)));
      };
      const onKey = (event) => {
        if (event.key !== 'Escape') return;
        event.preventDefault();
        event.stopPropagation();
        finish({ok: false, cancelled: true});
      };
      const place = (from, to) => {
        const x = Math.max(0, Math.min(from.x, to.x, window.innerWidth));
        const y = Math.max(0, Math.min(from.y, to.y, window.innerHeight));
        const right = Math.max(0, Math.min(Math.max(from.x, to.x), window.innerWidth));
        const bottom = Math.max(0, Math.min(Math.max(from.y, to.y), window.innerHeight));
        const rect = {x, y, width: Math.max(0, right - x), height: Math.max(0, bottom - y)};
        box.style.left = `${rect.x}px`;
        box.style.top = `${rect.y}px`;
        box.style.width = `${rect.width}px`;
        box.style.height = `${rect.height}px`;
        return rect;
      };
      window.addEventListener('keydown', onKey, true);
      timer = setTimeout(() => finish({ok: false, timedOut: true}), 120_000);
      cancel.addEventListener('pointerdown', (event) => event.stopPropagation());
      cancel.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        finish({ok: false, cancelled: true});
      });
      shade.addEventListener('pointerdown', (event) => {
        if (event.button !== 0) return;
        event.preventDefault();
        shade.setPointerCapture(event.pointerId);
        start = {x: event.clientX, y: event.clientY};
        shade.style.background = 'transparent';
        box.hidden = false;
        place(start, start);
      });
      shade.addEventListener('pointermove', (event) => {
        if (start) place(start, {x: event.clientX, y: event.clientY});
      });
      shade.addEventListener('pointerup', (event) => {
        if (!start) return;
        const rect = place(start, {x: event.clientX, y: event.clientY});
        start = null;
        if (rect.width < 12 || rect.height < 12) {
          box.hidden = true;
          shade.style.background = 'rgba(0,0,0,.28)';
          label.textContent = '请拖出一个包含二维码的区域';
          return;
        }
        finish({ok: true, rect, viewportWidth: window.innerWidth, viewportHeight: window.innerHeight});
      });
      shade.addEventListener('pointercancel', () => { start = null; box.hidden = true; shade.style.background = 'rgba(0,0,0,.28)'; });
      regionFinish = finish;
    });
    return regionTask;
  }
  function onMessage(msg, _sender, respond) {
    if (msg.type === 'mfa_select_region') { selectMfaRegion().then(respond); return true; }
    if (msg.type === 'mfa_select_cancel') { regionFinish?.({ok: false, cancelled: true}); respond({ok: true}); return; }
    if (msg.type === 'fill_context') { respond(context(msg)); return; }
    if (msg.type === 'inline_menu_context') {
      const target = bind(contextInput, msg.mode);
      respond({...context({target_id:target?.id}), menuTarget:target?.id || null}); return;
    }
    if (msg.type === 'inline_show' && msg.document_id === documentId) {
      const target = targets.get(msg.target_id);
      if (!valid(target)) { respond({ok:false}); return; }
      open(target, true).then(respond); return true;
    }
    if (msg.type === 'inline_close' && msg.token === token) {
      closePanel(false); if (hidden) hideBadge(); respond({ok:true}); return;
    }
    if (msg.type === 'inline_ready' && msg.token === token) {
      clearTimeout(panelTimer); panelTimer = null; badge.title = 'CredPivot：点击关闭填充面板';
      respond({ok:true}); return;
    }
    if (msg.type === 'inline_feedback' && msg.token === token) {
      clearTimeout(panelTimer); panelTimer = null;
      if (msg.message) showFailure(msg.message);
      else {
        inlineFailure = ''; clearTimeout(noticeTimer); if (notice) notice.hidden = true;
        badge.textContent = 'CP'; badge.title = 'CredPivot：点击关闭填充面板';
        badge.setAttribute('aria-label','使用 CredPivot 填充');
      }
      respond({ok:true}); return;
    }
    if (msg.type === 'inline_preference') {
      hidden = msg.hidden === true;
      if (hidden) { closePanel(); hideBadge(); }
      else { const target = bind(lastInput); if (target) showBadge(target); }
      respond({ok:true}); return;
    }
    if (msg.type === 'page_notice' && msg.message) {
      ensureHost();
      showFailure(String(msg.message));
      respond({ok:true}); return;
    }
    if (msg.type === 'capture_login') {
      const {user,pass} = loginFields(true,bind(lastInput));
      respond({documentId,origin:location.origin,username:user?.value ?? '',password:pass?.value ?? ''});
      return;
    }
    if (msg.type !== 'deliver_secret') return;
    if (msg.document_id !== documentId || msg.origin !== location.origin || (msg.url && msg.url !== location.href)) {
      respond({filled:false,reason:'document_mismatch'}); return;
    }
    const target = msg.target_id ? targets.get(msg.target_id) : null;
    if (msg.target_id && !valid(target)) { respond({filled:false,reason:'target_changed'}); return; }
    delivering = true;
    try {
    if (msg.mode === 'otp') { const ok = fillOtp(msg.totp_code,target); respond({filled:ok,otp_filled:ok,reason:ok ? undefined : 'no_otp_field'}); return; }
    const {user,pass} = loginFields(false,target);
    const usernameFilled = Boolean(msg.username && setValue(user,msg.username));
    const passwordFilled = Boolean(msg.password && setValue(pass,msg.password));
    const otpFilled = msg.mode === 'all' && Boolean(fillOtp(msg.totp_code,target));
    respond({filled:usernameFilled || passwordFilled || otpFilled,login_filled:usernameFilled || passwordFilled,
      username_filled:usernameFilled,password_filled:passwordFilled,otp_filled:otpFilled,
      partial:Boolean((msg.username && !usernameFilled) || (msg.password && !passwordFilled)),
      reason:usernameFilled || passwordFilled || otpFilled ? undefined : 'no_login_fields'});
    } finally {
      if (Object.hasOwn(msg, 'password')) msg.password = '';
      if (Object.hasOwn(msg, 'username')) msg.username = '';
      if (Object.hasOwn(msg, 'totp_code')) msg.totp_code = '';
      delivering = false;
    }
  }
  chrome.runtime.onMessage.addListener(onMessage);
  listen(document,'focusin',(event) => {
    if (delivering || !event.isTrusted || event.composedPath().includes(host)) return;
    const input = event.composedPath().find((el) => el instanceof HTMLInputElement);
    const target = bind(input);
    if (target) { lastInput = input; showBadge(target); }
    else { closePanel(); hideBadge(); }
  },true);
  listen(document,'contextmenu',(event) => {
    if (event.isTrusted) contextInput = event.composedPath().find((el) => el instanceof HTMLInputElement) || null;
  },true);
  listen(document,'pointerdown',(event) => {
    if (event.isTrusted && panel && !event.composedPath().includes(host)) closePanel();
    if (!delivering && event.isTrusted && !event.composedPath().includes(host)) {
      const input = event.composedPath().find((el) => el instanceof HTMLInputElement);
      const target = bind(input);
      if (target) { lastInput = input; showBadge(target); }
    }
  },true);
  listen(document,'keydown',(event) => { if (event.isTrusted && event.key === 'Escape') closePanel(); },true);
  listen(window,'scroll',schedulePosition,true);
  listen(window,'resize',schedulePosition);
  listen(window,'pagehide',() => { regionFinish?.({ok: false, cancelled: true}); closePanel(); hideBadge(); targets.clear(); });
  listen(window,'pageshow',(event) => {
    if (!event.isTrusted) return;
    // BFCache 返回沿用旧脚本，不会再次执行 document_idle；恢复当前输入框的入口即可。
    let input = document.activeElement;
    while (input?.shadowRoot?.activeElement) input = input.shadowRoot.activeElement;
    const target = bind(input);
    if (target) { lastInput = input; showBadge(target); }
  });
  void runtimeMessage({type:'inline_site_state'}).then((response) => { hidden = response?.hidden === true; if (hidden) { closePanel(); hideBadge(); } }).catch(() => {});
  // document_idle 时页面可能已 autofocus；只显示入口，不因此读取候选或触发验证。
  let initial = document.activeElement;
  while (initial?.shadowRoot?.activeElement) initial = initial.shadowRoot.activeElement;
  const initialTarget = bind(initial);
  if (initialTarget) { lastInput = initial; showBadge(initialTarget); }
  globalThis.__credpivotContentReady = true;
  globalThis.__credpivotContentVersion = version;
  globalThis.__credpivotContentCleanup = () => {
    regionFinish?.({ok: false, cancelled: true});
    closePanel(); observer?.disconnect(); if (frame) cancelAnimationFrame(frame);
    for (const remove of listeners) remove();
    try { chrome.runtime.onMessage.removeListener(onMessage); } catch (_) { /* 扩展更新后旧监听可能已经失效。 */ }
    host?.remove(); targets.clear();
  };
})();
