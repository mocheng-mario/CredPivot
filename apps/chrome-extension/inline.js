const $ = (id) => document.getElementById(id);
const token = location.hash.slice(1);
let tabId, metadata = null, busy = false, invalid = false;
function status(message, kind = '') { $('status').textContent = message; $('status').className = kind; }
function setBusy(value) {
  busy = value;
  for (const button of document.querySelectorAll('button:not(#close)')) button.disabled = value || invalid;
  $('account').disabled = value || invalid;
  $('search').disabled = value || invalid;
}
async function request(type, values = {}) {
  const response = await chrome.runtime.sendMessage({type,token,tab_id:tabId,...values});
  if (!response?.ok) throw Object.assign(new Error(response?.message || '本机连接中断，请关闭面板后重试'),{code:response?.code});
  return response;
}
function renderList() {
  $('list').replaceChildren();
  const query = $('search').value.toLocaleLowerCase();
  const rows = (metadata?.candidates || []).filter((row) =>
    `${row.display_name || ''} ${row.username || ''} ${row.issuer || ''} ${row.account || ''} ${row.partition_name || ''}`.toLocaleLowerCase().includes(query));
  for (const row of rows) {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'candidate';
    if (row.id === metadata.selected_id) button.classList.add('selected');
    const title = document.createElement('strong');
    title.textContent = metadata.mode === 'login' ? row.username || row.display_name || '无用户名账号' : `${row.issuer || 'MFA'} · ${row.account || '无账号标签'}`;
    const detail = document.createElement('small');
    detail.textContent = [row.id === metadata.selected_id ? '已选记录' : '',row.partition_name,metadata.mode === 'login' ? row.display_name :
      `${row.linked ? '账号关联' : '独立匹配'} · ${['精确网站','通配规则','正则规则'][row.match_rank] || '网站匹配'}`].filter(Boolean).join(' · ');
    button.append(title,detail);
    button.addEventListener('click',(event) => { if (event.isTrusted) void perform('inline_fill',{candidate_id:row.id}); });
    $('list').append(button);
  }
  if (!rows.length) {
    const text = document.createElement('p'); text.textContent = query ? '没有匹配的候选记录' : '此网站暂无可用记录，请在 App 中配置匹配网站。';
    $('list').append(text);
  }
  setBusy(busy);
}
function render(response) {
  if (response.filled) {
    $('choices').hidden = true; $('connect').hidden = true; $('retry').hidden = true; $('hide').hidden = true;
    status(response.message,response.partial ? '' : 'success');
    // 收到完整填充成功的结果后立即关闭；失败或部分填充继续保留说明。
    if (!response.partial) void request('inline_cancel').catch(() => {});
    return;
  }
  metadata = response;
  $('site').textContent = response.origin;
  $('choices').hidden = false;
  $('connect').hidden = true;
  $('retry').hidden = true;
  // 唯一登录账号也能切到独立 MFA，不能因此把其他分区的验证器隐藏。
  const chooseAccount = response.mode === 'otp' && response.accounts.length > 0;
  $('account').hidden = !chooseAccount; $('accountLabel').hidden = !chooseAccount;
  $('account').replaceChildren();
  const none = document.createElement('option'); none.value = ''; none.textContent = '不关联登录账号，选择独立 MFA'; $('account').append(none);
  for (const row of response.accounts) {
    const option = document.createElement('option'); option.value = row.id;
    option.textContent = `${row.partition_name ? `[${row.partition_name}] ` : ''}${row.username || row.display_name || '无用户名账号'}`;
    $('account').append(option);
  }
  $('account').value = response.account_id || '';
  $('more').hidden = !response.more;
  status(response.mode === 'otp' ? '选择本次使用的 MFA；验证码仅在点击后读取。' : '选择要填充的账号。');
  renderList();
}
async function perform(type, values = {}) {
  if (busy || invalid) return;
  setBusy(true); $('retry').hidden = true;
  status(type === 'inline_fill' ? '正在填充；验证码临近过期时会等待下一组…' : type === 'inline_connect' || values.automatic === true
    ? '正在发起验证，请完成系统指纹或主密码验证。可关闭面板取消。' : '正在检查连接并读取候选…');
  try { render(await request(type,values)); }
  catch (error) {
    const needsVerification = ['extension_gate_required','extension_gate_cancelled','extension_gate_paused'].includes(error.code);
    status(error.message,['extension_gate_required','extension_gate_paused'].includes(error.code) ? '' : 'error'); $('choices').hidden = true;
    $('connect').hidden = invalid;
    $('connect').textContent = error.code === 'extension_gate_cancelled' ? '重新连接并验证' : '连接与验证';
    $('retry').hidden = invalid || needsVerification;
  }
  finally { setBusy(false); }
}
$('search').addEventListener('input',renderList);
$('account').addEventListener('change',(event) => { if (event.isTrusted) void perform('inline_account',{credential_id:$('account').value}); });
$('more').addEventListener('click',(event) => { if (event.isTrusted) void perform('inline_more'); });
$('connect').addEventListener('click',(event) => { if (event.isTrusted) void perform('inline_connect'); });
$('retry').addEventListener('click',(event) => { if (event.isTrusted) void perform('inline_load'); });
$('hide').addEventListener('click',(event) => { if (event.isTrusted) void perform('inline_hide_site'); });
$('close').addEventListener('click',(event) => { if (event.isTrusted) void request('inline_cancel').catch(() => { status('请点击网页空白处关闭面板'); }); });
document.addEventListener('keydown',(event) => { if (event.isTrusted && event.key === 'Escape') void request('inline_cancel').catch(() => {}); });
const heartbeat = setInterval(() => {
  if (!tabId || invalid) return;
  request('inline_ping').catch(() => {
    invalid = true; setBusy(false); $('connect').hidden = true; $('retry').hidden = true;
    status('页面、输入框或连接已改变，请关闭面板后重新点击填充图标。','error');
  });
},20_000);
window.addEventListener('pagehide',() => { clearInterval(heartbeat); });
(async () => {
  try {
    const tab = await chrome.tabs.getCurrent(); tabId = tab?.id;
    if (!tabId || !/^[0-9a-f-]{36}$/.test(token)) throw new Error('请从网页输入框或右键菜单打开此面板');
    const info = await request('inline_ping');
    $('site').textContent = info.origin;
    await perform('inline_load',{automatic:true});
  } catch (error) { invalid = true; setBusy(false); status(error.message,'error'); }
})();
