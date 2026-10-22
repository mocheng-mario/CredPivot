import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'agent_bridge.dart';
import 'vault_tools.dart';
import 'website_rules_editor.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';
import 'credential_group_ui.dart';
import 'credential_list_tile.dart';
import 'linked_refs.dart';
import 'credential_otpauth.dart';
import 'server_login_page.dart';
import 'touch_id_gate.dart';

Future<void> _showTextRevealDialog(
  BuildContext context, {
  required String title,
  required String body,
  bool allowCopy = true,
  bool touchIdToCopy = false,
  String touchIdCopyReason = '复制敏感内容',
}) async {
  await showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(title),
      content: SelectableText(body),
      actions: [
        if (allowCopy)
          TextButton(
            onPressed: () async {
              if (touchIdToCopy) {
                if (!await requireTouchId(ctx, reason: touchIdCopyReason)) return;
              }
              await AgentBridge.copyConcealed(body);
              if (ctx.mounted) {
                ScaffoldMessenger.of(ctx).showSnackBar(
                  const SnackBar(content: LText('已复制，将按设置自动清除剪贴板')),
                );
              }
            },
            child: const LText('复制'),
          ),
        FilledButton(onPressed: () => Navigator.pop(ctx), child: const LText('关闭')),
      ],
    ),
  );
}

/// 凭据 Tab：登录 / MFA / SSH 分栏，均可手动添加。
class CredentialsTab extends StatelessWidget {
  const CredentialsTab({super.key, required this.unlocked, this.onUnlock});

  final bool unlocked;
  final VoidCallback? onUnlock;

  @override
  Widget build(BuildContext context) {
    if (!unlocked) {
      return AppEmptyState(
        icon: Icons.lock_outline_rounded,
        title: '解锁后查看凭据',
        message: '登录密码、验证码、SSH 密钥与服务器配置都保存在保险库中。',
        action: FilledButton.icon(
            onPressed: onUnlock,
            icon: const Icon(Icons.lock_open_rounded),
            label: const LText('前往解锁')),
      );
    }
    return DefaultTabController(
      length: 5,
      child: Column(
        children: [
          Container(
            margin: const EdgeInsets.fromLTRB(24, 4, 24, 8),
            padding: const EdgeInsets.all(4),
            decoration: BoxDecoration(
                color: AppColors.sidebar,
                borderRadius: BorderRadius.circular(12)),
            child: const TabBar(
              isScrollable: true,
              tabAlignment: TabAlignment.start,
              splashBorderRadius: BorderRadius.all(Radius.circular(9)),
              tabs: [
                Tab(child: LText('登录密码')),
                Tab(child: LText('MFA / TOTP')),
                Tab(child: LText('SSH 密钥')),
                Tab(child: LText('服务器')),
                Tab(child: LText('笔记 / 管理')),
              ],
            ),
          ),
          Expanded(
            child: TabBarView(
              children: [
                _LoginPasswordPanel(),
                _TotpPanel(),
                _SshKeysPanel(),
                const ServerLoginPanel(),
                const VaultToolsPanel(),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _LoginPasswordPanel extends StatefulWidget {
  @override
  State<_LoginPasswordPanel> createState() => _LoginPasswordPanelState();
}

class _LoginPasswordPanelState extends State<_LoginPasswordPanel> {
  final _search = TextEditingController();
  List<Map<String, dynamic>> _items = [];
  List<Map<String, dynamic>> _groups = [];
  String? _filterGroupId;
  Map<String, dynamic>? _selected;
  String _status = '';
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  Future<void> _refresh() async {
    if (!mounted) return;
    setState(() => _busy = true);
    try {
      final q = _search.text.trim();
      final items = await AgentBridge.listCredentials(q.isEmpty ? null : q);
      final groups = await loadCredentialGroups('login');
      if (!mounted) return;
      final selectedId = _selected?['id'];
      _items = items;
      _groups = groups;
      // 刷新后使用当前版本，避免连续编辑仍携带上一次的 revision。
      _selected = null;
      for (final row in _items) {
        if (row['id'] == selectedId) {
          _selected = row;
          break;
        }
      }
      _filterGroupId = dropdownValueIfPresent(_filterGroupId, _groups);
      _status = '';
    } on AgentException catch (e) {
      _status = AgentBridge.friendlyMessage(e);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _addOrEdit({Map<String, dynamic>? existing}) async {
    final isEdit = existing != null;
    List<Map<String, dynamic>> totps = [];
    try {
      totps = await AgentBridge.listTotp();
    } on AgentException catch (e) {
      setState(() => _status = AgentBridge.friendlyMessage(e));
      return;
    }
    List<Map<String, dynamic>> websiteRules = [{'uri': '', 'match_mode': 'exact_origin'}];
    if (isEdit) {
      try {
        final result = await AgentBridge.manage({'action': 'login_website_rules', 'credential_id': existing!['id']});
        websiteRules = (result['rules'] as List).map((row) => Map<String, dynamic>.from(row as Map)).toList();
      } on AgentException catch (e) {
        if (mounted) setState(() => _status = e.message);
        return;
      }
    }
    if (!mounted) return;
    var validating = false;
    var formError = '';
    final nameCtl = TextEditingController(text: existing?['display_name']?.toString() ?? '');
    final userCtl = TextEditingController(text: existing?['username']?.toString() ?? '');
    final passCtl = TextEditingController();
    final rawGroupId = existing?['group_id'] as String?;
    var groupId = dropdownValueIfPresent(rawGroupId, _groups);
    final rawTotp = existing?['linked_totp_id'] as String?;
    var linkedTotp = dropdownValueIfPresent(rawTotp, totps);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
        title: LText(isEdit ? '编辑登录' : '添加登录'),
        content: SizedBox(width: appEditDialogWidth(ctx), child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: appFormFields([
              TextField(
                controller: nameCtl,
                decoration: InputDecoration(labelText: tr('名称'), hintText: tr('例如：公司 VPN 账号')),
              ),
              DropdownButtonFormField<String?>(
                isExpanded: true,
                value: groupId,
                decoration: InputDecoration(labelText: tr('分组')),
                items: [
                  const DropdownMenuItem(value: null, child: LText('（未分组）')),
                  ..._groups.map(
                    (g) => DropdownMenuItem(
                      value: g['id'] as String,
                      child: Text(
                        g['name']?.toString() ?? '',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ),
                ],
                onChanged: (v) => setLocal(() => groupId = v),
              ),
              TextField(controller: userCtl, decoration: InputDecoration(labelText: tr('用户名'))),
              TextField(
                controller: passCtl,
                obscureText: true,
                decoration: InputDecoration(
                  labelText: tr(isEdit ? '候选密码（留空则不修改）' : '密码'),
                  helperText: isEdit ? tr('确认在网站应用后，从「候选与历史」启用') : null,
                  suffixIcon: IconButton(tooltip: tr('生成密码'), icon: const Icon(Icons.auto_awesome), onPressed: () async {
                    final generated = await generatePasswordDialog(context); if (generated != null) passCtl.text = generated;
                  }),
                ),
              ),
              DropdownButtonFormField<String?>(
                isExpanded: true,
                value: linkedTotp,
                decoration: InputDecoration(
                  labelText: tr('关联 MFA / TOTP'),
                  helperText: tr('浏览器扩展「填充 MFA」需要在此关联'),
                ),
                items: [
                  const DropdownMenuItem(value: null, child: LText('（不关联）')),
                  ...totps.map(
                    (t) => DropdownMenuItem(
                      value: t['id'] as String,
                      child: LText(
                        '${t['issuer']} : ${t['account']}',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ),
                ],
                onChanged: (v) => setLocal(() => linkedTotp = v),
              ),
              WebsiteRulesEditor(rules: websiteRules, enabled: !validating),
              if (formError.isNotEmpty) Text(formError, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
            ]),
          ),
        )),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('取消')),
          FilledButton(onPressed: validating ? null : () async {
            setLocal(() { validating = true; formError = ''; });
            try {
              final error = await websiteRulesError(websiteRules);
              if (!ctx.mounted) return;
              if (error == null) { Navigator.pop(ctx, true); return; }
              setLocal(() => formError = error);
            } catch (_) {
              if (ctx.mounted) setLocal(() => formError = '网站规则校验失败，请重试');
            } finally {
              if (ctx.mounted) setLocal(() => validating = false);
            }
          }, child: LText(validating ? '校验中…' : '保存')),
        ],
      ),
      ),
    );
    if (ok != true) {
      for (final controller in [nameCtl, userCtl, passCtl]) { controller.dispose(); }
      return;
    }
    if (isEdit) {
      if (!await requireTouchId(context, reason: '保存登录凭据修改')) {
        for (final controller in [nameCtl, userCtl, passCtl]) { controller.dispose(); }
        return;
      }
    }
    if (staleLinkWasCleared(rawTotp, linkedTotp) && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: LText('关联的 MFA 已删除，保存后将清除该关联。')),
      );
    }
    try {
      final origin = websiteRules.first['uri'].toString().trim();
      final user = userCtl.text.trim();
      final displayName = nameCtl.text.trim();
      if (isEdit) {
        await AgentBridge.updateLogin(
          credentialId: existing!['id'] as String,
          expectedRevision: existing['current_revision'] as String,
          origin: origin,
          websiteRules: websiteRules,
          username: user,
          displayName: displayName,
          groupId: groupId,
          connectionHost: existing['connection_host']?.toString() ?? '',
          linkedTotpId: linkedTotp,
          password: passCtl.text.isEmpty ? null : passCtl.text,
        );
      } else {
        await AgentBridge.createLogin(
          origin: origin,
          websiteRules: websiteRules,
          username: user,
          password: passCtl.text,
          displayName: displayName,
          groupId: groupId,
          linkedTotpId: linkedTotp,
        );
      }
      await _refresh();
    } on AgentException catch (e) {
      if (mounted) setState(() => _status = e.message);
    } finally {
      for (final controller in [nameCtl, userCtl, passCtl]) { controller.dispose(); }
    }
  }

  Future<void> _copyPassword(String id) async {
    if (!await requireTouchId(context, reason: '复制登录密码')) return;
    final detail = await AgentBridge.getCredential(id);
    await AgentBridge.copyConcealed(detail['password'] as String? ?? '');
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('密码已复制，将按设置自动清除剪贴板')));
    }
  }

  @override
  Widget build(BuildContext context) {
    final visibleItems = _items
        .where((row) =>
            _filterGroupId == null || row['group_id'] == _filterGroupId)
        .toList();
    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 12, 24, 20),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        AppSectionHeader(
          title: '登录密码',
          subtitle: '${visibleItems.length} 条登录凭据',
          action: FilledButton.icon(
              onPressed: _busy ? null : () => _addOrEdit(),
              icon: const Icon(Icons.add_rounded),
              label: const LText('添加登录项')),
        ),
        Row(children: [
          Expanded(
              child: TextField(
            controller: _search,
            decoration: InputDecoration(
                hintText: tr('搜索网站、名称或用户名，按回车确认'),
                prefixIcon: Icon(Icons.search_rounded)),
            onSubmitted: (_) => _refresh(),
          )),
          const SizedBox(width: 8),
          IconButton(
              onPressed: _busy ? null : _refresh,
              tooltip: tr('刷新列表'),
              icon: const Icon(Icons.refresh_rounded)),
        ]),
        if (_status.isNotEmpty) AppNotice(_status),
        buildGroupFilterBar(
          groups: _groups,
          selectedGroupId: _filterGroupId,
          onChanged: (v) => setState(() {
            _filterGroupId = v;
            _selected = null;
          }),
          onManage: () =>
              showManageGroupsDialog(context, 'login').then((_) => _refresh()),
        ),
        Expanded(
            child: CredentialWorkspace(
          list: visibleItems.isEmpty
              ? const AppEmptyState(
                  icon: Icons.key_outlined,
                  title: '没有匹配的登录项',
                  message: '添加新的登录项，或调整搜索条件与分组。')
              : ListView(
                  children: buildGroupedListTiles(
                  groups: _groups,
                  items: visibleItems,
                  tileBuilder: (row) {
                    final dn = row['display_name']?.toString() ?? '';
                    return selectableCredentialTile(
                      context: context,
                      selected: _selected?['id'] == row['id'],
                      title: Text(dn.isNotEmpty
                          ? dn
                          : (row['title']?.toString() ??
                              row['origin']?.toString() ??
                              '')),
                      subtitle: LText('${row['origin']} · ${row['username']}'),
                      onTap: () => setState(() => _selected = row),
                    );
                  },
                )),
          detail: _selected == null
              ? null
              : CredentialDetails(
                  title:
                      _selected!['display_name']?.toString().isNotEmpty == true
                          ? _selected!['display_name'].toString()
                          : (_selected!['title']?.toString() ??
                              _selected!['origin']?.toString() ??
                              '登录项'),
                  fields: {
                    '网站': _selected!['origin']?.toString() ?? '',
                    '用户名': _selected!['username']?.toString() ?? '',
                    '密码': '••••••••'
                  },
                ),
          actions: _selected == null
                ? null
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      CredentialActionSection(
                        title: '常用操作',
                        children: [
                          OutlinedButton(
                            onPressed: () {
                              final u = _selected!['username']?.toString() ?? '';
                              Clipboard.setData(ClipboardData(text: u));
                              ScaffoldMessenger.of(context).showSnackBar(
                                  const SnackBar(content: LText('用户名已复制')));
                            },
                            child: const LText('复制用户名'),
                          ),
                          OutlinedButton(
                            onPressed: () =>
                                _copyPassword(_selected!['id'] as String),
                            child: const LText('复制密码'),
                          ),
                        ],
                      ),
                      CredentialActionSection(
                        title: '密码维护',
                        children: [
                          OutlinedButton(onPressed: () async { await showPasswordVersions(context, _selected!); if (mounted) await _refresh(); }, child: const LText('候选与历史')),
                          OutlinedButton(onPressed: () async {
                            if (!await confirmVaultAction(context, '确认密码当前正在使用？', '将当前时间记录为启用时间；仅在确认此密码当前已生效时操作。')) return;
                            try { await vaultAction(context, {'action':'mark_password_active','credential_id':_selected!['id'],'expected_revision':_selected!['current_revision']}, confirmed: true); await _refresh(); } catch(e) { vaultMessage(context,e); }
                          }, child: const LText('确认启用时间')),
                        ],
                      ),
                      CredentialActionSection(
                        title: '资料管理',
                        children: [
                          OutlinedButton(
                            onPressed: () => _addOrEdit(existing: _selected),
                            child: const LText('编辑'),
                          ),
                          OutlinedButton(onPressed: () async { await editItemDetails(context, _selected!); if (mounted) await _refresh(); }, child: const LText('备注与策略')),
                        ],
                      ),
                      CredentialActionSection(
                        title: '危险操作',
                        dangerous: true,
                        children: [
                          OutlinedButton(
                            onPressed: () async {
                              final title = _selected!['title']?.toString() ??
                                  _selected!['origin']?.toString() ??
                                  '登录项';
                              if (!await confirmCredentialDanger(
                                context,
                                title: '删除登录密码',
                                message: '确定删除「$title」？可从「笔记 / 管理 → 回收站」恢复。',
                              )) {
                                return;
                              }
                              if (!await requireTouchId(context, reason: '删除登录密码', confirmed: true))
                                return;
                              final itemId = _selected!['item_id'] as String?;
                              if (itemId == null) return;
                              await AgentBridge.trashCredential(itemId);
                              _selected = null;
                              await _refresh();
                            },
                            child: const LText('删除'),
                          ),
                        ],
                      ),
                    ],
                  ),
        )),
      ]),
    );
  }
}

class _TotpPanel extends StatefulWidget {
  @override
  State<_TotpPanel> createState() => _TotpPanelState();
}

class _TotpPanelState extends State<_TotpPanel> {
  List<Map<String, dynamic>> _items = [];
  List<Map<String, dynamic>> _groups = [];
  String? _filterGroupId;
  Map<String, dynamic>? _selected;
  String _status = '';
  String? _liveCode;
  String? _liveCodeForId;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    try {
      _items = await AgentBridge.listTotp();
      _groups = await loadCredentialGroups('totp');
      _filterGroupId = dropdownValueIfPresent(_filterGroupId, _groups);
      _status = '';
      setState(() {});
    } on AgentException catch (e) {
      setState(() => _status = e.message);
    }
  }

  void _applyOtpauthUri(
    String input,
    TextEditingController issuerCtl,
    TextEditingController accountCtl,
    TextEditingController secretCtl,
  ) {
    final parsed = parseOtpauthUri(input);
    if (parsed == null) return;
    if (parsed.secret.isNotEmpty) secretCtl.text = parsed.secret;
    if (parsed.issuer.isNotEmpty) issuerCtl.text = parsed.issuer;
    if (parsed.account.isNotEmpty) accountCtl.text = parsed.account;
  }

  Future<void> _addTotp() async {
    final issuerCtl = TextEditingController();
    final accountCtl = TextEditingController();
    final secretCtl = TextEditingController();
    final uriCtl = TextEditingController();
    var groupId = dropdownValueIfPresent(_filterGroupId, _groups);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
        title: const LText('添加 MFA / TOTP'),
        content: SizedBox(width: appEditDialogWidth(ctx), child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: appFormFields([
              DropdownButtonFormField<String?>(
                isExpanded: true,
                value: groupId,
                decoration: InputDecoration(labelText: tr('分组')),
                items: [
                  const DropdownMenuItem(value: null, child: LText('（未分组）')),
                  ..._groups.map(
                    (g) => DropdownMenuItem(
                      value: g['id'] as String,
                      child: Text(
                        g['name']?.toString() ?? '',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ),
                ],
                onChanged: (v) => setLocal(() => groupId = v),
              ),
              TextButton.icon(onPressed: () async {
                try { final uris = await AgentBridge.scanQrImage();
                  if (!ctx.mounted) return;
                  if (uris.isEmpty) { vaultMessage(context, AgentException('qr','图片中没有找到 TOTP 二维码')); return; }
                  String? selected = uris.first;
                  if (uris.length > 1) { selected = await showDialog<String>(context: ctx, builder:(c)=>SimpleDialog(title: const LText('选择二维码'), children:[for(var n=0;n<uris.length;n++) SimpleDialogOption(onPressed:()=>Navigator.pop(c,uris[n]),child:LText('TOTP 二维码 ${n+1}'))])); }
                  if (selected != null) { uriCtl.text = selected; _applyOtpauthUri(selected, issuerCtl, accountCtl, secretCtl); }
                } catch(e) { vaultMessage(context,e); }
              }, icon: const Icon(Icons.qr_code_scanner), label: const LText('从二维码图片导入')),
              TextField(
                controller: uriCtl,
                decoration: InputDecoration(
                  labelText: tr('otpauth URI（可选）'),
                  hintText: 'otpauth://totp/...',
                ),
                onChanged: (v) => _applyOtpauthUri(v, issuerCtl, accountCtl, secretCtl),
              ),
              TextField(controller: issuerCtl, decoration: InputDecoration(labelText: tr('发行方 Issuer'))),
              TextField(controller: accountCtl, decoration: InputDecoration(labelText: tr('账号'))),
              TextField(
                controller: secretCtl,
                decoration: InputDecoration(labelText: tr('密钥 Base32')),
                onChanged: (value) {
                  if (value.trim().toLowerCase().startsWith('otpauth://')) {
                    uriCtl.text = value.trim();
                    _applyOtpauthUri(value.trim(), issuerCtl, accountCtl, secretCtl);
                    return;
                  }
                  final uri = Uri.tryParse(uriCtl.text.trim());
                  if (uri?.scheme == 'otpauth') {
                    uriCtl.text = uri!.replace(queryParameters: {...uri.queryParameters, 'secret': value.trim()}).toString();
                  }
                },
              ),
            ]),
          ),
        )),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('取消')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const LText('保存')),
        ],
      ),
      ),
    );
    if (ok != true) return;
    final rawSecret = secretCtl.text.trim();
    if (rawSecret.toLowerCase().startsWith('otpauth://')) {
      _applyOtpauthUri(rawSecret, issuerCtl, accountCtl, secretCtl);
    }
    if (uriCtl.text.trim().toLowerCase().startsWith('otpauth://')) {
      _applyOtpauthUri(uriCtl.text.trim(), issuerCtl, accountCtl, secretCtl);
    }
    final uriInput = uriCtl.text.trim();
    final secret = secretCtl.text.trim();
    final storageInput =
        uriInput.toLowerCase().startsWith('otpauth://') ? uriInput : secret;
    final localErr = validateTotpSecretInput(storageInput);
    if (localErr != null) {
      setState(() => _status = localErr);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(localErr)));
      }
      return;
    }
    try {
      await AgentBridge.createTotp(
        issuer: issuerCtl.text.trim().isEmpty ? 'CredPivot' : issuerCtl.text.trim(),
        account: accountCtl.text.trim(),
        secretBase32: storageInput,
        groupId: groupId,
      );
      await _refresh();
    } on AgentException catch (e) {
      final msg = AgentBridge.friendlyMessage(e);
      setState(() => _status = msg);
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
    }
  }

  Future<void> _copyCode(String id) => copyTotpCode(context, id);
  Future<void> _showCode(String id) => showTotpStatus(context, id);

  Future<Map<String, dynamic>?> _revealAfterTouchId(String reason) async {
    final id = _selected?['id'] as String?;
    if (id == null) return null;
    if (!await requireTouchId(context, reason: reason)) return null;
    try {
      return await AgentBridge.totpReveal(id);
    } on AgentException catch (e) {
      setState(() => _status = AgentBridge.friendlyMessage(e));
      return null;
    }
  }

  Future<void> _showQrCode() async {
    final reveal = await _revealAfterTouchId('生成 MFA 二维码');
    if (reveal == null || !mounted) return;
    final uri = reveal['otpauth_uri'] as String? ?? '';
    if (uri.isEmpty) return;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: LText('${reveal['issuer']} : ${reveal['account']}'),
        content: SizedBox(
          width: 260,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              QrImageView(data: uri, size: 220, backgroundColor: Colors.white),
              const SizedBox(height: 8),
              LText('扫码后可在其他设备添加同一 MFA', style: Theme.of(ctx).textTheme.bodySmall),
            ],
          ),
        ),
        actions: [
          FilledButton(onPressed: () => Navigator.pop(ctx), child: const LText('关闭')),
        ],
      ),
    );
  }

  Future<void> _showOtpauthUri() async {
    final reveal = await _revealAfterTouchId('查看 MFA otpauth URI');
    if (reveal == null || !mounted) return;
    await _showTextRevealDialog(
      context,
      title: 'otpauth URI',
      body: reveal['otpauth_uri'] as String? ?? '',
      touchIdToCopy: true,
      touchIdCopyReason: '复制 MFA otpauth URI',
    );
  }

  Future<void> _showSecret() async {
    final reveal = await _revealAfterTouchId('查看 MFA 密钥');
    if (reveal == null || !mounted) return;
    await _showTextRevealDialog(
      context,
      title: 'Base32 密钥',
      body: reveal['secret_base32'] as String? ?? '',
      touchIdToCopy: true,
      touchIdCopyReason: '复制 MFA 密钥',
    );
  }

  Future<void> _deleteTotp(Map<String, dynamic> row) async {
    if (!await confirmCredentialDanger(
      context,
      title: '删除 MFA / TOTP',
      message: '确定删除「${row['issuer']} : ${row['account']}」？',
    )) {
      return;
    }
    if (!await requireTouchId(context, reason: '删除 MFA / TOTP', confirmed: true)) return;
    final itemId = row['item_id'] as String?;
    if (itemId == null) return;
    try {
      await AgentBridge.trashCredential(itemId);
      if (_liveCodeForId == row['id']) {
        _liveCode = null;
        _liveCodeForId = null;
      }
      await _refresh();
    } on AgentException catch (e) {
      setState(() => _status = e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    final visibleItems = _items
        .where((row) =>
            _filterGroupId == null || row['group_id'] == _filterGroupId)
        .toList();
    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 12, 24, 20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          AppSectionHeader(
            title: '动态验证码',
            subtitle: '${visibleItems.length} 个验证器',
            action: FilledButton.icon(
                onPressed: _addTotp,
                icon: const Icon(Icons.add_rounded),
                label: const LText('添加 TOTP')),
          ),
          if (_status.isNotEmpty) AppNotice(_status),
          buildGroupFilterBar(
            groups: _groups,
            selectedGroupId: _filterGroupId,
            onChanged: (v) => setState(() {
              _filterGroupId = v;
              _selected = null;
              _liveCode = null;
              _liveCodeForId = null;
            }),
            onManage: () =>
                showManageGroupsDialog(context, 'totp').then((_) => _refresh()),
          ),
          if (_liveCode != null)
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Row(
                  children: [
                    LText('当前验证码：$_liveCode',
                        style: Theme.of(context).textTheme.titleLarge),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.copy),
                      onPressed: () async {
                        await AgentBridge.copyConcealed(_liveCode!);
                        if (!mounted) return;
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: LText('验证码已复制，将按设置自动清除剪贴板')),
                        );
                      },
                    ),
                  ],
                ),
              ),
            ),
          Expanded(
              child: CredentialWorkspace(
            list: visibleItems.isEmpty
                ? const AppEmptyState(
                    icon: Icons.pin_outlined,
                    title: '没有匹配的验证码',
                    message: '添加 TOTP，或选择其他分组。')
                : ListView(
                    children: buildGroupedListTiles(
                      groups: _groups,
                      items: visibleItems,
                      tileBuilder: (row) {
                        final selected = _selected?['id'] == row['id'];
                        return selectableCredentialTile(
                          context: context,
                          selected: selected,
                          icon: Icons.pin_outlined,
                          title: Text(row['issuer']?.toString() ?? 'TOTP'),
                          subtitle: Text(row['account']?.toString() ?? ''),
                          onTap: () => setState(() {
                            _selected = row;
                            _liveCode = null;
                            _liveCodeForId = null;
                          }),
                        );
                      },
                    ),
                  ),
            detail: _selected == null
                ? null
                : CredentialDetails(
                    title: '${_selected!['issuer']} : ${_selected!['account']}',
                    icon: Icons.pin_outlined,
                    fields: {
                      '发行方': _selected!['issuer']?.toString() ?? '',
                      '账户': _selected!['account']?.toString() ?? '',
                      '验证方式': 'TOTP 动态验证码'
                    },
                  ),
            actions: _selected == null
                ? null
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      CredentialActionSection(
                        title: '验证码',
                        children: [
                          FilledButton.tonal(
                            onPressed: () => _copyCode(_selected!['id'] as String),
                            child: const LText('复制验证码'),
                          ),
                          OutlinedButton(
                            onPressed: () => _showCode(_selected!['id'] as String),
                            child: LText(_liveCodeForId == _selected!['id']
                                ? '刷新显示'
                                : '显示验证码'),
                          ),
                        ],
                      ),
                      CredentialActionSection(
                        title: '密钥与迁移',
                        children: [
                          OutlinedButton(
                              onPressed: _showQrCode, child: const LText('二维码')),
                          OutlinedButton(
                              onPressed: _showOtpauthUri,
                              child: const LText('otpauth URI')),
                          OutlinedButton(
                              onPressed: _showSecret, child: const LText('密钥')),
                        ],
                      ),
                      CredentialActionSection(
                        title: '资料管理',
                        children: [
                          OutlinedButton(onPressed: () async { await editTotp(context, _selected!); if (mounted) await _refresh(); }, child: const LText('编辑')),
                          OutlinedButton(
                            onPressed: () {
                              final itemId = _selected!['item_id'] as String?;
                              if (itemId == null) return;
                              showMoveItemToGroupDialog(
                                context,
                                scope: 'totp',
                                itemId: itemId,
                                currentGroupId: _selected!['group_id'] as String?,
                              ).then((_) => _refresh());
                            },
                            child: const LText('移到分组'),
                          ),
                        ],
                      ),
                      CredentialActionSection(
                        title: '危险操作',
                        dangerous: true,
                        children: [
                          OutlinedButton(
                            onPressed: () => _deleteTotp(_selected!),
                            child: const LText('删除'),
                          ),
                        ],
                      ),
                    ],
                  ),
          )),
        ],
      ),
    );
  }
}

class _SshKeysPanel extends StatefulWidget {
  @override
  State<_SshKeysPanel> createState() => _SshKeysPanelState();
}

class _SshKeysPanelState extends State<_SshKeysPanel> {
  List<Map<String, dynamic>> _items = [];
  List<Map<String, dynamic>> _groups = [];
  String? _filterGroupId;
  Map<String, dynamic>? _selected;
  String _status = '';
  String _storagePath = '';
  String _agentSocket = '';
  bool _deleting = false;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    try {
      final response = await AgentBridge.request({'type': 'ssh_key_list'});
      final payload = AgentBridge.payloadOf(response);
      final items = (payload['items'] as List<dynamic>? ?? [])
          .map((item) => Map<String, dynamic>.from(item as Map)).toList();
      if (!mounted) return;
      final groups = await loadCredentialGroups('ssh');
      if (!mounted) return;
      Map<String, dynamic>? selected;
      for (final row in items) {
        if (row['id'] == _selected?['id']) selected = row;
      }
      setState(() {
        _items = items;
        _groups = groups;
        _selected = selected;
        _filterGroupId = dropdownValueIfPresent(_filterGroupId, groups);
        _storagePath = payload['storage_path']?.toString() ?? '';
        _agentSocket = payload['agent_socket']?.toString() ?? '';
        _status = '';
      });
    } on AgentException catch (e) {
      if (mounted) setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  Future<void> _generate() async {
    if (_deleting) return;
    final labelCtl = TextEditingController(text: 'Key ${_items.length + 1}');
    bool setDefault = _items.isEmpty;
    var groupId = dropdownValueIfPresent(_filterGroupId, _groups);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
          title: const LText('生成 SSH 密钥'),
          content: SizedBox(width: appEditDialogWidth(ctx), child: SingleChildScrollView(child: Column(
            mainAxisSize: MainAxisSize.min,
            children: appFormFields([
              DropdownButtonFormField<String?>(
                isExpanded: true,
                value: groupId,
                decoration: InputDecoration(labelText: tr('分组')),
                items: [
                  const DropdownMenuItem(value: null, child: LText('（未分组）')),
                  ..._groups.map(
                    (g) => DropdownMenuItem(
                      value: g['id'] as String,
                      child: Text(
                        g['name']?.toString() ?? '',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ),
                ],
                onChanged: (v) => setLocal(() => groupId = v),
              ),
              TextField(controller: labelCtl, decoration: InputDecoration(labelText: tr('标签'))),
              CheckboxListTile(
                value: setDefault,
                onChanged: (v) => setLocal(() => setDefault = v ?? false),
                title: const LText('设为默认（Agent 签名用）'),
                contentPadding: EdgeInsets.zero,
              ),
            ]),
          ))),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('取消')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const LText('生成')),
          ],
        ),
      ),
    );
    final label = labelCtl.text.trim();
    labelCtl.dispose();
    if (ok != true || !mounted) return;
    if (!await confirmCredentialDanger(
      context,
      title: '生成新 SSH 密钥',
      message: '将生成新的 Ed25519 密钥对。确认继续？',
      confirmLabel: '生成',
    )) {
      return;
    }
    if (!mounted) return;
    try {
      await AgentBridge.generateSshKey(
        label: label,
        setDefault: setDefault,
        groupId: groupId,
      );
      await _refresh();
    } on AgentException catch (e) {
      if (mounted) setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  void _copyPublicKey(Map<String, dynamic> row) {
    final pub = row['public_openssh']?.toString() ?? '';
    Clipboard.setData(ClipboardData(text: pub));
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('公钥已复制')));
  }

  Future<void> _delete(Map<String, dynamic> row) async {
    if (_deleting) return;
    final itemId = row['item_id'] as String?;
    if (itemId == null) return;
    setState(() => _deleting = true);
    try {
      if (!await confirmCredentialDanger(context,
          title: '删除 SSH 密钥',
          message: '删除「${row['label'] ?? 'SSH'}」？\n\n'
              '删除默认密钥时会由剩余密钥接替；没有剩余时暂停 SSH 签名。'
              '如需撤销服务器访问权限，还需移除服务器端公钥。')) return;
      if (!mounted || !await requireTouchId(context,
          reason: '删除 SSH 密钥', confirmed: true)) return;
      await AgentBridge.trashCredential(itemId);
      await _refresh();
      if (mounted) setState(() => _status = 'SSH 密钥已删除。历史备份中可能仍保留副本。');
    } on AgentException catch (e) {
      if (mounted) setState(() => _status = AgentBridge.friendlyMessage(e));
    } catch (_) {
      if (mounted) setState(() => _status = '删除未完成，请刷新后确认当前状态');
    } finally {
      if (mounted) setState(() => _deleting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final visibleItems = _items
        .where((row) =>
            _filterGroupId == null || row['group_id'] == _filterGroupId)
        .toList();
    return AbsorbPointer(
      absorbing: _deleting,
      child: Padding(
      padding: const EdgeInsets.fromLTRB(24, 12, 24, 20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          AppSectionHeader(
            title: 'SSH 密钥',
            subtitle: '${visibleItems.length} 对密钥',
            action: FilledButton.icon(
                onPressed: _generate,
                icon: const Icon(Icons.add_rounded),
                label: const LText('生成密钥')),
          ),
          TextButton.icon(onPressed: () async { await transferSshKey(context); if (mounted) await _refresh(); }, icon: const Icon(Icons.file_open_outlined), label: const LText('导入 OpenSSH 私钥')),
          if (_status.isNotEmpty) AppNotice(_status),
          if (_deleting) const LinearProgressIndicator(minHeight: 2),
          buildGroupFilterBar(
            groups: _groups,
            selectedGroupId: _filterGroupId,
            onChanged: (v) => setState(() {
              _filterGroupId = v;
              _selected = null;
            }),
            onManage: () =>
                showManageGroupsDialog(context, 'ssh').then((_) => _refresh()),
          ),
          Expanded(
              child: CredentialWorkspace(
            list: visibleItems.isEmpty
                ? const AppEmptyState(
                    icon: Icons.terminal_rounded,
                    title: '没有匹配的 SSH 密钥',
                    message: '生成新的密钥，或选择其他分组。')
                : ListView(
                    children: buildGroupedListTiles(
                      groups: _groups,
                      items: visibleItems,
                      tileBuilder: (row) {
                        final pub = row['public_openssh']?.toString() ?? '';
                        final selected = _selected?['id'] == row['id'];
                        return selectableCredentialTile(
                          context: context,
                          selected: selected,
                          icon: Icons.terminal_rounded,
                          title: Text(row['label']?.toString() ?? 'SSH'),
                          subtitle: Text(
                            pub.length > 48 ? '${pub.substring(0, 48)}…' : pub,
                            maxLines: 2,
                          ),
                          trailing: row['is_default'] == true
                              ? const Chip(label: LText('默认'))
                              : null,
                          onTap: () => setState(() => _selected = row),
                        );
                      },
                    ),
                  ),
            detail: _selected == null
                ? null
                : CredentialDetails(
                    title: _selected!['label']?.toString() ?? 'SSH',
                    icon: Icons.terminal_rounded,
                    fields: {
                      '公钥': _selected!['public_openssh']?.toString() ?? '',
                      '默认密钥': _selected!['is_default'] == true ? '是' : '否',
                      '存储方式': '私钥加密保存在保险库数据库中，由 SSH Agent 完成签名。',
                      '数据库文件': _storagePath,
                      'SSH Agent 连接': _agentSocket,
                      '独立私钥文件': '不生成，也无需手动指定私钥文件。',
                    },
                  ),
            actions: _selected == null
                ? null
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      CredentialActionSection(
                        title: '密钥使用',
                        children: [
                          FilledButton.tonal(
                            onPressed: () => _copyPublicKey(_selected!),
                            child: const LText('复制公钥'),
                          ),
                          OutlinedButton(onPressed: () async {
                            if (!await requireTouchId(context, reason: '切换 SSH 签名密钥')) return;
                            try { await AgentBridge.request({'type':'ssh_select_key','key_id':_selected!['id']}); if (mounted) setState(() => _status='已切换当前 SSH 签名密钥（重启后使用默认密钥）'); } catch(e) { vaultMessage(context,e); }
                          }, child: const LText('用于当前 SSH 签名')),
                        ],
                      ),
                      CredentialActionSection(
                        title: '密钥导出',
                        children: [
                          OutlinedButton(onPressed: () => transferSshKey(context, keyId: _selected!['id'].toString()), child: const LText('导出私钥')),
                        ],
                      ),
                      CredentialActionSection(
                        title: '资料管理',
                        children: [
                          OutlinedButton(onPressed: () => editItemDetails(context, _selected!), child: const LText('备注与关联')),
                          OutlinedButton(
                            onPressed: () {
                              final itemId = _selected!['item_id'] as String?;
                              if (itemId == null) return;
                              showMoveItemToGroupDialog(
                                context,
                                scope: 'ssh',
                                itemId: itemId,
                                currentGroupId: _selected!['group_id'] as String?,
                              ).then((_) => _refresh());
                            },
                            child: const LText('移到分组'),
                          ),
                        ],
                      ),
                      CredentialActionSection(
                        title: '危险操作',
                        dangerous: true,
                        children: [
                          OutlinedButton.icon(
                            onPressed: () => _delete(_selected!),
                            icon: const Icon(Icons.delete_outline_rounded),
                            label: const LText('删除'),
                          ),
                        ],
                      ),
                    ],
                  ),
          )),
          LText(
            '支持 Ed25519 OpenSSH 导入、导出和删除。可在「设置」中配置 SSH IdentityAgent。',
            style: TextStyle(fontSize: 11, color: AppColors.muted),
          ),
        ],
      ),
    ));
  }
}

// —— 安全中心（恢复码 / 备份）——

class SecurityCenterTab extends StatefulWidget {
  const SecurityCenterTab({super.key, required this.unlocked, this.onVaultSwitched, this.onUnlock});

  final bool unlocked;
  final VoidCallback? onVaultSwitched;
  final VoidCallback? onUnlock;

  @override
  State<SecurityCenterTab> createState() => _SecurityCenterTabState();
}

class _SecurityCenterTabState extends State<SecurityCenterTab> {
  int _loadGeneration = 0;
  Map<String, dynamic> _summary = {};
  Map<String, dynamic> _backupStatus = {};
  List<Map<String, dynamic>> _restorePoints = [];
  List<Map<String, dynamic>> _recoveryCodes = [];
  String _log = '';
  final _serviceName = TextEditingController();
  final _codesText = TextEditingController();
  final _recoveryKey = TextEditingController();
  final _rebuildPassword = TextEditingController();

  @override
  void initState() {
    super.initState();
    if (widget.unlocked) {
      _loadAll();
    }
  }

  @override
  void dispose() {
    _serviceName.dispose();
    _codesText.dispose();
    _recoveryKey.dispose();
    _rebuildPassword.dispose();
    super.dispose();
  }

  Future<void> _loadAll() async {
    if (!widget.unlocked) return;
    final generation = ++_loadGeneration;
    try {
      final summary = await AgentBridge.securitySummary();
      final backupStatus = await AgentBridge.backupStatus();
      final restorePoints = await AgentBridge.listRestorePoints();
      final recoveryCodes = await AgentBridge.listRecoveryCodes();
      // 页面保留在导航栈中，旧请求不能把锁定前的数据重新写回。
      if (!mounted || !widget.unlocked || generation != _loadGeneration) return;
      setState(() {
        _summary = summary;
        _backupStatus = backupStatus;
        _restorePoints = restorePoints;
        _recoveryCodes = recoveryCodes;
      });
    } on AgentException catch (e) {
      if (mounted && widget.unlocked && generation == _loadGeneration) {
        setState(() => _log = AgentBridge.diagnosticMessage(e));
      }
    }
  }

  Future<void> _importBitwarden() async {
    await importBitwardenWithPreview(context);
    if (mounted) await _loadAll();
  }

  Future<void> _addRecoveryCodes() async {
    final name = _serviceName.text.trim();
    final codes = _codesText.text
        .split(RegExp(r'[\s,;]+'))
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
    if (name.isEmpty || codes.isEmpty) {
      setState(() => _log = '请填写服务名和至少一条恢复码');
      return;
    }
    try {
      await AgentBridge.createRecoveryCodes(name, codes);
      _serviceName.clear();
      _codesText.clear();
      await _loadAll();
      setState(() => _log = '已保存网站恢复码');
    } on AgentException catch (e) {
      setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  Future<void> _recoverPoint(Map<String, dynamic> point) async {
    if (!await requireTouchId(context, reason: '从恢复点恢复保险库')) return;
    final target = await AgentBridge.pickDirectory();
    if (target == null) return;
    final ts = point['created_at_ms'] as int? ?? 0;
    try {
      await AgentBridge.recoverRestorePoint(ts, target);
      await AgentBridge.lockVault();
      await AgentBridge.vaultOpenDir(target);
      widget.onVaultSwitched?.call();
      setState(() => _log = '已恢复到：$target。工作库已切换，请重新解锁。');
    } on AgentException catch (e) {
      setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  Future<void> _migrateVault() async {
    if (!await requireTouchId(context, reason: '迁移保险库')) return;
    final target = await AgentBridge.pickDirectory();
    if (target == null) return;
    try {
      await AgentBridge.migrateVault(target);
      setState(() => _log = '已迁移工作库到：$target');
      await _loadAll();
    } on AgentException catch (e) {
      setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  Future<void> _securityRebuild() async {
    if (!await requireTouchId(context, reason: '安全重建保险库')) return;
    try {
      final newKey = await AgentBridge.securityRebuild(_rebuildPassword.text, _recoveryKey.text.trim());
      _recoveryKey.text = newKey;
      setState(() => _log = '安全重建完成。请保存新的恢复密钥。');
      await _loadAll();
    } on AgentException catch (e) {
      setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  Future<void> _verifyOvb() async {
    final path = await AgentBridge.pickOpenFile();
    if (path == null) return;
    try {
      await AgentBridge.verifyOvb(path, _rebuildPassword.text);
      setState(() => _log = 'OVB 验证通过');
      await _loadAll();
    } on AgentException catch (e) {
      setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  Future<void> _openRecoveryCode(Map<String, dynamic> row) async {
    await manageRecoveryEntries(context, row);
    if (mounted) await _loadAll();
  }

  Future<void> _recoverOvbToEmptyDir() async {
    final ovb = await AgentBridge.pickOpenFile();
    if (ovb == null) return;
    final target = await AgentBridge.pickDirectory();
    if (target == null) return;
    try {
      await AgentBridge.vaultRecoverOvb(
        ovbPath: ovb,
        targetDir: target,
        password: _rebuildPassword.text.isNotEmpty ? _rebuildPassword.text : null,
        recoveryKey: _recoveryKey.text.trim().isNotEmpty ? _recoveryKey.text.trim() : null,
      );
      await AgentBridge.lockVault();
      await AgentBridge.vaultOpenDir(target);
      widget.onVaultSwitched?.call();
      setState(() => _log = 'OVB 已恢复到：$target。工作库已切换，请重新解锁。');
    } on AgentException catch (e) {
      setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  Future<void> _verifyRecoveryKey() async {
    try {
      await AgentBridge.verifyRecoveryKey(_recoveryKey.text.trim());
      setState(() => _log = '恢复密钥验证通过');
      await _loadAll();
    } on AgentException catch (e) {
      setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  @override
  void didUpdateWidget(covariant SecurityCenterTab oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!widget.unlocked && oldWidget.unlocked) {
      _loadGeneration++;
      _summary = {};
      _backupStatus = {};
      _restorePoints = [];
      _recoveryCodes = [];
      _log = '';
      _recoveryKey.clear();
      _rebuildPassword.clear();
      _serviceName.clear();
      _codesText.clear();
    } else if (widget.unlocked && !oldWidget.unlocked) {
      _loadAll();
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!widget.unlocked) {
      return AppEmptyState(
        icon: Icons.verified_user_outlined,
        title: '安全中心已锁定',
        message: '解锁保险库后，查看网站恢复码、备份记录与恢复点。',
        action: FilledButton.icon(
            onPressed: widget.onUnlock,
            icon: const Icon(Icons.lock_open_rounded),
            label: const LText('前往解锁')),
      );
    }
    return ListView(
      padding: const EdgeInsets.fromLTRB(24, 6, 24, 24),
      children: [
        if (_log.isNotEmpty) AppNotice(_log),
        AppPanel(
          title: '备份状态',
          subtitle: '记录最近一次成功验证的时间，建议定期检查备份。',
          icon: Icons.cloud_done_outlined,
          trailing: IconButton(
              onPressed: _loadAll,
              tooltip: tr('刷新安全状态'),
              icon: const Icon(Icons.refresh_rounded)),
          child: Column(children: [
            _backupRow('本地恢复点', 'local_restore_verified_ms'),
            _backupRow('OVB 导出', 'ovb_export_verified_ms'),
            _backupRow('OVB 解密验证', 'ovb_decrypt_verified_ms'),
            _backupRow('恢复密钥验证', 'recovery_key_verified_ms'),
          ]),
        ),
        const SizedBox(height: 16),
        AppPanel(
          title: '网站恢复码',
          subtitle: '保存网站提供的一次性备用恢复码。点击服务名称查看。',
          icon: Icons.verified_user_outlined,
          child:
              Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            if (_recoveryCodes.isEmpty)
              const AppNotice('还没有保存恢复码。可在下方添加服务和恢复码。'),
            ..._recoveryCodes.map((r) => ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(Icons.verified_user_outlined,
                      color: AppColors.primary),
                  title: Text(r['service_name']?.toString() ?? ''),
                  subtitle: LText('剩余 ${r['remaining_count'] ?? 0} / ${r['code_count'] ?? 0} 条恢复码'),
                  trailing: const Icon(Icons.chevron_right_rounded, size: 18),
                  onTap: () => _openRecoveryCode(r),
                )),
            const SizedBox(height: 12),
            TextField(
                controller: _serviceName,
                decoration: InputDecoration(
                    labelText: tr('服务名称'), hintText: tr('例如 GitHub'))),
            const SizedBox(height: 12),
            TextField(
                controller: _codesText,
                minLines: 2,
                maxLines: 4,
                decoration: InputDecoration(
                    labelText: tr('恢复码'), hintText: tr('使用换行、空格或逗号分隔'))),
            const SizedBox(height: 14),
            Align(
                alignment: Alignment.centerLeft,
                child: FilledButton.icon(
                    onPressed: _addRecoveryCodes,
                    icon: const Icon(Icons.add_rounded),
                    label: const LText('保存恢复码'))),
          ]),
        ),
        const SizedBox(height: 16),
        AppPanel(
          title: '本地恢复点',
          subtitle: '选择恢复点后，将恢复到你指定的目录。',
          icon: Icons.history_rounded,
          child: _restorePoints.isEmpty
              ? const AppNotice('暂无可用的本地恢复点。')
              : Column(
                  children: _restorePoints
                      .map((point) => ListTile(
                            contentPadding: EdgeInsets.zero,
                            leading: const Icon(Icons.restore_rounded),
                            title:
                                Text(displayDateTime(point['created_at_ms'])),
                            trailing: OutlinedButton(
                                onPressed: () => _recoverPoint(point),
                                child: const LText('恢复')),
                          ))
                      .toList()),
        ),
        const SizedBox(height: 16),
        AppPanel(
          title: '导入与迁移',
          subtitle: '从其他密码管理器导入，或更换当前工作目录。',
          icon: Icons.drive_file_move_outlined,
          child: Wrap(spacing: 10, runSpacing: 10, children: [
            OutlinedButton.icon(
                onPressed: _importBitwarden,
                icon: const Icon(Icons.file_upload_outlined),
                label: const LText('导入 Bitwarden')),
            OutlinedButton.icon(
                onPressed: _migrateVault,
                icon: const Icon(Icons.folder_outlined),
                label: const LText('迁移保险库目录')),
          ]),
        ),
        const SizedBox(height: 16),
        Card(
            child: ExpansionTile(
          shape: const Border(),
          collapsedShape: const Border(),
          leading: Icon(Icons.settings_backup_restore_rounded,
              color: AppColors.primary),
          title: const LText('从 OVB 备份恢复'),
          subtitle: const LText('恢复后会切换工作库，并需要重新解锁'),
          childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
          children: [
            const AppNotice('填写备份主密码或恢复密钥，然后选择 OVB 文件及目标空目录。'),
            TextField(
                controller: _rebuildPassword,
                obscureText: true,
                decoration: InputDecoration(labelText: tr('备份的主密码'))),
            const SizedBox(height: 12),
            TextField(
                controller: _recoveryKey,
                obscureText: true,
                decoration: InputDecoration(labelText: tr('恢复密钥'))),
            const SizedBox(height: 14),
            Align(
                alignment: Alignment.centerLeft,
                child: OutlinedButton(
                    onPressed: _recoverOvbToEmptyDir,
                    child: const LText('选择备份并恢复'))),
          ],
        )),
      ],
    );
  }

  Widget _backupRow(String title, String key) {
    final value = _backupStatus[key];
    final verified = value is num && value > 0;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 9),
      child: Row(children: [
        Icon(
            verified
                ? Icons.check_circle_outline_rounded
                : Icons.radio_button_unchecked_rounded,
            size: 18,
            color: verified ? AppColors.green : AppColors.muted),
        const SizedBox(width: 10),
        Expanded(child: Text(title)),
        const SizedBox(width: 12),
        Text(displayDateTime(value),
            style: Theme.of(context).textTheme.bodySmall),
      ]),
    );
  }
}
