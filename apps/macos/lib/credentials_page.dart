import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'agent_bridge.dart';
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
                  const SnackBar(content: Text('已复制（30 秒后清除剪贴板）')),
                );
              }
            },
            child: const Text('复制'),
          ),
        FilledButton(onPressed: () => Navigator.pop(ctx), child: const Text('关闭')),
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
            label: const Text('前往解锁')),
      );
    }
    return DefaultTabController(
      length: 4,
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
                Tab(text: '登录密码'),
                Tab(text: 'MFA / TOTP'),
                Tab(text: 'SSH 密钥'),
                Tab(text: '服务器'),
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
    final nameCtl = TextEditingController(text: existing?['display_name']?.toString() ?? '');
    final originCtl = TextEditingController(text: existing?['origin']?.toString() ?? 'https://');
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
        title: Text(isEdit ? '编辑登录' : '添加登录'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: nameCtl,
                decoration: const InputDecoration(labelText: '名称', hintText: '例如：公司 VPN 账号'),
              ),
              DropdownButtonFormField<String?>(
                isExpanded: true,
                value: groupId,
                decoration: const InputDecoration(labelText: '分组'),
                items: [
                  const DropdownMenuItem(value: null, child: Text('（未分组）')),
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
              TextField(
                controller: originCtl,
                decoration: const InputDecoration(labelText: '网站 / Origin', hintText: 'https://example.com'),
              ),
              TextField(controller: userCtl, decoration: const InputDecoration(labelText: '用户名')),
              TextField(
                controller: passCtl,
                obscureText: true,
                decoration: InputDecoration(
                  labelText: isEdit ? '新密码（留空则不修改）' : '密码',
                ),
              ),
              DropdownButtonFormField<String?>(
                isExpanded: true,
                value: linkedTotp,
                decoration: const InputDecoration(
                  labelText: '关联 MFA / TOTP',
                  helperText: '浏览器扩展「填充 MFA」需要在此关联',
                ),
                items: [
                  const DropdownMenuItem(value: null, child: Text('（不关联）')),
                  ...totps.map(
                    (t) => DropdownMenuItem(
                      value: t['id'] as String,
                      child: Text(
                        '${t['issuer']} : ${t['account']}',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ),
                ],
                onChanged: (v) => setLocal(() => linkedTotp = v),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('取消')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('保存')),
        ],
      ),
      ),
    );
    if (ok != true) return;
    if (isEdit) {
      if (!await requireTouchId(context, reason: '保存登录凭据修改')) return;
    }
    if (staleLinkWasCleared(rawTotp, linkedTotp) && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('关联的 MFA 已删除，保存后将清除该关联。')),
      );
    }
    try {
      final origin = originCtl.text.trim();
      final user = userCtl.text.trim();
      final displayName = nameCtl.text.trim();
      if (isEdit) {
        await AgentBridge.updateLogin(
          credentialId: existing!['id'] as String,
          expectedRevision: existing['current_revision'] as String,
          origin: origin,
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
          username: user,
          password: passCtl.text,
          displayName: displayName,
          groupId: groupId,
          linkedTotpId: linkedTotp,
        );
      }
      await _refresh();
    } on AgentException catch (e) {
      setState(() => _status = e.message);
    }
  }

  Future<void> _copyPassword(String id) async {
    if (!await requireTouchId(context, reason: '复制登录密码')) return;
    final detail = await AgentBridge.getCredential(id);
    await AgentBridge.copyConcealed(detail['password'] as String? ?? '');
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('密码已复制（30 秒后清除剪贴板）')));
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
              label: const Text('添加登录项')),
        ),
        Row(children: [
          Expanded(
              child: TextField(
            controller: _search,
            decoration: const InputDecoration(
                hintText: '搜索网站、名称或用户名，按回车确认',
                prefixIcon: Icon(Icons.search_rounded)),
            onSubmitted: (_) => _refresh(),
          )),
          const SizedBox(width: 8),
          IconButton(
              onPressed: _busy ? null : _refresh,
              tooltip: '刷新列表',
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
                      subtitle: Text('${row['origin']} · ${row['username']}'),
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
              : Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    OutlinedButton(
                      onPressed: () {
                        final u = _selected!['username']?.toString() ?? '';
                        Clipboard.setData(ClipboardData(text: u));
                        ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('用户名已复制')));
                      },
                      child: const Text('复制用户名'),
                    ),
                    OutlinedButton(
                      onPressed: () =>
                          _copyPassword(_selected!['id'] as String),
                      child: const Text('复制密码'),
                    ),
                    OutlinedButton(
                      onPressed: () => _addOrEdit(existing: _selected),
                      child: const Text('编辑'),
                    ),
                    OutlinedButton(
                      onPressed: () async {
                        final title = _selected!['title']?.toString() ??
                            _selected!['origin']?.toString() ??
                            '登录项';
                        if (!await confirmCredentialDanger(
                          context,
                          title: '删除登录密码',
                          message: '确定删除「$title」？将移入回收逻辑且不可轻易恢复。',
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
                      child: const Text('删除'),
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
        title: const Text('添加 MFA / TOTP'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              DropdownButtonFormField<String?>(
                isExpanded: true,
                value: groupId,
                decoration: const InputDecoration(labelText: '分组'),
                items: [
                  const DropdownMenuItem(value: null, child: Text('（未分组）')),
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
              TextField(
                controller: uriCtl,
                decoration: const InputDecoration(
                  labelText: 'otpauth URI（可选）',
                  hintText: 'otpauth://totp/...',
                ),
                onChanged: (v) => _applyOtpauthUri(v, issuerCtl, accountCtl, secretCtl),
              ),
              TextField(controller: issuerCtl, decoration: const InputDecoration(labelText: '发行方 Issuer')),
              TextField(controller: accountCtl, decoration: const InputDecoration(labelText: '账号')),
              TextField(
                controller: secretCtl,
                decoration: const InputDecoration(labelText: '密钥 Base32'),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('取消')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('保存')),
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

  Future<void> _copyCode(String id) async {
    if (!await requireTouchId(context, reason: '复制 MFA 验证码')) return;
    try {
      final code = await AgentBridge.totpCode(id);
      if (!mounted || _selected?['id'] != id) return;
      if (code.isEmpty) {
        setState(() => _status = '未拿到验证码');
        return;
      }
      await AgentBridge.copyConcealed(code);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('验证码 $code 已复制')),
        );
      }
    } on AgentException catch (e) {
      setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  Future<void> _showCode(String id) async {
    if (!await requireTouchId(context, reason: '查看 MFA 验证码')) return;
    try {
      final code = await AgentBridge.totpCode(id);
      if (!mounted || _selected?['id'] != id) return;
      if (code.isEmpty) {
        setState(() => _status = '未拿到验证码，请删除后重新添加（可整段粘贴 otpauth URI）');
        return;
      }
      setState(() {
        _liveCode = code;
        _liveCodeForId = id;
        _status = '';
      });
    } on AgentException catch (e) {
      setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

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
        title: Text('${reveal['issuer']} : ${reveal['account']}'),
        content: SizedBox(
          width: 260,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              QrImageView(data: uri, size: 220, backgroundColor: Colors.white),
              const SizedBox(height: 8),
              Text('扫码后可在其他设备添加同一 MFA', style: Theme.of(ctx).textTheme.bodySmall),
            ],
          ),
        ),
        actions: [
          FilledButton(onPressed: () => Navigator.pop(ctx), child: const Text('关闭')),
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
                label: const Text('添加 TOTP')),
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
                    Text('当前验证码：$_liveCode',
                        style: Theme.of(context).textTheme.titleLarge),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.copy),
                      onPressed: () async {
                        await AgentBridge.copyConcealed(_liveCode!);
                        if (!mounted) return;
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('验证码已复制（30 秒后清除）')),
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
                : Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      FilledButton.tonal(
                        onPressed: () => _copyCode(_selected!['id'] as String),
                        child: const Text('复制验证码'),
                      ),
                      OutlinedButton(
                        onPressed: () => _showCode(_selected!['id'] as String),
                        child: Text(_liveCodeForId == _selected!['id']
                            ? '刷新显示'
                            : '显示验证码'),
                      ),
                      OutlinedButton(
                          onPressed: _showQrCode, child: const Text('二维码')),
                      OutlinedButton(
                          onPressed: _showOtpauthUri,
                          child: const Text('otpauth URI')),
                      OutlinedButton(
                          onPressed: _showSecret, child: const Text('密钥')),
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
                        child: const Text('移到分组'),
                      ),
                      OutlinedButton(
                        onPressed: () => _deleteTotp(_selected!),
                        child: const Text('删除'),
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

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    try {
      _items = await AgentBridge.listSshKeys();
      _groups = await loadCredentialGroups('ssh');
      _filterGroupId = dropdownValueIfPresent(_filterGroupId, _groups);
      if (_items.isEmpty) {
        await AgentBridge.generateSshKey(label: 'Default', setDefault: true);
        _items = await AgentBridge.listSshKeys();
      }
      _status = '';
      setState(() {});
    } on AgentException catch (e) {
      setState(() => _status = e.message);
    }
  }

  Future<void> _generate() async {
    final labelCtl = TextEditingController(text: 'Key ${_items.length + 1}');
    bool setDefault = false;
    var groupId = dropdownValueIfPresent(_filterGroupId, _groups);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
          title: const Text('生成 SSH 密钥'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              DropdownButtonFormField<String?>(
                isExpanded: true,
                value: groupId,
                decoration: const InputDecoration(labelText: '分组'),
                items: [
                  const DropdownMenuItem(value: null, child: Text('（未分组）')),
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
              TextField(controller: labelCtl, decoration: const InputDecoration(labelText: '标签')),
              CheckboxListTile(
                value: setDefault,
                onChanged: (v) => setLocal(() => setDefault = v ?? false),
                title: const Text('设为默认（Agent 签名用）'),
                contentPadding: EdgeInsets.zero,
              ),
            ],
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('取消')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('生成')),
          ],
        ),
      ),
    );
    if (ok != true) return;
    if (!await confirmCredentialDanger(
      context,
      title: '生成新 SSH 密钥',
      message: '将生成新的 Ed25519 密钥对。确认继续？',
      confirmLabel: '生成',
    )) {
      return;
    }
    try {
      await AgentBridge.generateSshKey(
        label: labelCtl.text.trim(),
        setDefault: setDefault,
        groupId: groupId,
      );
      await _refresh();
    } on AgentException catch (e) {
      setState(() => _status = e.message);
    }
  }

  void _copyPublicKey(Map<String, dynamic> row) {
    final pub = row['public_openssh']?.toString() ?? '';
    Clipboard.setData(ClipboardData(text: pub));
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('公钥已复制')));
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
            title: 'SSH 密钥',
            subtitle: '${visibleItems.length} 对密钥',
            action: FilledButton.icon(
                onPressed: _generate,
                icon: const Icon(Icons.add_rounded),
                label: const Text('生成密钥')),
          ),
          if (_status.isNotEmpty) AppNotice(_status),
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
                              ? const Chip(label: Text('默认'))
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
                      '默认密钥': _selected!['is_default'] == true ? '是' : '否'
                    },
                  ),
            actions: _selected == null
                ? null
                : Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      FilledButton.tonal(
                        onPressed: () => _copyPublicKey(_selected!),
                        child: const Text('复制公钥'),
                      ),
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
                        child: const Text('移到分组'),
                      ),
                    ],
                  ),
          )),
          const Text(
            '选中密钥后可复制公钥或调整分组；在「保险库」页可配置 SSH IdentityAgent。',
            style: TextStyle(fontSize: 11, color: Colors.black54),
          ),
        ],
      ),
    );
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
    if (!await requireTouchId(context, reason: '导入 Bitwarden 凭据')) return;
    final path = await AgentBridge.pickOpenFile();
    if (path == null) return;
    try {
      final text = await AgentBridge.readTextFile(path);
      final report = await AgentBridge.importBitwarden(text);
      setState(() => _log = const JsonEncoder.withIndent('  ').convert(report));
      await _loadAll();
    } on AgentException catch (e) {
      setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
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
    if (!await requireTouchId(context, reason: '查看网站恢复码')) return;
    Map<String, dynamic> detail;
    try {
      final resp = await AgentBridge.request({'type': 'recovery_codes_get', 'id': row['id']});
      detail = AgentBridge.payloadOf(resp)['item'] as Map<String, dynamic>;
    } on AgentException catch (e) {
      if (mounted) setState(() => _log = AgentBridge.diagnosticMessage(e));
      return;
    }
    final codes = (detail['codes'] as List?)?.map((e) => e.toString()).toList() ?? [];
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(row['service_name']?.toString() ?? '恢复码'),
        content: SingleChildScrollView(child: SelectableText(codes.join('\n'))),
        actions: [
          TextButton(
            onPressed: () async {
              if (!await requireTouchId(ctx, reason: '复制网站恢复码')) return;
              await AgentBridge.copyConcealed(codes.join('\n'));
              if (ctx.mounted) {
                ScaffoldMessenger.of(ctx).showSnackBar(const SnackBar(content: Text('已复制')));
              }
            },
            child: const Text('复制全部'),
          ),
          FilledButton(onPressed: () => Navigator.pop(ctx), child: const Text('关闭')),
        ],
      ),
    );
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
            label: const Text('前往解锁')),
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
              tooltip: '刷新安全状态',
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
                  leading: const Icon(Icons.verified_user_outlined,
                      color: AppColors.primary),
                  title: Text(r['service_name']?.toString() ?? ''),
                  subtitle: Text('${r['code_count'] ?? 0} 条恢复码'),
                  trailing: const Icon(Icons.chevron_right_rounded, size: 18),
                  onTap: () => _openRecoveryCode(r),
                )),
            const SizedBox(height: 12),
            TextField(
                controller: _serviceName,
                decoration: const InputDecoration(
                    labelText: '服务名称', hintText: '例如 GitHub')),
            const SizedBox(height: 12),
            TextField(
                controller: _codesText,
                minLines: 2,
                maxLines: 4,
                decoration: const InputDecoration(
                    labelText: '恢复码', hintText: '使用换行、空格或逗号分隔')),
            const SizedBox(height: 14),
            Align(
                alignment: Alignment.centerLeft,
                child: FilledButton.icon(
                    onPressed: _addRecoveryCodes,
                    icon: const Icon(Icons.add_rounded),
                    label: const Text('保存恢复码'))),
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
                                child: const Text('恢复')),
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
                label: const Text('导入 Bitwarden')),
            OutlinedButton.icon(
                onPressed: _migrateVault,
                icon: const Icon(Icons.folder_outlined),
                label: const Text('迁移保险库目录')),
          ]),
        ),
        const SizedBox(height: 16),
        Card(
            child: ExpansionTile(
          shape: const Border(),
          collapsedShape: const Border(),
          leading: const Icon(Icons.settings_backup_restore_rounded,
              color: AppColors.primary),
          title: const Text('从 OVB 备份恢复'),
          subtitle: const Text('恢复后会切换工作库，并需要重新解锁'),
          childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
          children: [
            const AppNotice('填写备份主密码或恢复密钥，然后选择 OVB 文件及目标空目录。'),
            TextField(
                controller: _rebuildPassword,
                obscureText: true,
                decoration: const InputDecoration(labelText: '备份的主密码')),
            const SizedBox(height: 12),
            TextField(
                controller: _recoveryKey,
                obscureText: true,
                decoration: const InputDecoration(labelText: '恢复密钥')),
            const SizedBox(height: 14),
            Align(
                alignment: Alignment.centerLeft,
                child: OutlinedButton(
                    onPressed: _recoverOvbToEmptyDir,
                    child: const Text('选择备份并恢复'))),
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
