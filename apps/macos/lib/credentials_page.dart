import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'agent_bridge.dart';
import 'credential_confirm.dart';
import 'credential_group_ui.dart';
import 'credential_list_tile.dart';
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
  const CredentialsTab({super.key, required this.unlocked});

  final bool unlocked;

  @override
  Widget build(BuildContext context) {
    if (!unlocked) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(24),
          child: Text(
            '请先使用「主密码解锁」。\n'
            '解锁后可在本页管理登录密码、TOTP、SSH 与服务器/堡垒机配置。',
            textAlign: TextAlign.center,
          ),
        ),
      );
    }
    return DefaultTabController(
      length: 4,
      child: Column(
        children: [
          Material(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            child: const TabBar(
              isScrollable: true,
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
    setState(() => _busy = true);
    try {
      final q = _search.text.trim();
      _items = await AgentBridge.listCredentials(q.isEmpty ? null : q);
      _groups = await loadCredentialGroups('login');
      _status = '共 ${_items.length} 条登录';
    } on AgentException catch (e) {
      _status = AgentBridge.friendlyMessage(e);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _addOrEdit({Map<String, dynamic>? existing}) async {
    final isEdit = existing != null;
    final nameCtl = TextEditingController(text: existing?['display_name']?.toString() ?? '');
    final originCtl = TextEditingController(text: existing?['origin']?.toString() ?? 'https://');
    final userCtl = TextEditingController(text: existing?['username']?.toString() ?? '');
    final passCtl = TextEditingController();
    var groupId = existing?['group_id'] as String?;
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
                value: (groupId == null || (groupId?.isEmpty ?? true)) ? null : groupId,
                decoration: const InputDecoration(labelText: '分组'),
                items: [
                  const DropdownMenuItem(value: null, child: Text('（未分组）')),
                  ..._groups.map(
                    (g) => DropdownMenuItem(
                      value: g['id'] as String,
                      child: Text(g['name']?.toString() ?? ''),
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
          linkedTotpId: existing['linked_totp_id'] as String?,
          password: passCtl.text.isEmpty ? null : passCtl.text,
        );
      } else {
        await AgentBridge.createLogin(
          origin: origin,
          username: user,
          password: passCtl.text,
          displayName: displayName,
          groupId: groupId,
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
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          FilledButton.icon(
            onPressed: _busy ? null : () => _addOrEdit(),
            icon: const Icon(Icons.add),
            label: const Text('添加登录密码'),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _search,
                  decoration: const InputDecoration(labelText: '搜索', isDense: true),
                  onSubmitted: (_) => _refresh(),
                ),
              ),
              IconButton(onPressed: _busy ? null : _refresh, icon: const Icon(Icons.refresh)),
            ],
          ),
          if (_status.isNotEmpty) Text(_status, style: Theme.of(context).textTheme.bodySmall),
          buildGroupFilterBar(
            groups: _groups,
            selectedGroupId: _filterGroupId,
            onChanged: (v) => setState(() => _filterGroupId = v),
            onManage: () => showManageGroupsDialog(context, 'login').then((_) => _refresh()),
          ),
          Expanded(
            child: _items.isEmpty
                ? const Center(child: Text('暂无登录项，请点击上方「添加登录密码」'))
                : ListView(
                    children: buildGroupedListTiles(
                      groups: _groups,
                      items: _items.where((row) {
                        if (_filterGroupId == null) return true;
                        return row['group_id'] == _filterGroupId;
                      }).toList(),
                      tileBuilder: (row) {
                        final selected = _selected?['id'] == row['id'];
                        final dn = row['display_name']?.toString() ?? '';
                        final title = dn.isNotEmpty ? dn : (row['title']?.toString() ?? row['origin']?.toString() ?? '');
                        return selectableCredentialTile(
                          context: context,
                          selected: selected,
                          title: Text(title),
                          subtitle: Text('${row['origin']} · ${row['username']}'),
                          onTap: () => setState(() => _selected = row),
                        );
                      },
                    ),
                  ),
          ),
          if (_selected != null)
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                OutlinedButton(
                  onPressed: () {
                    final u = _selected!['username']?.toString() ?? '';
                    Clipboard.setData(ClipboardData(text: u));
                    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('用户名已复制')));
                  },
                  child: const Text('复制用户名'),
                ),
                OutlinedButton(
                  onPressed: () => _copyPassword(_selected!['id'] as String),
                  child: const Text('复制密码'),
                ),
                OutlinedButton(
                  onPressed: () => _addOrEdit(existing: _selected),
                  child: const Text('编辑'),
                ),
                OutlinedButton(
                  onPressed: () async {
                    final title = _selected!['title']?.toString() ?? _selected!['origin']?.toString() ?? '登录项';
                    if (!await confirmCredentialDanger(
                      context,
                      title: '删除登录密码',
                      message: '确定删除「$title」？将移入回收逻辑且不可轻易恢复。',
                    )) {
                      return;
                    }
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
        ],
      ),
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
      _status = '共 ${_items.length} 个 TOTP';
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
    var groupId = _filterGroupId;
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
                value: (groupId == null || (groupId?.isEmpty ?? true)) ? null : groupId,
                decoration: const InputDecoration(labelText: '分组'),
                items: [
                  const DropdownMenuItem(value: null, child: Text('（未分组）')),
                  ..._groups.map(
                    (g) => DropdownMenuItem(
                      value: g['id'] as String,
                      child: Text(g['name']?.toString() ?? ''),
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
    final secret = secretCtl.text.trim();
    final localErr = validateTotpSecretInput(secret);
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
        secretBase32: secret,
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
    try {
      final code = await AgentBridge.totpCode(id);
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
    if (!await requireTouchId(context, reason: '删除 MFA / TOTP')) return;
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
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          FilledButton.icon(
            onPressed: _addTotp,
            icon: const Icon(Icons.add),
            label: const Text('添加 TOTP'),
          ),
          if (_status.isNotEmpty) Text(_status, style: Theme.of(context).textTheme.bodySmall),
          buildGroupFilterBar(
            groups: _groups,
            selectedGroupId: _filterGroupId,
            onChanged: (v) => setState(() => _filterGroupId = v),
            onManage: () => showManageGroupsDialog(context, 'totp').then((_) => _refresh()),
          ),
          if (_liveCode != null)
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Row(
                  children: [
                    Text('当前验证码：$_liveCode', style: Theme.of(context).textTheme.titleLarge),
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
            child: _items.isEmpty
                ? const Center(child: Text('暂无 TOTP，请添加或从其他应用导出 Base32 密钥'))
                : ListView(
                    children: buildGroupedListTiles(
                      groups: _groups,
                      items: _items.where((row) {
                        if (_filterGroupId == null) return true;
                        return row['group_id'] == _filterGroupId;
                      }).toList(),
                      tileBuilder: (row) {
                        final selected = _selected?['id'] == row['id'];
                        return selectableCredentialTile(
                          context: context,
                          selected: selected,
                          title: Text('${row['issuer']} : ${row['account']}'),
                          onTap: () => setState(() => _selected = row),
                        );
                      },
                    ),
                  ),
          ),
          if (_selected != null)
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                FilledButton.tonal(
                  onPressed: () => _copyCode(_selected!['id'] as String),
                  child: const Text('复制验证码'),
                ),
                OutlinedButton(
                  onPressed: () => _showCode(_selected!['id'] as String),
                  child: Text(_liveCodeForId == _selected!['id'] ? '刷新显示' : '显示验证码'),
                ),
                OutlinedButton(onPressed: _showQrCode, child: const Text('二维码')),
                OutlinedButton(onPressed: _showOtpauthUri, child: const Text('otpauth URI')),
                OutlinedButton(onPressed: _showSecret, child: const Text('密钥')),
                OutlinedButton(
                  onPressed: () => _deleteTotp(_selected!),
                  child: const Text('删除'),
                ),
              ],
            ),
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
  String _status = '';

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    try {
      _items = await AgentBridge.listSshKeys();
      if (_items.isEmpty) {
        await AgentBridge.generateSshKey(label: 'Default', setDefault: true);
        _items = await AgentBridge.listSshKeys();
      }
      _status = '共 ${_items.length} 个密钥';
      setState(() {});
    } on AgentException catch (e) {
      setState(() => _status = e.message);
    }
  }

  Future<void> _generate() async {
    final labelCtl = TextEditingController(text: 'Key ${_items.length + 1}');
    bool setDefault = false;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
          title: const Text('生成 SSH 密钥'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
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
      await AgentBridge.generateSshKey(label: labelCtl.text.trim(), setDefault: setDefault);
      await _refresh();
    } on AgentException catch (e) {
      setState(() => _status = e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          FilledButton.icon(
            onPressed: _generate,
            icon: const Icon(Icons.add),
            label: const Text('生成 SSH 密钥'),
          ),
          if (_status.isNotEmpty) Text(_status, style: Theme.of(context).textTheme.bodySmall),
          Expanded(
            child: ListView.builder(
              itemCount: _items.length,
              itemBuilder: (_, i) {
                final row = _items[i];
                final pub = row['public_openssh']?.toString() ?? '';
                return ListTile(
                  title: Text(row['label']?.toString() ?? 'SSH'),
                  subtitle: Text(
                    pub.length > 48 ? '${pub.substring(0, 48)}…' : pub,
                    maxLines: 2,
                  ),
                  trailing: row['is_default'] == true
                      ? const Chip(label: Text('默认'))
                      : null,
                  onTap: () {
                    Clipboard.setData(ClipboardData(text: pub));
                    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('公钥已复制')));
                  },
                );
              },
            ),
          ),
          const Text(
            '点击条目复制公钥；在「保险库」页可配置 SSH IdentityAgent。',
            style: TextStyle(fontSize: 11, color: Colors.black54),
          ),
        ],
      ),
    );
  }
}

// —— 安全中心（恢复码 / 备份）——

class SecurityCenterTab extends StatefulWidget {
  const SecurityCenterTab({super.key, required this.unlocked, this.onVaultSwitched});

  final bool unlocked;
  final VoidCallback? onVaultSwitched;

  @override
  State<SecurityCenterTab> createState() => _SecurityCenterTabState();
}

class _SecurityCenterTabState extends State<SecurityCenterTab> {
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
    try {
      _summary = await AgentBridge.securitySummary();
      _backupStatus = await AgentBridge.backupStatus();
      _restorePoints = await AgentBridge.listRestorePoints();
      _recoveryCodes = await AgentBridge.listRecoveryCodes();
      setState(() {});
    } on AgentException catch (e) {
      setState(() => _log = e.message);
    }
  }

  Future<void> _importBitwarden() async {
    final path = await AgentBridge.pickOpenFile();
    if (path == null) return;
    try {
      final text = await AgentBridge.readTextFile(path);
      final report = await AgentBridge.importBitwarden(text);
      setState(() => _log = const JsonEncoder.withIndent('  ').convert(report));
      await _loadAll();
    } on AgentException catch (e) {
      setState(() => _log = e.message);
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
      setState(() => _log = e.message);
    }
  }

  Future<void> _recoverPoint(Map<String, dynamic> point) async {
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
      setState(() => _log = e.message);
    }
  }

  Future<void> _migrateVault() async {
    final target = await AgentBridge.pickDirectory();
    if (target == null) return;
    try {
      await AgentBridge.migrateVault(target);
      setState(() => _log = '已迁移工作库到：$target');
      await _loadAll();
    } on AgentException catch (e) {
      setState(() => _log = e.message);
    }
  }

  Future<void> _securityRebuild() async {
    try {
      final newKey = await AgentBridge.securityRebuild(_rebuildPassword.text, _recoveryKey.text.trim());
      _recoveryKey.text = newKey;
      setState(() => _log = '安全重建完成。请保存新的恢复密钥。');
      await _loadAll();
    } on AgentException catch (e) {
      setState(() => _log = e.message);
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
      setState(() => _log = e.message);
    }
  }

  Future<void> _openRecoveryCode(Map<String, dynamic> row) async {
    final codes = (row['codes'] as List?)?.map((e) => e.toString()).toList() ?? [];
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(row['service_name']?.toString() ?? '恢复码'),
        content: SingleChildScrollView(child: SelectableText(codes.join('\n'))),
        actions: [
          TextButton(
            onPressed: () async {
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
      setState(() => _log = e.message);
    }
  }

  Future<void> _verifyRecoveryKey() async {
    try {
      await AgentBridge.verifyRecoveryKey(_recoveryKey.text.trim());
      setState(() => _log = '恢复密钥验证通过');
      await _loadAll();
    } on AgentException catch (e) {
      setState(() => _log = e.message);
    }
  }

  @override
  void didUpdateWidget(covariant SecurityCenterTab oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!widget.unlocked && oldWidget.unlocked) {
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
      return const Center(child: Text('解锁后可查看安全中心'));
    }
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Expanded(
            child: SingleChildScrollView(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text('网站恢复码', style: Theme.of(context).textTheme.titleSmall),
                  FilledButton.icon(
                    onPressed: _addRecoveryCodes,
                    icon: const Icon(Icons.add),
                    label: const Text('添加网站恢复码'),
                  ),
                  ..._recoveryCodes.map(
                    (r) => ListTile(
                      title: Text(r['service_name']?.toString() ?? ''),
                      subtitle: Text('${(r['codes'] as List?)?.length ?? 0} 条码'),
                      onTap: () => _openRecoveryCode(r),
                    ),
                  ),
                  TextField(controller: _serviceName, decoration: const InputDecoration(labelText: '服务名')),
                  TextField(
                    controller: _codesText,
                    maxLines: 2,
                    decoration: const InputDecoration(labelText: '恢复码'),
                  ),
                  const Divider(),
                  Text('备份与恢复', style: Theme.of(context).textTheme.titleSmall),
                  Text(const JsonEncoder.withIndent('  ').convert(_backupStatus)),
                  ..._restorePoints.map(
                    (p) => ListTile(
                      title: Text('恢复点 ${p['created_at_ms']}'),
                      trailing: TextButton(
                        onPressed: () => _recoverPoint(p),
                        child: const Text('恢复'),
                      ),
                    ),
                  ),
                  TextField(
                    controller: _rebuildPassword,
                    obscureText: true,
                    decoration: const InputDecoration(labelText: '主密码'),
                  ),
                  TextField(controller: _recoveryKey, decoration: const InputDecoration(labelText: '恢复密钥')),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      OutlinedButton(onPressed: _loadAll, child: const Text('刷新')),
                      OutlinedButton(onPressed: _importBitwarden, child: const Text('Bitwarden')),
                      OutlinedButton(onPressed: _migrateVault, child: const Text('迁移目录')),
                      OutlinedButton(onPressed: _recoverOvbToEmptyDir, child: const Text('OVB 恢复')),
                    ],
                  ),
                ],
              ),
            ),
          ),
          if (_log.isNotEmpty) Text(_log, style: Theme.of(context).textTheme.bodySmall),
        ],
      ),
    );
  }
}
