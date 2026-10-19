import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';

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
            '解锁后可在本页手动添加登录密码、TOTP 与 SSH 密钥。',
            textAlign: TextAlign.center,
          ),
        ),
      );
    }
    return DefaultTabController(
      length: 3,
      child: Column(
        children: [
          Material(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            child: const TabBar(
              tabs: [
                Tab(text: '登录密码'),
                Tab(text: 'MFA / TOTP'),
                Tab(text: 'SSH 密钥'),
              ],
            ),
          ),
          Expanded(
            child: TabBarView(
              children: [
                _LoginPasswordPanel(),
                _TotpPanel(),
                _SshKeysPanel(),
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
      _status = '共 ${_items.length} 条登录';
    } on AgentException catch (e) {
      _status = AgentBridge.friendlyMessage(e);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _addOrEdit({Map<String, dynamic>? existing}) async {
    final originCtl = TextEditingController(text: existing?['origin']?.toString() ?? 'https://');
    final userCtl = TextEditingController(text: existing?['username']?.toString() ?? '');
    final passCtl = TextEditingController();
    final isEdit = existing != null;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(isEdit ? '编辑登录' : '添加登录'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
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
    );
    if (ok != true) return;
    try {
      if (isEdit) {
        await AgentBridge.updateLogin(
          credentialId: existing!['id'] as String,
          expectedRevision: existing['current_revision'] as String,
          origin: originCtl.text.trim(),
          username: userCtl.text.trim(),
          password: passCtl.text.isEmpty ? null : passCtl.text,
        );
      } else {
        await AgentBridge.createLogin(
          origin: originCtl.text.trim(),
          username: userCtl.text.trim(),
          password: passCtl.text,
        );
      }
      await _refresh();
    } on AgentException catch (e) {
      setState(() => _status = e.message);
    }
  }

  Future<void> _copyPassword(String id) async {
    final detail = await AgentBridge.getCredential(id);
    await AgentBridge.copyConcealed(detail['password'] as String? ?? '');
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('密码已复制')));
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
          Expanded(
            child: _items.isEmpty
                ? const Center(child: Text('暂无登录项，请点击上方「添加登录密码」'))
                : ListView.builder(
                    itemCount: _items.length,
                    itemBuilder: (_, i) {
                      final row = _items[i];
                      return ListTile(
                        selected: _selected?['id'] == row['id'],
                        title: Text(row['title']?.toString() ?? row['origin']?.toString() ?? ''),
                        subtitle: Text('${row['origin']} · ${row['username']}'),
                        onTap: () => setState(() => _selected = row),
                      );
                    },
                  ),
          ),
          if (_selected != null)
            Wrap(
              spacing: 8,
              children: [
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
      _status = '共 ${_items.length} 个 TOTP';
      setState(() {});
    } on AgentException catch (e) {
      setState(() => _status = e.message);
    }
  }

  String? _parseOtpauthSecret(String input) {
    final t = input.trim();
    if (!t.toLowerCase().startsWith('otpauth://')) return null;
    final uri = Uri.tryParse(t);
    return uri?.queryParameters['secret'];
  }

  Future<void> _addTotp() async {
    final issuerCtl = TextEditingController();
    final accountCtl = TextEditingController();
    final secretCtl = TextEditingController();
    final uriCtl = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('添加 MFA / TOTP'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: uriCtl,
                decoration: const InputDecoration(
                  labelText: 'otpauth URI（可选）',
                  hintText: 'otpauth://totp/...',
                ),
                onChanged: (v) {
                  final sec = _parseOtpauthSecret(v);
                  if (sec != null) secretCtl.text = sec;
                },
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
    );
    if (ok != true) return;
    try {
      await AgentBridge.createTotp(
        issuer: issuerCtl.text.trim().isEmpty ? 'CredPivot' : issuerCtl.text.trim(),
        account: accountCtl.text.trim(),
        secretBase32: secretCtl.text.trim().replaceAll(' ', ''),
      );
      await _refresh();
    } on AgentException catch (e) {
      setState(() => _status = e.message);
    }
  }

  Future<void> _showCode(String id) async {
    try {
      final code = await AgentBridge.totpCode(id);
      setState(() {
        _liveCode = code;
        _liveCodeForId = id;
      });
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
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: _liveCode!));
                        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('已复制验证码')));
                      },
                    ),
                  ],
                ),
              ),
            ),
          Expanded(
            child: _items.isEmpty
                ? const Center(child: Text('暂无 TOTP，请添加或从其他应用导出 Base32 密钥'))
                : ListView.builder(
                    itemCount: _items.length,
                    itemBuilder: (_, i) {
                      final row = _items[i];
                      return ListTile(
                        title: Text('${row['issuer']} : ${row['account']}'),
                        trailing: FilledButton(
                          onPressed: () => _showCode(row['id'] as String),
                          child: Text(_liveCodeForId == row['id'] ? '刷新' : '显示验证码'),
                        ),
                        onLongPress: () async {
                          final itemId = row['item_id'] as String?;
                          if (itemId != null) {
                            await AgentBridge.trashCredential(itemId);
                            await _refresh();
                          }
                        },
                      );
                    },
                  ),
          ),
          const Text('长按条目可删除', style: TextStyle(fontSize: 11, color: Colors.black54)),
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
  const SecurityCenterTab({super.key, required this.unlocked});

  final bool unlocked;

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
      await AgentBridge.vaultOpenDir(target);
      setState(() => _log = '已恢复到空目录：$target');
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
      await AgentBridge.securityRebuild(_rebuildPassword.text, _recoveryKey.text.trim());
      setState(() => _log = '安全重建完成');
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
      await AgentBridge.vaultOpenDir(target);
      setState(() => _log = 'OVB 已恢复：$target');
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
    if (widget.unlocked && !oldWidget.unlocked) {
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
