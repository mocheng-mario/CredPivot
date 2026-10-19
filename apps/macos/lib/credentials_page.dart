import 'dart:convert';

import 'package:flutter/material.dart';

import 'agent_bridge.dart';

class CredentialsTab extends StatefulWidget {
  const CredentialsTab({super.key, required this.unlocked});

  final bool unlocked;

  @override
  State<CredentialsTab> createState() => _CredentialsTabState();
}

class _CredentialsTabState extends State<CredentialsTab> {
  final _search = TextEditingController();
  List<Map<String, dynamic>> _items = [];
  Map<String, dynamic>? _selected;
  String _status = '';
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    if (widget.unlocked) {
      _refresh();
    }
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  @override
  void didUpdateWidget(covariant CredentialsTab oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.unlocked && !oldWidget.unlocked) {
      _refresh();
    }
    if (!widget.unlocked) {
      setState(() {
        _items = [];
        _selected = null;
      });
    }
  }

  Future<void> _refresh() async {
    if (!widget.unlocked) return;
    setState(() => _busy = true);
    try {
      final q = _search.text.trim();
      _items = await AgentBridge.listCredentials(q.isEmpty ? null : q);
      if (_selected != null) {
        final id = _selected!['id'];
        _selected = _items.cast<Map<String, dynamic>?>().firstWhere(
              (e) => e?['id'] == id,
              orElse: () => null,
            );
      }
      _status = '共 ${_items.length} 条';
    } on AgentException catch (e) {
      _status = e.message;
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _copyPassword(String credentialId) async {
    try {
      final detail = await AgentBridge.getCredential(credentialId);
      final pw = detail['password'] as String? ?? '';
      await AgentBridge.copyConcealed(pw);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('密码已复制（剪贴板约 30 秒后清理）')),
        );
      }
    } on AgentException catch (e) {
      setState(() => _status = e.message);
    }
  }

  Future<void> _trashSelected() async {
    final itemId = _selected?['item_id'] as String?;
    if (itemId == null) return;
    setState(() => _busy = true);
    try {
      await AgentBridge.trashCredential(itemId);
      _selected = null;
      await _refresh();
    } on AgentException catch (e) {
      _status = e.message;
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!widget.unlocked) {
      return const Center(child: Text('请先主密码解锁以查看密码列表'));
    }
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _search,
                  decoration: const InputDecoration(
                    labelText: '搜索标题 / 站点 / 用户名',
                    isDense: true,
                  ),
                  onSubmitted: (_) => _refresh(),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton(onPressed: _busy ? null : _refresh, child: const Text('搜索')),
            ],
          ),
          if (_status.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(_status, style: Theme.of(context).textTheme.bodySmall),
            ),
          const SizedBox(height: 8),
          Expanded(
            flex: 2,
            child: ListView.builder(
              itemCount: _items.length,
              itemBuilder: (ctx, i) {
                final row = _items[i];
                final selected = _selected?['id'] == row['id'];
                return ListTile(
                  selected: selected,
                  title: Text(row['title']?.toString() ?? row['origin']?.toString() ?? ''),
                  subtitle: Text('${row['origin']} · ${row['username']}'),
                  onTap: () => setState(() => _selected = row),
                );
              },
            ),
          ),
          if (_selected != null) ...[
            Text('详情', style: Theme.of(context).textTheme.titleSmall),
            Text(const JsonEncoder.withIndent('  ').convert(_selected)),
            Wrap(
              spacing: 8,
              children: [
                OutlinedButton(
                  onPressed: () => _copyPassword(_selected!['id'] as String),
                  child: const Text('复制密码'),
                ),
                OutlinedButton(onPressed: _trashSelected, child: const Text('移入回收站')),
              ],
            ),
          ],
        ],
      ),
    );
  }
}

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
      setState(() => _log = '请填写服务名和至少一条恢复码（可多行/逗号分隔）');
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
      setState(() => _log = '已恢复到空目录并切换工作库：$target');
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
      setState(() => _log = '安全重建完成（VMK 已轮换；旧本地恢复点需旧凭据）');
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
      setState(() => _log = 'OVB 解密验证通过');
      await _loadAll();
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
                  Text('安全摘要', style: Theme.of(context).textTheme.titleMedium),
                  Text(const JsonEncoder.withIndent('  ').convert(_summary)),
                  const SizedBox(height: 12),
                  Text('备份验证状态 (M3-2)', style: Theme.of(context).textTheme.titleSmall),
                  Text(const JsonEncoder.withIndent('  ').convert(_backupStatus)),
                  const SizedBox(height: 12),
                  Text('网站恢复码 (M2-5)', style: Theme.of(context).textTheme.titleSmall),
                  ..._recoveryCodes.map(
                    (r) => ListTile(
                      dense: true,
                      title: Text(r['service_name']?.toString() ?? ''),
                      subtitle: Text('${(r['codes'] as List?)?.length ?? 0} 条码'),
                    ),
                  ),
                  TextField(
                    controller: _serviceName,
                    decoration: const InputDecoration(labelText: '服务名', isDense: true),
                  ),
                  TextField(
                    controller: _codesText,
                    decoration: const InputDecoration(
                      labelText: '恢复码（多行或逗号分隔）',
                      isDense: true,
                    ),
                    maxLines: 3,
                  ),
                  OutlinedButton(onPressed: _addRecoveryCodes, child: const Text('添加恢复码')),
                  const Divider(),
                  Text('本地恢复点 (M3-3)', style: Theme.of(context).textTheme.titleSmall),
                  ..._restorePoints.map(
                    (p) => ListTile(
                      dense: true,
                      title: Text('${p['created_at_ms']}'),
                      trailing: TextButton(
                        onPressed: () => _recoverPoint(p),
                        child: const Text('恢复到空目录'),
                      ),
                    ),
                  ),
                  const Divider(),
                  TextField(
                    controller: _rebuildPassword,
                    obscureText: true,
                    decoration: const InputDecoration(labelText: '主密码（验证 OVB / 安全重建）'),
                  ),
                  TextField(
                    controller: _recoveryKey,
                    decoration: const InputDecoration(labelText: '恢复密钥'),
                  ),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      OutlinedButton(onPressed: _loadAll, child: const Text('刷新')),
                      OutlinedButton(onPressed: _importBitwarden, child: const Text('Bitwarden 导入')),
                      OutlinedButton(onPressed: _migrateVault, child: const Text('迁移工作库目录')),
                      OutlinedButton(onPressed: _verifyOvb, child: const Text('验证 OVB')),
                      OutlinedButton(onPressed: _verifyRecoveryKey, child: const Text('验证恢复密钥')),
                      OutlinedButton(onPressed: _securityRebuild, child: const Text('安全重建 (VMK)')),
                    ],
                  ),
                ],
              ),
            ),
          ),
          if (_log.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(_log, style: Theme.of(context).textTheme.bodySmall),
            ),
        ],
      ),
    );
  }
}
