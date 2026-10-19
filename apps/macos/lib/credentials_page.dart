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
  String _importLog = '';

  @override
  void initState() {
    super.initState();
    if (widget.unlocked) {
      _load();
    }
  }

  Future<void> _load() async {
    if (!widget.unlocked) return;
    try {
      _summary = await AgentBridge.securitySummary();
      setState(() {});
    } on AgentException catch (e) {
      setState(() => _importLog = e.message);
    }
  }

  Future<void> _importBitwarden() async {
    final path = await AgentBridge.pickOpenFile();
    if (path == null) return;
    try {
      final text = await AgentBridge.readTextFile(path);
      final report = await AgentBridge.importBitwarden(text);
      setState(() => _importLog = const JsonEncoder.withIndent('  ').convert(report));
      await _load();
    } on AgentException catch (e) {
      setState(() => _importLog = e.message);
    }
  }

  @override
  void didUpdateWidget(covariant SecurityCenterTab oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.unlocked && !oldWidget.unlocked) {
      _load();
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!widget.unlocked) {
      return const Center(child: Text('解锁后可查看安全中心'));
    }
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text('安全摘要', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          Text(const JsonEncoder.withIndent('  ').convert(_summary)),
          const SizedBox(height: 16),
          OutlinedButton(onPressed: _load, child: const Text('刷新摘要')),
          const SizedBox(height: 8),
          OutlinedButton(onPressed: _importBitwarden, child: const Text('导入 Bitwarden JSON')),
          if (_importLog.isNotEmpty) ...[
            const SizedBox(height: 12),
            Expanded(child: SingleChildScrollView(child: Text(_importLog))),
          ],
        ],
      ),
    );
  }
}
