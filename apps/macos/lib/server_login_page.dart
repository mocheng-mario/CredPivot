import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';
import 'credential_confirm.dart';
import 'credential_list_tile.dart';
import 'touch_id_gate.dart';

/// 服务器 / 堡垒机：关联登录、MFA、SSH 的一站式入口。
class ServerLoginPanel extends StatefulWidget {
  const ServerLoginPanel({super.key});

  @override
  State<ServerLoginPanel> createState() => _ServerLoginPanelState();
}

class _ServerLoginPanelState extends State<ServerLoginPanel> {
  List<Map<String, dynamic>> _items = [];
  List<Map<String, dynamic>> _logins = [];
  List<Map<String, dynamic>> _totps = [];
  List<Map<String, dynamic>> _sshKeys = [];
  Map<String, dynamic>? _selected;
  String _status = '';

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    try {
      _items = await AgentBridge.listServerProfiles();
      _logins = await AgentBridge.listCredentials();
      _totps = await AgentBridge.listTotp();
      _sshKeys = await AgentBridge.listSshKeys();
      _status = '共 ${_items.length} 个服务器配置';
      setState(() {});
    } on AgentException catch (e) {
      setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  String? _linkLabel(String? id, List<Map<String, dynamic>> pool, String field) {
    if (id == null || id.isEmpty) return null;
    for (final row in pool) {
      if (row['id'] == id) {
        return row[field]?.toString();
      }
    }
    return '（已删除）';
  }

  Future<void> _addOrEdit({Map<String, dynamic>? existing}) async {
    final isEdit = existing != null;
    if (isEdit && !await requireTouchId(context, reason: '编辑服务器登录配置')) return;

    final labelCtl = TextEditingController(text: existing?['label']?.toString() ?? '');
    final hostCtl = TextEditingController(text: existing?['host']?.toString() ?? '');
    final portCtl = TextEditingController(text: '${existing?['port'] ?? 22}');
    var linkedLogin = existing?['linked_login_id'] as String?;
    var linkedTotp = existing?['linked_totp_id'] as String?;
    var linkedSsh = existing?['linked_ssh_key_id'] as String?;

    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
          title: Text(isEdit ? '编辑服务器' : '添加服务器 / 堡垒机'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(controller: labelCtl, decoration: const InputDecoration(labelText: '名称')),
                TextField(
                  controller: hostCtl,
                  decoration: const InputDecoration(labelText: '主机 / 堡垒机地址'),
                ),
                TextField(
                  controller: portCtl,
                  decoration: const InputDecoration(labelText: '端口'),
                  keyboardType: TextInputType.number,
                ),
                const SizedBox(height: 8),
                DropdownButtonFormField<String?>(
                  value: (linkedLogin == null || (linkedLogin?.isEmpty ?? true)) ? null : linkedLogin,
                  decoration: const InputDecoration(labelText: '关联登录密码'),
                  items: [
                    const DropdownMenuItem(value: null, child: Text('（不关联）')),
                    ..._logins.map(
                      (c) => DropdownMenuItem(
                        value: c['id'] as String,
                        child: Text('${c['username']} @ ${c['origin']}'),
                      ),
                    ),
                  ],
                  onChanged: (v) => setLocal(() => linkedLogin = v),
                ),
                DropdownButtonFormField<String?>(
                  value: (linkedTotp == null || (linkedTotp?.isEmpty ?? true)) ? null : linkedTotp,
                  decoration: const InputDecoration(labelText: '关联 MFA / TOTP'),
                  items: [
                    const DropdownMenuItem(value: null, child: Text('（不关联）')),
                    ..._totps.map(
                      (t) => DropdownMenuItem(
                        value: t['id'] as String,
                        child: Text('${t['issuer']} : ${t['account']}'),
                      ),
                    ),
                  ],
                  onChanged: (v) => setLocal(() => linkedTotp = v),
                ),
                DropdownButtonFormField<String?>(
                  value: (linkedSsh == null || (linkedSsh?.isEmpty ?? true)) ? null : linkedSsh,
                  decoration: const InputDecoration(labelText: '关联 SSH 密钥'),
                  items: [
                    const DropdownMenuItem(value: null, child: Text('（不关联）')),
                    ..._sshKeys.map(
                      (s) => DropdownMenuItem(
                        value: s['id'] as String,
                        child: Text(s['label']?.toString() ?? 'SSH'),
                      ),
                    ),
                  ],
                  onChanged: (v) => setLocal(() => linkedSsh = v),
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
    if (isEdit && !await requireTouchId(context, reason: '保存服务器配置')) return;

    final port = int.tryParse(portCtl.text.trim()) ?? 22;
    try {
      if (isEdit) {
        await AgentBridge.updateServerProfile(
          id: existing!['id'] as String,
          expectedRevision: existing['current_revision'] as String,
          label: labelCtl.text.trim(),
          host: hostCtl.text.trim(),
          port: port,
          linkedLoginId: linkedLogin,
          linkedTotpId: linkedTotp,
          linkedSshKeyId: linkedSsh,
        );
      } else {
        await AgentBridge.createServerProfile(
          label: labelCtl.text.trim().isEmpty ? hostCtl.text.trim() : labelCtl.text.trim(),
          host: hostCtl.text.trim(),
          port: port,
          linkedLoginId: linkedLogin,
          linkedTotpId: linkedTotp,
          linkedSshKeyId: linkedSsh,
        );
      }
      await _refresh();
    } on AgentException catch (e) {
      setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  Future<void> _deleteSelected() async {
    final row = _selected;
    if (row == null) return;
    if (!await confirmCredentialDanger(
      context,
      title: '删除服务器配置',
      message: '确定删除「${row['label']}」？此操作不可撤销。',
    )) {
      return;
    }
    if (!await requireTouchId(context, reason: '删除服务器配置')) return;
    final itemId = row['item_id'] as String?;
    if (itemId == null) return;
    try {
      await AgentBridge.trashCredential(itemId);
      _selected = null;
      await _refresh();
    } on AgentException catch (e) {
      setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  Future<String?> _loginUsername(String? loginId) async {
    if (loginId == null || loginId.isEmpty) return null;
    try {
      final detail = await AgentBridge.getCredential(loginId);
      return detail['username'] as String?;
    } on AgentException catch (_) {
      return null;
    }
  }

  Future<void> _copyPassword() async {
    final loginId = _selected?['linked_login_id'] as String?;
    if (loginId == null || loginId.isEmpty) {
      setState(() => _status = '请先关联登录密码');
      return;
    }
    if (!await requireTouchId(context, reason: '复制登录密码')) return;
    final detail = await AgentBridge.getCredential(loginId);
    await AgentBridge.copyConcealed(detail['password'] as String? ?? '');
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('密码已复制（30 秒后清除）')),
      );
    }
  }

  Future<void> _copyMfa() async {
    final totpId = _selected?['linked_totp_id'] as String?;
    if (totpId == null || totpId.isEmpty) {
      setState(() => _status = '请先关联 MFA');
      return;
    }
    try {
      final code = await AgentBridge.totpCode(totpId);
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

  Future<void> _copySshHint() async {
    final host = _selected?['host']?.toString() ?? '';
    final port = _selected?['port'] ?? 22;
    final user = await _loginUsername(_selected?['linked_login_id'] as String?);
    final u = user ?? 'user';
    final line = port == 22 ? 'ssh $u@$host' : 'ssh -p $port $u@$host';
    await Clipboard.setData(ClipboardData(text: line));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('已复制：$line')));
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
            onPressed: () => _addOrEdit(),
            icon: const Icon(Icons.add),
            label: const Text('添加服务器 / 堡垒机'),
          ),
          if (_status.isNotEmpty) Text(_status, style: Theme.of(context).textTheme.bodySmall),
          Expanded(
            child: _items.isEmpty
                ? const Center(child: Text('暂无配置。可在此关联账户密码、MFA 与 SSH 密钥。'))
                : ListView.builder(
                    itemCount: _items.length,
                    itemBuilder: (_, i) {
                      final row = _items[i];
                      final selected = _selected?['id'] == row['id'];
                      final loginLbl = _linkLabel(
                        row['linked_login_id'] as String?,
                        _logins,
                        'username',
                      );
                      final totpLbl = _linkLabel(
                        row['linked_totp_id'] as String?,
                        _totps,
                        'issuer',
                      );
                      final sub = [
                        '${row['host']}:${row['port']}',
                        if (loginLbl != null) '登录: $loginLbl',
                        if (totpLbl != null) 'MFA: $totpLbl',
                      ].join(' · ');
                      return selectableCredentialTile(
                        context: context,
                        selected: selected,
                        title: Text(row['label']?.toString() ?? row['host']?.toString() ?? ''),
                        subtitle: Text(sub),
                        onTap: () => setState(() => _selected = row),
                      );
                    },
                  ),
          ),
          if (_selected != null)
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                OutlinedButton(onPressed: _copySshHint, child: const Text('复制 SSH 命令')),
                OutlinedButton(onPressed: _copyPassword, child: const Text('复制密码')),
                FilledButton.tonal(onPressed: _copyMfa, child: const Text('复制 MFA')),
                OutlinedButton(onPressed: () => _addOrEdit(existing: _selected), child: const Text('编辑')),
                OutlinedButton(onPressed: _deleteSelected, child: const Text('删除')),
              ],
            ),
        ],
      ),
    );
  }
}
