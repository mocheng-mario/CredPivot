import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';
import 'credential_confirm.dart';
import 'credential_list_tile.dart';
import 'linked_refs.dart';
import 'terminal_settings.dart';
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
      final selectedId = _selected?['id'] as String?;
      _items = await AgentBridge.listServerProfiles();
      _logins = await AgentBridge.listCredentials();
      _totps = await AgentBridge.listTotp();
      _sshKeys = await AgentBridge.listSshKeys();
      if (selectedId != null) {
        Map<String, dynamic>? next;
        for (final row in _items) {
          if (row['id'] == selectedId) {
            next = row;
            break;
          }
        }
        _selected = next;
      }
      _status = '共 ${_items.length} 个服务器配置';
      setState(() {});
    } on AgentException catch (e) {
      setState(
        () => _status = '${AgentBridge.friendlyMessage(e)}\n（详情见「诊断」标签中的 Agent 日志）',
      );
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

  String? _linkedLoginDisplayName(String? loginId) {
    if (loginId == null || loginId.isEmpty) return null;
    for (final row in _logins) {
      if (row['id'] == loginId) {
        return _loginPickerLabel(row);
      }
    }
    return '（已删除）';
  }

  String _loginPickerLabel(Map<String, dynamic> row) {
    final dn = row['display_name']?.toString().trim() ?? '';
    if (dn.isNotEmpty) return dn;
    final user = row['username']?.toString() ?? '';
    final origin = row['origin']?.toString() ?? '';
    if (origin.isNotEmpty && user.isNotEmpty) return '$user @ $origin';
    return user.isNotEmpty ? user : origin;
  }

  String? _loginLinkedTotpId(String? loginId) {
    final id = dropdownValueIfPresent(loginId, _logins);
    if (id == null) return null;
    for (final row in _logins) {
      if (row['id'] == id) {
        return dropdownValueIfPresent(row['linked_totp_id'] as String?, _totps);
      }
    }
    return null;
  }

  /// 一键连接 / 复制 MFA：服务器单独关联优先，否则继承关联登录上的 MFA。
  String? _resolveTotpIdForServer(Map<String, dynamic> row) {
    final onServer = dropdownValueIfPresent(row['linked_totp_id'] as String?, _totps);
    if (onServer != null && onServer.isNotEmpty) return onServer;
    final loginId = dropdownValueIfPresent(row['linked_login_id'] as String?, _logins);
    return _loginLinkedTotpId(loginId);
  }

  bool _totpInheritedFromLogin(Map<String, dynamic> row) {
    final onServer = dropdownValueIfPresent(row['linked_totp_id'] as String?, _totps);
    if (onServer != null && onServer.isNotEmpty) return false;
    return _loginLinkedTotpId(dropdownValueIfPresent(row['linked_login_id'] as String?, _logins)) !=
        null;
  }

  Future<void> _addOrEdit({Map<String, dynamic>? existing}) async {
    final isEdit = existing != null;
    if (isEdit && !await requireTouchId(context, reason: '编辑服务器登录配置')) return;

    final labelCtl = TextEditingController(text: existing?['label']?.toString() ?? '');
    final hostCtl = TextEditingController(text: existing?['host']?.toString() ?? '');
    final portCtl = TextEditingController(text: '${existing?['port'] ?? 22}');
    final manualUserCtl = TextEditingController(text: existing?['manual_username']?.toString() ?? '');
    final rawLogin = existing?['linked_login_id'] as String?;
    final rawTotp = existing?['linked_totp_id'] as String?;
    final rawSsh = existing?['linked_ssh_key_id'] as String?;
    var linkedLogin = dropdownValueIfPresent(rawLogin, _logins);
    var linkedTotp = dropdownValueIfPresent(rawTotp, _totps);
    var linkedSsh = dropdownValueIfPresent(rawSsh, _sshKeys);
    final hadStaleLink = isEdit &&
        (staleLinkWasCleared(rawLogin, linkedLogin) ||
            staleLinkWasCleared(rawTotp, linkedTotp) ||
            staleLinkWasCleared(rawSsh, linkedSsh));

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
                  value: linkedLogin,
                  decoration: const InputDecoration(labelText: '关联登录密码'),
                  items: [
                    const DropdownMenuItem(value: null, child: Text('（不关联，使用下方手动用户名）')),
                    ..._logins.map(
                      (c) => DropdownMenuItem(
                        value: c['id'] as String,
                        child: Text(_loginPickerLabel(c)),
                      ),
                    ),
                  ],
                  onChanged: (v) => setLocal(() {
                    linkedLogin = v;
                    if ((linkedTotp == null || linkedTotp!.isEmpty) && v != null && v.isNotEmpty) {
                      for (final row in _logins) {
                        if (row['id'] == v) {
                          linkedTotp = dropdownValueIfPresent(
                            row['linked_totp_id'] as String?,
                            _totps,
                          );
                          break;
                        }
                      }
                    }
                  }),
                ),
                TextField(
                  controller: manualUserCtl,
                  enabled: linkedLogin == null || (linkedLogin?.isEmpty ?? true),
                  decoration: InputDecoration(
                    labelText: '手动 SSH 用户名',
                    hintText: linkedLogin == null || (linkedLogin?.isEmpty ?? true)
                        ? '未关联登录时必填'
                        : '已关联登录，用户名取自凭据',
                  ),
                ),
                DropdownButtonFormField<String?>(
                  value: linkedTotp,
                  decoration: const InputDecoration(
                    labelText: '关联 MFA / TOTP',
                    helperText: '留空则一键连接使用「关联登录」上的 MFA；此处若选择则覆盖登录',
                  ),
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
                  value: linkedSsh,
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

    if (hadStaleLink && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('部分关联凭据已删除，保存后将清除无效关联；请按需重新选择。'),
        ),
      );
    }

    final port = int.tryParse(portCtl.text.trim()) ?? 22;
    final noLinkedLogin = linkedLogin == null || (linkedLogin?.isEmpty ?? true);
    final manualUser = manualUserCtl.text.trim();
    if (noLinkedLogin && manualUser.isEmpty) {
      setState(() => _status = '未关联登录密码时，请填写手动 SSH 用户名');
      return;
    }
    try {
      if (isEdit) {
        await AgentBridge.updateServerProfile(
          id: existing!['id'] as String,
          expectedRevision: existing['current_revision'] as String,
          label: labelCtl.text.trim(),
          host: hostCtl.text.trim(),
          port: port,
          manualUsername: noLinkedLogin ? manualUser : '',
          linkedLoginId: linkedLogin,
          linkedTotpId: linkedTotp,
          linkedSshKeyId: linkedSsh,
        );
      } else {
        await AgentBridge.createServerProfile(
          label: labelCtl.text.trim().isEmpty ? hostCtl.text.trim() : labelCtl.text.trim(),
          host: hostCtl.text.trim(),
          port: port,
          manualUsername: noLinkedLogin ? manualUser : '',
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

  Future<String?> _resolveSshUsername(Map<String, dynamic> row) async {
    final loginId = row['linked_login_id'] as String?;
    if (loginId != null && loginId.isNotEmpty) {
      final u = await _loginUsername(loginId);
      if (u != null && u.isNotEmpty) return u;
    }
    final manual = row['manual_username']?.toString().trim() ?? '';
    return manual.isEmpty ? null : manual;
  }

  Future<String?> _activateLinkedSshKey(Map<String, dynamic> row) async {
    final keyId = dropdownValueIfPresent(row['linked_ssh_key_id'] as String?, _sshKeys);
    if (keyId == null || keyId.isEmpty) return null;
    try {
      await AgentBridge.selectSshKey(keyId);
      return null;
    } on AgentException catch (e) {
      return AgentBridge.friendlyMessage(e);
    }
  }

  Future<void> _openExpectAuto() async {
    final row = _selected;
    if (row == null) return;
    final host = row['host']?.toString().trim() ?? '';
    if (host.isEmpty) {
      setState(() => _status = '主机地址为空');
      return;
    }
    final loginId = dropdownValueIfPresent(row['linked_login_id'] as String?, _logins);
    if (loginId == null || loginId.isEmpty) {
      setState(() => _status = '一键连接需要有效关联登录密码（若已删除请重新编辑服务器）');
      return;
    }
    final username = await _resolveSshUsername(row);
    if (username == null || username.isEmpty) {
      setState(() => _status = '请关联登录凭据，或在编辑里填写「手动 SSH 用户名」');
      return;
    }
    if (!await ensureTerminalConfigured(context)) {
      setState(() => _status = '请先选择终端应用（终端设置）');
      return;
    }
    if (!await requireTouchId(context, reason: '一键 SSH 自动认证')) return;
    final totpId = _resolveTotpIdForServer(row);
    final String password;
    String? otp;
    try {
      if (totpId != null && totpId.isNotEmpty) {
        final results = await Future.wait<Object?>([
          AgentBridge.getCredential(loginId),
          AgentBridge.totpCode(totpId),
        ]);
        final detail = results[0]! as Map<String, dynamic>;
        password = detail['password'] as String? ?? '';
        otp = results[1] as String?;
      } else {
        final detail = await AgentBridge.getCredential(loginId);
        password = detail['password'] as String? ?? '';
      }
    } on AgentException catch (e) {
      setState(() => _status = AgentBridge.friendlyMessage(e));
      return;
    }
    if (password.isEmpty) {
      setState(() => _status = '关联的登录密码为空');
      return;
    }
    final sshErr = await _activateLinkedSshKey(row);
    if (sshErr != null) {
      setState(() => _status = sshErr);
      return;
    }
    final port = row['port'] is int ? row['port'] as int : int.tryParse('${row['port']}') ?? 22;
    final err = await AgentBridge.openSshExpect(
      host: host,
      port: port,
      username: username,
      password: password,
      otp: otp,
    );
    if (err != null && err.isNotEmpty) {
      setState(() => _status = err);
      return;
    }
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('已在终端中启动 expect 自动认证连接')),
      );
    }
  }

  Future<void> _openInTerminal() async {
    final row = _selected;
    if (row == null) return;
    final host = row['host']?.toString().trim() ?? '';
    if (host.isEmpty) {
      setState(() => _status = '主机地址为空');
      return;
    }
    final username = await _resolveSshUsername(row);
    if (username == null || username.isEmpty) {
      setState(() => _status = '请关联登录凭据，或在编辑里填写「手动 SSH 用户名」');
      return;
    }
    if (!await ensureTerminalConfigured(context)) {
      setState(() => _status = '请先选择终端应用（终端设置）');
      return;
    }
    final sshErr = await _activateLinkedSshKey(row);
    if (sshErr != null) {
      setState(() => _status = sshErr);
      return;
    }
    final port = row['port'] is int ? row['port'] as int : int.tryParse('${row['port']}') ?? 22;
    final err = await AgentBridge.openSshInTerminal(host: host, port: port, username: username);
    if (err != null && err.isNotEmpty) {
      setState(() => _status = err);
      return;
    }
    if (mounted) {
      final term = await loadTerminalApplication();
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('已在 ${terminalDisplayName(term)} 中打开 SSH')),
      );
    }
  }

  Future<void> _copyPassword() async {
    final loginId = dropdownValueIfPresent(_selected?['linked_login_id'] as String?, _logins);
    if (loginId == null || loginId.isEmpty) {
      setState(() => _status = '请先关联有效登录密码');
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
    final row = _selected;
    if (row == null) return;
    final totpId = _resolveTotpIdForServer(row);
    if (totpId == null || totpId.isEmpty) {
      setState(() => _status = '请在登录密码或本服务器上关联 MFA');
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
    final user = _selected == null ? null : await _resolveSshUsername(_selected!);
    if (user == null || user.isEmpty) {
      setState(() => _status = '无法生成 SSH 命令：缺少用户名');
      return;
    }
    final u = user;
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
          Row(
            children: [
              Expanded(
                child: FilledButton.icon(
                  onPressed: () => _addOrEdit(),
                  icon: const Icon(Icons.add),
                  label: const Text('添加服务器 / 堡垒机'),
                ),
              ),
              const SizedBox(width: 8),
              OutlinedButton(
                onPressed: () => showTerminalPickerDialog(context),
                child: const Text('终端设置'),
              ),
            ],
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
                      final loginLbl = _linkedLoginDisplayName(
                        row['linked_login_id'] as String?,
                      );
                      final effectiveTotpId = _resolveTotpIdForServer(row);
                      final totpLbl = effectiveTotpId == null
                          ? null
                          : _linkLabel(effectiveTotpId, _totps, 'issuer');
                      final inheritedTotp = _totpInheritedFromLogin(row);
                      final manualUser = row['manual_username']?.toString().trim() ?? '';
                      final sub = [
                        '${row['host']}:${row['port']}',
                        if (loginLbl != null) '登录: $loginLbl',
                        if (loginLbl == null && manualUser.isNotEmpty) '用户: $manualUser',
                        if (totpLbl != null)
                          inheritedTotp ? 'MFA: $totpLbl（继承登录）' : 'MFA: $totpLbl',
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
                FilledButton.icon(
                  onPressed: _openExpectAuto,
                  icon: const Icon(Icons.bolt),
                  label: const Text('一键连接（密码+MFA）'),
                ),
                OutlinedButton.icon(
                  onPressed: _openInTerminal,
                  icon: const Icon(Icons.terminal),
                  label: const Text('仅打开 SSH'),
                ),
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
