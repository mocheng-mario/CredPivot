import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';
import 'credential_group_ui.dart';
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
  List<Map<String, dynamic>> _groups = [];
  String? _filterGroupId;
  Map<String, dynamic>? _selected;
  String _status = '';
  int _refreshGeneration = 0;
  bool _copyingTerminalCommand = false;

  void _onVaultChanged() { if (mounted) _refresh(); }

  @override
  void dispose() {
    AgentBridge.vaultChanges.removeListener(_onVaultChanged);
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
    AgentBridge.vaultChanges.addListener(_onVaultChanged);
    _refresh();
  }

  Future<void> _refresh() async {
    final generation = ++_refreshGeneration;
    try {
      final items = await AgentBridge.listServerProfiles();
      final logins = await AgentBridge.listCredentials();
      final totps = await AgentBridge.listTotp();
      final sshKeys = await AgentBridge.listSshKeys();
      final groups = await loadCredentialGroups('server');
      if (!mounted || generation != _refreshGeneration) return;
      final selectedId = _selected?['id'];
      setState(() {
        _items = items;
        _logins = logins;
        _totps = totps;
        _sshKeys = sshKeys;
        _groups = groups;
        _filterGroupId = dropdownValueIfPresent(_filterGroupId, groups);
        _selected = null;
        for (final row in items) {
          if (row['id'] == selectedId &&
              (_filterGroupId == null || row['group_id'] == _filterGroupId)) _selected = row;
        }
        _status = '';
      });
    } on AgentException catch (e) {
      if (mounted && generation == _refreshGeneration) setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  String? _linkLabel(String? id, List<Map<String, dynamic>> pool, String field) {
    if (id == null || id.isEmpty) return null;
    for (final row in pool) {
      if (row['id'] == id) {
        return row[field]?.toString();
      }
    }
    return '${tr('server.linkLabel.text')} ($id)';
  }

  String? _linkedLoginDisplayName(String? loginId) {
    if (loginId == null || loginId.isEmpty) return null;
    for (final row in _logins) {
      if (row['id'] == loginId) {
        return _loginPickerLabel(row);
      }
    }
    return '${tr('server.linkLabel.text')} ($loginId)';
  }

  String? _resolveTotpIdForServer(Map<String, dynamic> row) {
    return dropdownValueIfPresent(row['linked_totp_id'] as String?, _totps);
  }

  Future<void> _addOrEdit({Map<String, dynamic>? existing}) async {
    if (await showServerProfileEditor(context, existing: existing) && mounted) {
      AgentBridge.notifyVaultChanged();
      await _refresh();
    }
  }

  Future<void> _deleteSelected() async {
    final row = _selected;
    if (row == null) return;
    if (!await confirmCredentialDanger(
      context,
      title: tr('server.deleteSelected.title'),
      message: tr('server.delete.confirmation', args: {'label': row['label']}),
    )) {
      return;
    }
    if (!await requireTouchId(context, reason: tr('server.deleteSelected.title'), confirmed: true)) return;
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
    // SSH 用户名已经在列表元数据中，不应为解析用户名提前读取密码。
    for (final login in _logins) {
      if (login['id'] == loginId) return login['username']?.toString();
    }
    return null;
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

  Future<String?> _linkedSshIdentityFile(Map<String, dynamic> row) async {
    final keyId = dropdownValueIfPresent(row['linked_ssh_key_id'] as String?, _sshKeys);
    if (keyId == null || keyId.isEmpty) return null;
    return AgentBridge.prepareSshIdentityFile(keyId);
  }

  Future<void> _openSshAuto() async {
    final row = _selected;
    if (row == null) return;
    if (row['unavailable'] == true) {
      final reason = row['unavailable_reason']?.toString() ?? '';
      setState(() => _status = reason.isEmpty ? '这条连接已停用，需要重新确认后才能使用' : reason);
      return;
    }
    final host = row['host']?.toString().trim() ?? '';
    if (host.isEmpty) {
      setState(() => _status = tr('server.openSshAuto.text'));
      return;
    }
    final loginId = dropdownValueIfPresent(row['linked_login_id'] as String?, _logins);
    final manualUser = row['manual_username']?.toString().trim() ?? '';
    if ((loginId == null || loginId.isEmpty) && manualUser.isEmpty) {
      setState(() => _status = tr('server.openSshAuto.text.item2'));
      return;
    }
    final username = await _resolveSshUsername(row);
    if (username == null || username.isEmpty) {
      setState(() => _status = tr('server.openSshAuto.text.item3'));
      return;
    }
    if (!await ensureTerminalConfigured(context)) {
      setState(() => _status = tr('server.openSshAuto.text.item4'));
      return;
    }
    if (!await requireTouchId(context, reason: tr('server.openSshAuto.reason'))) return;
    final totpId = _resolveTotpIdForServer(row);
    final port = row['port'] is int ? row['port'] as int : int.tryParse('${row['port']}') ?? 22;
    String sessionId;
    String? identityFile;
    try {
      final prepared = await AgentBridge.sshSessionPrepare(
        host: host,
        port: port,
        user: username,
        loginCredentialId: loginId ?? '',
        totpId: totpId,
        serverProfileId: row['id']?.toString(),
      );
      sessionId = prepared['session_id'] as String;
      identityFile = prepared['identity_file'] as String?;
      await AgentBridge.materializeSshAskpass();
    } on AgentException catch (e) {
      setState(() => _status = AgentBridge.friendlyMessage(e));
      return;
    }
    final err = await AgentBridge.openSshWithAskpass(
      host: host,
      port: port,
      username: username,
      sessionId: sessionId,
      identityFile: identityFile,
    );
    if (err != null && err.isNotEmpty) {
      setState(() => _status = err);
      return;
    }
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: LText('server.openSshAuto.text.item5')),
      );
    }
  }

  Future<void> _openInTerminal() async {
    final row = _selected;
    if (row == null) return;
    if (row['unavailable'] == true) {
      final reason = row['unavailable_reason']?.toString() ?? '';
      setState(() => _status = reason.isEmpty ? '这条连接已停用，需要重新确认后才能使用' : reason);
      return;
    }
    final host = row['host']?.toString().trim() ?? '';
    if (host.isEmpty) {
      setState(() => _status = tr('server.openSshAuto.text'));
      return;
    }
    final username = await _resolveSshUsername(row);
    if (username == null || username.isEmpty) {
      setState(() => _status = tr('server.openSshAuto.text.item3'));
      return;
    }
    if (!await ensureTerminalConfigured(context)) {
      setState(() => _status = tr('server.openSshAuto.text.item4'));
      return;
    }
    String? identityFile;
    try { identityFile = await _linkedSshIdentityFile(row); }
    catch (e) { if (mounted) setState(() => _status = e is AgentException ? AgentBridge.friendlyMessage(e) : tr('ssh.git.failed')); return; }
    final port = row['port'] is int ? row['port'] as int : int.tryParse('${row['port']}') ?? 22;
    final err = await AgentBridge.openSshInTerminal(host: host, port: port, username: username, identityFile: identityFile);
    if (err != null && err.isNotEmpty) {
      setState(() => _status = err);
      return;
    }
    if (mounted) {
      final term = await loadTerminalApplication();
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: LText('server.status.sshOpened', args: {'terminal': terminalDisplayName(term)})),
      );
    }
  }

  Future<void> _copyPassword() async {
    final row = _selected;
    if (row == null) return;
    if (_selected?['unavailable'] == true) {
      setState(() => _status = _selected?['unavailable_reason']?.toString().isNotEmpty == true
          ? _selected!['unavailable_reason'].toString()
          : '这条连接已停用，需要重新确认后才能使用');
      return;
    }
    try {
      final session = await AgentBridge.clipboardSession();
      if (!mounted || !await requireTouchId(context, reason: tr('server.copyPassword.reason'))) return;
      final detail = await AgentBridge.manage({'action': 'server_profile_password', 'id': row['id']});
      await AgentBridge.copyConcealed(detail['password'] as String? ?? '', session: session);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: LText('server.copyPassword.text.item2')),
        );
      }
    } on AgentException catch (e) {
      if (mounted) setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  Future<void> _copyMfa() async {
    final row = _selected;
    if (row == null) return;
    if (row['unavailable'] == true) {
      setState(() => _status = row['unavailable_reason']?.toString().isNotEmpty == true
          ? row['unavailable_reason'].toString()
          : '这条连接已停用，需要重新确认后才能使用');
      return;
    }
    final totpId = _resolveTotpIdForServer(row);
    if (totpId == null || totpId.isEmpty) {
      setState(() => _status = tr('server.copyMfa.text'));
      return;
    }
    try {
      final session = await AgentBridge.clipboardSession();
      if (!mounted) return;
      final code = await AgentBridge.totpCode(totpId);
      await AgentBridge.copyConcealed(code, session: session);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: LText('server.copyMfa.text.item2', args: {'code': code})),
        );
      }
    } on AgentException catch (e) {
      if (mounted) setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  Future<void> _copyTerminalConnectCommand() async {
    final row = _selected;
    if (row == null || _copyingTerminalCommand) return;
    if (row['unavailable'] == true) {
      setState(() => _status = row['unavailable_reason']?.toString().isNotEmpty == true
          ? row['unavailable_reason'].toString() : '这条连接已停用，需要重新确认后才能使用');
      return;
    }
    setState(() => _copyingTerminalCommand = true);
    try {
      final command = await AgentBridge.terminalConnectCommand(row['id'].toString());
      await Clipboard.setData(ClipboardData(text: command));
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('server.terminal.copied')));
    } catch (error) {
      if (mounted) setState(() => _status = error is AgentException
          ? AgentBridge.friendlyMessage(error) : tr('server.terminal.unavailable'));
    } finally {
      if (mounted) setState(() => _copyingTerminalCommand = false);
    }
  }

  Future<void> _copySshHint() async {
    final host = _selected?['host']?.toString() ?? '';
    final port = _selected?['port'] ?? 22;
    final user = _selected == null ? null : await _resolveSshUsername(_selected!);
    if (user == null || user.isEmpty) {
      setState(() => _status = tr('server.copySshHint.text'));
      return;
    }
    final u = user;
    final line = port == 22 ? 'ssh $u@$host' : 'ssh -p $port $u@$host';
    await Clipboard.setData(ClipboardData(text: line));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: LText('server.copySshHint.text.item2', args: {'line': line})));
    }
  }

  @override
  Widget build(BuildContext context) {
    final visibleItems = _items
        .where((row) => _filterGroupId == null || row['group_id'] == _filterGroupId)
        .toList();
    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 12, 24, 20),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        AppSectionHeader(
          title: tr('credentials.server.title'),
          subtitle: tr('server.list.count', args: {'count': visibleItems.length}),
          action: Wrap(spacing: 8, runSpacing: 8, children: [
            OutlinedButton.icon(
                onPressed: () => showTerminalPickerDialog(context),
                icon: const Icon(Icons.terminal_rounded),
                label: const LText('server.build.text')),
            FilledButton.icon(
                onPressed: () => _addOrEdit(),
                icon: const Icon(Icons.add_rounded),
                label: const LText('server.build.text.item2')),
          ]),
        ),
        if (_status.isNotEmpty) AppNotice(_status),
        buildGroupFilterBar(
          groups: _groups,
          selectedGroupId: _filterGroupId,
          onChanged: (value) => setState(() {
            _filterGroupId = value;
            _selected = null;
          }),
          onManage: () => showManageGroupsDialog(context, 'server').then((_) => _refresh()),
        ),
        Expanded(
            child: CredentialWorkspace(
          list: visibleItems.isEmpty
              ? AppEmptyState(
                  icon: Icons.dns_outlined,
                  title: tr('server.build.title'),
                  message: tr('server.build.message'))
              : buildGroupedList(
                  scope: 'server',
                  groups: _groups,
                  items: visibleItems,
                  tileBuilder: (row) {
                    final selected = _selected?['id'] == row['id'];
                    final loginLbl = _linkedLoginDisplayName(
                      row['linked_login_id'] as String?,
                    );
                    final effectiveTotpId = _resolveTotpIdForServer(row);
                    final totpLbl = effectiveTotpId == null
                        ? null
                        : _linkLabel(effectiveTotpId, _totps, 'issuer');
                    final manualUser =
                        row['manual_username']?.toString().trim() ?? '';
                    final unavailable = row['unavailable'] == true;
                    final sub = [
                      if (unavailable) (row['unavailable_reason']?.toString().isNotEmpty == true
                          ? row['unavailable_reason'].toString()
                          : '已停用'),
                      '${row['host']}:${row['port']}',
                      if (loginLbl != null) tr('server.links.login', args: {'login': loginLbl}),
                      if (loginLbl == null && manualUser.isNotEmpty)
                        tr('server.links.user', args: {'username': manualUser}),
                      if (totpLbl != null) 'MFA: $totpLbl',
                    ].join(' · ');
                    return selectableCredentialTile(
                      context: context,
                      icon: Icons.dns_outlined,
                      selected: selected,
                      title: Text(row['label']?.toString() ??
                          row['host']?.toString() ??
                          ''),
                      subtitle: Text(sub),
                      onTap: () => setState(() => _selected = row),
                    );
                  },
                ),
          detail: _selected == null
              ? null
              : CredentialDetails(
                  title: _selected!['label']?.toString() ??
                      _selected!['host']?.toString() ??
                      tr('credentials.server.title'),
                  icon: Icons.dns_outlined,
                  fields: {
                    tr('server.fields.host'): _selected!['host']?.toString() ?? '',
                    tr('server.fields.port'): _selected!['port']?.toString() ?? '',
                    tr('server.fields.account'): _linkedLoginDisplayName(
                            (_selected!['linked_login_id'] ?? _selected!['stale_linked_login_id']) as String?) ??
                        _selected!['manual_username']?.toString() ??
                        '',
                    'MFA': _linkLabel((_selected!['linked_totp_id'] ?? _selected!['stale_linked_totp_id']) as String?, _totps, 'issuer') ?? tr('common.notLinked'),
                    'SSH 密钥': _linkLabel((_selected!['linked_ssh_key_id'] ?? _selected!['stale_linked_ssh_key_id']) as String?, _sshKeys, 'label') ?? tr('common.notLinked'),
                  },
                  copyableFields: {tr('server.fields.host')},
                ),
          actions: _selected == null
                ? null
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      CredentialActionSection(
                        title: tr('server.build.title.item2'),
                        children: [
                          FilledButton.icon(
                            onPressed: _openSshAuto,
                            icon: const Icon(Icons.bolt),
                            label: const LText('server.build.text.item8'),
                          ),
                          OutlinedButton.icon(
                            onPressed: _openInTerminal,
                            icon: const Icon(Icons.terminal),
                            label: const LText('server.build.text.item9'),
                          ),
                          if (Platform.isMacOS) OutlinedButton.icon(
                            onPressed: _copyingTerminalCommand || _selected!['unavailable'] == true ? null : _copyTerminalConnectCommand,
                            icon: const Icon(Icons.copy_rounded),
                            label: const LText('server.terminal.copy'),
                          ),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('server.build.title.item3'),
                        children: [
                          OutlinedButton(
                              onPressed: _copySshHint,
                              child: const LText('server.build.text.item10')),
                          OutlinedButton(
                              onPressed: _copyPassword, child: const LText('server.build.text.item11')),
                          FilledButton.tonal(
                              onPressed: _copyMfa, child: const LText('server.build.text.item12')),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('server.build.title.item4'),
                        children: [
                          OutlinedButton(
                              onPressed: () => _addOrEdit(existing: _selected),
                              child: const LText('common.edit')),
                          OutlinedButton(
                              onPressed: () async {
                                final row = _selected!;
                                await showMoveItemToGroupDialog(context, scope: 'server',
                                    itemId: row['item_id'] as String,
                                    currentGroupId: row['group_id'] as String?);
                                if (mounted) await _refresh();
                              },
                              child: const LText('credentials.build.text.item20')),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('server.build.title.item5'),
                        dangerous: true,
                        children: [
                          OutlinedButton(
                              onPressed: _deleteSelected, child: const LText('common.delete')),
                        ],
                      ),
                    ],
                  ),
        )),
      ]),
    );
  }
}

String _loginPickerLabel(Map<String, dynamic> row) {
    final dn = row['display_name']?.toString().trim() ?? '';
    if (dn.isNotEmpty) return dn;
    final user = row['username']?.toString() ?? '';
    final origin = row['origin']?.toString() ?? '';
    if (origin.isNotEmpty && user.isNotEmpty) return '$user @ $origin';
    return user.isNotEmpty ? user : origin;
  }


Future<bool> showServerProfileEditor(BuildContext context, {Map<String, dynamic>? existing}) async {
    final isEdit = existing != null;
    final partition = existing?['partition_id']?.toString() ?? AgentBridge.activePartitionId;
    List<Map<String, dynamic>> logins, totps, sshKeys, groups;
    try {
      logins = await AgentBridge.listCredentials(null, partition);
      totps = await AgentBridge.listTotp(partitionId: partition);
      sshKeys = await AgentBridge.listSshKeys(partitionId: partition);
      groups = await loadCredentialGroups('server', partitionId: partition);
    } on AgentException catch (e) {
      if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(AgentBridge.friendlyMessage(e))));
      return false;
    }
    if (!context.mounted) return false;

    final labelCtl = TextEditingController(text: existing?['label']?.toString() ?? '');
    final hostCtl = TextEditingController(text: existing?['host']?.toString() ?? '');
    final portCtl = TextEditingController(text: '${existing?['port'] ?? 22}');
    final manualUserCtl = TextEditingController(text: existing?['manual_username']?.toString() ?? '');
    final manualSecretCtl = TextEditingController();
    final rawLogin = (existing?['linked_login_id'] ?? existing?['stale_linked_login_id']) as String?;
    final rawTotp = (existing?['linked_totp_id'] ?? existing?['stale_linked_totp_id']) as String?;
    final rawSsh = (existing?['linked_ssh_key_id'] ?? existing?['stale_linked_ssh_key_id']) as String?;
    var linkedLogin = rawLogin?.isEmpty == true ? null : rawLogin;
    var linkedTotp = rawTotp?.isEmpty == true ? null : rawTotp;
    var linkedSsh = rawSsh?.isEmpty == true ? null : rawSsh;
    var groupId = dropdownValueIfPresent(existing?['group_id'] as String?, groups);
    final hadStaleLink = existing?['unavailable'] == true;

    bool selectable(String? id, List<Map<String, dynamic>> pool, String field) {
      if (id == null || id.isEmpty) return true;
      if (!pool.any((row) => row['id'] == id)) return false;
      if (linkedLogin == null || linkedLogin!.isEmpty) return true;
      final login = logins.where((row) => row['id'] == linkedLogin);
      return login.isNotEmpty && ((login.first[field] as List?) ?? const []).contains(id);
    }

    String snapshot() => jsonEncode([labelCtl.text,hostCtl.text,portCtl.text,manualUserCtl.text,manualSecretCtl.text,linkedLogin,linkedTotp,linkedSsh,groupId]);
    final initialSnapshot = snapshot();
    var closing = false, confirmingDiscard = false, saving = false;
    var formError = '';
    ModalRoute<bool>? dialogRoute;
    Future<void> cancel(BuildContext ctx) async {
      if (closing || confirmingDiscard || saving) return;
      confirmingDiscard = true;
      try {
        if (snapshot() != initialSnapshot && !await confirmDiscardChanges(ctx)) return;
        if (ctx.mounted) { closing = true; Navigator.pop(ctx, false); }
      } finally { confirmingDiscard = false; }
    }
    Future<bool> confirmConnectionWarnings(BuildContext ctx) async {
      final notes = <String>[];
      final independent = linkedLogin == null || linkedLogin!.isEmpty;
      if (!independent) {
        final profiles = await AgentBridge.listServerProfiles(partitionId: partition);
        final host = hostCtl.text.trim().toLowerCase();
        final selfId = existing?['id'];
        final duplicate = profiles.any((row) => row['id'] != selfId
            && (row['host']?.toString().trim().toLowerCase() == host)
            && row['linked_login_id'] == linkedLogin);
        if (duplicate) notes.add(tr('server.warn.sameHost'));
      } else {
        final lines = <String>[];
        void collect(String? id, String field, String kind) {
          if (id == null || id.isEmpty) return;
          final names = <String>[];
          for (final login in logins) {
            final ids = ((login[field] as List?) ?? const []).map((item) => item.toString());
            if (!ids.contains(id)) continue;
            names.add(_loginPickerLabel(login));
          }
          if (names.isNotEmpty) lines.add('$kind：${names.join('、')}');
        }
        collect(linkedTotp, 'linked_mfa_ids', tr('server.warn.mfa'));
        collect(linkedSsh, 'linked_ssh_key_ids', tr('server.warn.ssh'));
        if (lines.isNotEmpty) notes.add(tr('server.warn.linkedAccounts', args: {'accounts': lines.join('\n')}));
      }
      if (notes.isEmpty || !ctx.mounted) return notes.isEmpty;
      final go = await showDialog<bool>(context: ctx, builder: (dialogContext) => AlertDialog(
        title: const LText('server.warn.title'),
        content: SingleChildScrollView(child: Text(notes.join('\n\n'))),
        actions: [
          TextButton(onPressed: () => Navigator.pop(dialogContext, false), child: const LText('common.cancel')),
          FilledButton(onPressed: () => Navigator.pop(dialogContext, true), child: const LText('server.warn.continue')),
        ],
      ));
      return go == true;
    }
    Future<void> save(BuildContext ctx, StateSetter setLocal) async {
      if (saving || closing) return;
      final port = int.tryParse(portCtl.text.trim());
      final noLinkedLogin = linkedLogin == null || linkedLogin!.isEmpty;
      if (hostCtl.text.trim().isEmpty || port == null || port < 1 || port > 65535 ||
          (noLinkedLogin && (manualUserCtl.text.trim().isEmpty ||
            (manualSecretCtl.text.isEmpty && existing?['has_manual_secret'] != true)))) {
        setLocal(() => formError = tr('server.save.text'));
        return;
      }
      if ((!noLinkedLogin && !logins.any((row) => row['id'] == linkedLogin)) ||
          !selectable(linkedTotp, totps, 'linked_mfa_ids') || !selectable(linkedSsh, sshKeys, 'linked_ssh_key_ids')) {
        setLocal(() => formError = '旧关联已不可用，请重新选择同一分区内仍然有效的账户、MFA 或 SSH 密钥');
        return;
      }
      setLocal(() { saving = true; formError = ''; });
      try {
        if (!await confirmConnectionWarnings(ctx)) return;
        if (isEdit && !await requireTouchId(ctx, reason: tr('server.save.reason'))) return;
        if (!ctx.mounted || closing) return;
        if (isEdit) {
          await AgentBridge.updateServerProfile(
            id: existing['id'] as String,
            expectedRevision: existing['current_revision'] as String,
            label: labelCtl.text.trim(), host: hostCtl.text.trim(), port: port,
            manualUsername: noLinkedLogin ? manualUserCtl.text.trim() : '',
            manualSecret: noLinkedLogin && manualSecretCtl.text.isNotEmpty ? manualSecretCtl.text : null,
            linkedLoginId: linkedLogin, linkedTotpId: linkedTotp, linkedSshKeyId: linkedSsh,
            groupId: groupId,
          );
        } else {
          await AgentBridge.createServerProfile(
            partitionId: partition,
            label: labelCtl.text.trim().isEmpty ? hostCtl.text.trim() : labelCtl.text.trim(),
            host: hostCtl.text.trim(), port: port,
            manualUsername: noLinkedLogin ? manualUserCtl.text.trim() : '',
            manualSecret: noLinkedLogin ? manualSecretCtl.text : null,
            linkedLoginId: linkedLogin, linkedTotpId: linkedTotp, linkedSshKeyId: linkedSsh,
            groupId: groupId,
          );
        }
        if (ctx.mounted && !closing) {
          closing = true;
          Navigator.pop(ctx, true);
          if (hadStaleLink && context.mounted) ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('连接已重新确认，旧引用已按本次选择更新')));
        }
      } catch (e) {
        if (ctx.mounted && !closing) setLocal(() => formError = e is AgentException ? AgentBridge.friendlyMessage(e) : tr('common.saveFailed'));
      } finally {
        if (ctx.mounted && !closing) setLocal(() => saving = false);
      }
    }
    try {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) {
        dialogRoute = ModalRoute.of<bool>(ctx);
        return PopScope(canPop: false, onPopInvokedWithResult: (didPop, _) { if (!didPop) cancel(ctx); }, child: StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
          title: LText(isEdit ? tr('server.save.text.item3') : tr('server.save.text.item4')),
          content: SizedBox(width: appEditDialogWidth(ctx), child: AbsorbPointer(absorbing: saving, child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: appFormFields([
                if (existing?['unavailable'] == true)
                  Text(existing?['unavailable_reason']?.toString().isNotEmpty == true
                      ? existing!['unavailable_reason'].toString()
                      : '这条连接已停用，重新选择并保存后才能使用'),
                if (hadStaleLink) Text([
                  if (rawLogin?.isNotEmpty == true) '原账户：$rawLogin',
                  if (rawTotp?.isNotEmpty == true) '原 MFA：$rawTotp',
                  if (rawSsh?.isNotEmpty == true) '原 SSH 密钥：$rawSsh',
                  '旧引用仅供查看；无效项需要重新选择或清除。',
                ].join('\n')),
                AppFieldRow(label: tr('common.name'), child: TextField(controller: labelCtl, decoration: InputDecoration())),
                AppFieldRow(label: tr('common.group'), child: DropdownButtonFormField<String?>(
                  isExpanded: true,
                  value: groupId,
                  decoration: InputDecoration(),
                  items: [
                    const DropdownMenuItem(value: null, child: LText('common.ungroupedOption')),
                    for (final group in groups)
                      DropdownMenuItem(value: group['id'] as String,
                          child: Text(credentialGroupLabel(group), maxLines: 1, overflow: TextOverflow.ellipsis)),
                  ],
                  onChanged: (value) => setLocal(() => groupId = value),
                )),
                AppFieldRow(label: tr('server.save.text.item5'), child: TextField(
                  controller: hostCtl,
                  decoration: InputDecoration(),
                )),
                AppFieldRow(label: tr('server.fields.port'), child: TextField(
                  controller: portCtl,
                  decoration: InputDecoration(),
                  keyboardType: TextInputType.number,
                )),
                const SizedBox(height: 8),
                AppFieldRow(label: tr('server.save.text.item6'), child: DropdownButtonFormField<String?>(
                  isExpanded: true,
                  value: linkedLogin,
                  decoration: InputDecoration(),
                  items: [
                    const DropdownMenuItem(value: null, child: LText('server.save.text.item7')),
                    if (linkedLogin != null && !logins.any((row) => row['id'] == linkedLogin))
                      DropdownMenuItem(value: linkedLogin, enabled: false, child: Text('旧账户：$linkedLogin（需重新选择）')),
                    ...logins.map(
                      (c) => DropdownMenuItem(
                        value: c['id'] as String,
                        child: Text(
                          _loginPickerLabel(c),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ),
                  ],
                  onChanged: (v) => setLocal(() {
                    if (v != linkedLogin) {
                      linkedTotp = null;
                      linkedSsh = null;
                    }
                    linkedLogin = v;
                  }),
                )),
                if (linkedLogin == null || (linkedLogin?.isEmpty ?? true)) ...[
                  AppFieldRow(label: tr('server.save.text.item8'), child: TextField(
                    controller: manualUserCtl,
                    decoration: InputDecoration(hintText: tr('server.save.text.item9')),
                  )),
                  AppFieldRow(label: tr('common.password'), child: TextField(
                    controller: manualSecretCtl,
                    obscureText: true,
                    decoration: InputDecoration(hintText: existing?['has_manual_secret'] == true ? '留空则保持原密码' : '请填写连接自己的密码'),
                  )),
                ],
                AppFieldRow(label: tr('server.save.text.item11'), help: tr('server.save.text.item12'), child: DropdownButtonFormField<String?>(
                  isExpanded: true,
                  value: linkedTotp,
                  decoration: InputDecoration(),
                  items: [
                    const DropdownMenuItem(value: null, child: LText('server.save.text.item13')),
                    if (!selectable(linkedTotp, totps, 'linked_mfa_ids'))
                      DropdownMenuItem(value: linkedTotp, enabled: false, child: Text('旧 MFA：$linkedTotp（需重新选择）')),
                    ...totps.where((t) => selectable(t['id'] as String?, totps, 'linked_mfa_ids')).map(
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
                )),
                AppFieldRow(label: tr('server.save.text.item14'), child: DropdownButtonFormField<String?>(
                  isExpanded: true,
                  value: linkedSsh,
                  decoration: InputDecoration(),
                  items: [
                    const DropdownMenuItem(value: null, child: LText('server.save.text.item13')),
                    if (!selectable(linkedSsh, sshKeys, 'linked_ssh_key_ids'))
                      DropdownMenuItem(value: linkedSsh, enabled: false, child: Text('旧 SSH 密钥：$linkedSsh（需重新选择）')),
                    ...sshKeys.where((s) => selectable(s['id'] as String?, sshKeys, 'linked_ssh_key_ids')).map(
                      (s) => DropdownMenuItem(
                        value: s['id'] as String,
                        child: Text(
                          s['label']?.toString() ?? 'SSH',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ),
                  ],
                  onChanged: (v) => setLocal(() => linkedSsh = v),
                )),
                if (formError.isNotEmpty) LText(formError, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
              ]),
            ),
          ))),
          actions: [
            TextButton(onPressed: saving ? null : () => cancel(ctx), child: const LText('common.cancel')),
            FilledButton(onPressed: saving ? null : () => save(ctx, setLocal), child: LText(saving ? tr('common.saving') : tr('common.save'))),
          ],
        ),
      ));
      },
    );
    return ok == true;
    } finally {
      await dialogRoute?.completed;
      labelCtl.dispose();
      hostCtl.dispose();
      portCtl.dispose();
      manualUserCtl.dispose();
      manualSecretCtl.dispose();
    }

  }
