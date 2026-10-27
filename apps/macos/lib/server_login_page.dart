import 'dart:convert';

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
    return tr('server.linkLabel.text');
  }

  String? _linkedLoginDisplayName(String? loginId) {
    if (loginId == null || loginId.isEmpty) return null;
    for (final row in _logins) {
      if (row['id'] == loginId) {
        return _loginPickerLabel(row);
      }
    }
    return tr('server.linkLabel.text');
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

  Future<void> _openSshAuto() async {
    final row = _selected;
    if (row == null) return;
    final host = row['host']?.toString().trim() ?? '';
    if (host.isEmpty) {
      setState(() => _status = tr('server.openSshAuto.text'));
      return;
    }
    final loginId = dropdownValueIfPresent(row['linked_login_id'] as String?, _logins);
    if (loginId == null || loginId.isEmpty) {
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
    final sshErr = await _activateLinkedSshKey(row);
    if (sshErr != null) {
      setState(() => _status = sshErr);
      return;
    }
    final port = row['port'] is int ? row['port'] as int : int.tryParse('${row['port']}') ?? 22;
    String sessionId;
    try {
      sessionId = await AgentBridge.sshSessionPrepare(
        host: host,
        port: port,
        user: username,
        loginCredentialId: loginId,
        totpId: totpId,
      );
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
        SnackBar(content: LText('server.status.sshOpened', args: {'terminal': terminalDisplayName(term)})),
      );
    }
  }

  Future<void> _copyPassword() async {
    final loginId = dropdownValueIfPresent(_selected?['linked_login_id'] as String?, _logins);
    if (loginId == null || loginId.isEmpty) {
      setState(() => _status = tr('server.copyPassword.text'));
      return;
    }
    if (!await requireTouchId(context, reason: tr('server.copyPassword.reason'))) return;
    final detail = await AgentBridge.getCredential(loginId);
    await AgentBridge.copyConcealed(detail['password'] as String? ?? '');
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: LText('server.copyPassword.text.item2')),
      );
    }
  }

  Future<void> _copyMfa() async {
    final row = _selected;
    if (row == null) return;
    final totpId = _resolveTotpIdForServer(row);
    if (totpId == null || totpId.isEmpty) {
      setState(() => _status = tr('server.copyMfa.text'));
      return;
    }
    if (!await requireTouchId(context, reason: tr('server.copyMfa.reason'))) return;
    try {
      final code = await AgentBridge.totpCode(totpId);
      await AgentBridge.copyConcealed(code);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: LText('server.copyMfa.text.item2', args: {'code': code})),
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
              : ListView(
                  children: buildGroupedListTiles(
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
                    final inheritedTotp = _totpInheritedFromLogin(row);
                    final manualUser =
                        row['manual_username']?.toString().trim() ?? '';
                    final sub = [
                      '${row['host']}:${row['port']}',
                      if (loginLbl != null) tr('server.links.login', args: {'login': loginLbl}),
                      if (loginLbl == null && manualUser.isNotEmpty)
                        tr('server.links.user', args: {'username': manualUser}),
                      if (totpLbl != null)
                        inheritedTotp ? tr('server.links.inheritedMfa', args: {'mfa': totpLbl}) : 'MFA: $totpLbl',
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
                )),
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
                            _selected!['linked_login_id'] as String?) ??
                        _selected!['manual_username']?.toString() ??
                        '',
                    'MFA': _resolveTotpIdForServer(_selected!) == null
                        ? tr('common.notLinked')
                        : (_totpInheritedFromLogin(_selected!)
                            ? tr('server.build.text.item6')
                            : tr('server.build.text.item7')),
                  },
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
    final rawLogin = existing?['linked_login_id'] as String?;
    final rawTotp = existing?['linked_totp_id'] as String?;
    final rawSsh = existing?['linked_ssh_key_id'] as String?;
    var linkedLogin = dropdownValueIfPresent(rawLogin, logins);
    var linkedTotp = dropdownValueIfPresent(rawTotp, totps);
    var linkedSsh = dropdownValueIfPresent(rawSsh, sshKeys);
    var groupId = dropdownValueIfPresent(existing?['group_id'] as String?, groups);
    final hadStaleLink = isEdit &&
        (staleLinkWasCleared(rawLogin, linkedLogin) ||
            staleLinkWasCleared(rawTotp, linkedTotp) ||
            staleLinkWasCleared(rawSsh, linkedSsh));

    String snapshot() => jsonEncode([labelCtl.text,hostCtl.text,portCtl.text,manualUserCtl.text,linkedLogin,linkedTotp,linkedSsh,groupId]);
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
    Future<void> save(BuildContext ctx, StateSetter setLocal) async {
      if (saving || closing) return;
      final port = int.tryParse(portCtl.text.trim());
      final noLinkedLogin = linkedLogin == null || linkedLogin!.isEmpty;
      if (hostCtl.text.trim().isEmpty || port == null || port < 1 || port > 65535 ||
          (noLinkedLogin && manualUserCtl.text.trim().isEmpty)) {
        setLocal(() => formError = tr('server.save.text'));
        return;
      }
      setLocal(() { saving = true; formError = ''; });
      try {
        if (isEdit && !await requireTouchId(ctx, reason: tr('server.save.reason'))) return;
        if (!ctx.mounted || closing) return;
        if (isEdit) {
          await AgentBridge.updateServerProfile(
            id: existing!['id'] as String,
            expectedRevision: existing['current_revision'] as String,
            label: labelCtl.text.trim(), host: hostCtl.text.trim(), port: port,
            manualUsername: noLinkedLogin ? manualUserCtl.text.trim() : '',
            linkedLoginId: linkedLogin, linkedTotpId: linkedTotp, linkedSshKeyId: linkedSsh,
            groupId: groupId,
          );
        } else {
          await AgentBridge.createServerProfile(
            partitionId: partition,
            label: labelCtl.text.trim().isEmpty ? hostCtl.text.trim() : labelCtl.text.trim(),
            host: hostCtl.text.trim(), port: port,
            manualUsername: noLinkedLogin ? manualUserCtl.text.trim() : '',
            linkedLoginId: linkedLogin, linkedTotpId: linkedTotp, linkedSshKeyId: linkedSsh,
            groupId: groupId,
          );
        }
        if (ctx.mounted && !closing) {
          closing = true;
          Navigator.pop(ctx, true);
          if (hadStaleLink && context.mounted) ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: LText('server.save.text.item2')));
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
                TextField(controller: labelCtl, decoration: InputDecoration(labelText: tr('common.name'))),
                DropdownButtonFormField<String?>(
                  isExpanded: true,
                  value: groupId,
                  decoration: InputDecoration(labelText: tr('common.group')),
                  items: [
                    const DropdownMenuItem(value: null, child: LText('common.ungroupedOption')),
                    for (final group in groups)
                      DropdownMenuItem(value: group['id'] as String,
                          child: Text(group['name'].toString(), maxLines: 1, overflow: TextOverflow.ellipsis)),
                  ],
                  onChanged: (value) => setLocal(() => groupId = value),
                ),
                TextField(
                  controller: hostCtl,
                  decoration: InputDecoration(labelText: tr('server.save.text.item5')),
                ),
                TextField(
                  controller: portCtl,
                  decoration: InputDecoration(labelText: tr('server.fields.port')),
                  keyboardType: TextInputType.number,
                ),
                const SizedBox(height: 8),
                DropdownButtonFormField<String?>(
                  isExpanded: true,
                  value: linkedLogin,
                  decoration: InputDecoration(labelText: tr('server.save.text.item6')),
                  items: [
                    const DropdownMenuItem(value: null, child: LText('server.save.text.item7')),
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
                    linkedLogin = v;
                    if ((linkedTotp == null || linkedTotp!.isEmpty) && v != null && v.isNotEmpty) {
                      for (final row in logins) {
                        if (row['id'] == v) {
                          linkedTotp = dropdownValueIfPresent(
                            row['linked_totp_id'] as String?,
                            totps,
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
                    labelText: tr('server.save.text.item8'),
                    hintText: linkedLogin == null || (linkedLogin?.isEmpty ?? true)
                        ? tr('server.save.text.item9')
                        : tr('server.save.text.item10'),
                  ),
                ),
                DropdownButtonFormField<String?>(
                  isExpanded: true,
                  value: linkedTotp,
                  decoration: InputDecoration(
                    labelText: tr('server.save.text.item11'),
                    helperText: tr('server.save.text.item12'),
                  ),
                  items: [
                    const DropdownMenuItem(value: null, child: LText('server.save.text.item13')),
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
                DropdownButtonFormField<String?>(
                  isExpanded: true,
                  value: linkedSsh,
                  decoration: InputDecoration(labelText: tr('server.save.text.item14')),
                  items: [
                    const DropdownMenuItem(value: null, child: LText('server.save.text.item13')),
                    ...sshKeys.map(
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
                ),
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
    }

  }
