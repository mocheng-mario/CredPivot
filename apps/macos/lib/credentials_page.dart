import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'agent_bridge.dart';
import 'vault_tools.dart';
import 'google_password_import.dart';
import 'website_rules_editor.dart';
import 'mfa_bindings_editor.dart';
import 'totp_editor.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';
import 'credential_group_ui.dart';
import 'credential_list_tile.dart';
import 'linked_refs.dart';
import 'server_login_page.dart';
import 'touch_id_gate.dart';
import 'passkeys_page.dart';
import 'credential_partitions.dart';

Future<void> _showTextRevealDialog(
  BuildContext context, {
  required String title,
  required String body,
  bool allowCopy = true,
  bool touchIdToCopy = false,
  String touchIdCopyReason = 'credentials.showTextRevealDialog.text',
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
                  const SnackBar(content: LText('credentials.showTextRevealDialog.text.item2')),
                );
              }
            },
            child: const LText('common.copy'),
          ),
        FilledButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.close')),
      ],
    ),
  );
}

Future<bool> showLoginEditor(BuildContext context, {Map<String, dynamic>? existing}) async {
    final isEdit = existing != null;
    final partition = existing?['partition_id']?.toString() ?? AgentBridge.activePartitionId;
    List<Map<String, dynamic>> totps = [];
    List<Map<String, dynamic>> groups = [];
    try {
      totps = await AgentBridge.listTotp(partitionId: partition);
      groups = await loadCredentialGroups('login', partitionId: partition);
    } on AgentException catch (e) {
      if (context.mounted) vaultMessage(context, e);
      return false;
    }
    List<Map<String, dynamic>> websiteRules = [newWebsiteRule()];
    List<String> linkedMfaIds = [];
    var passwordActiveSince = DateTime.now().millisecondsSinceEpoch;
    if (isEdit) {
      try {
        final result = await AgentBridge.manage({'action': 'login_website_rules', 'credential_id': existing['id']});
        websiteRules = (result['rules'] as List).map((row) => Map<String, dynamic>.from(row as Map)).toList();
        linkedMfaIds = (result['linked_mfa_ids'] as List? ?? []).cast<String>();
      } on AgentException catch (e) {
        if (context.mounted) vaultMessage(context, e);
        return false;
      }
    }
    if (!context.mounted) return false;
    var validating = false;
    var closing = false;
    var formError = '';
    ModalRoute<bool>? dialogRoute;
    final nameCtl = TextEditingController(text: existing?['display_name']?.toString() ?? '');
    final userCtl = TextEditingController(text: existing?['username']?.toString() ?? '');
    final passCtl = TextEditingController();
    final rawGroupId = existing?['group_id'] as String?;
    var groupId = dropdownValueIfPresent(rawGroupId, groups);
    final rawTotp = existing?['linked_totp_id'] as String?;
    final linkedTotp = dropdownValueIfPresent(rawTotp, totps);
    String snapshot() => jsonEncode([nameCtl.text,userCtl.text,passCtl.text,groupId,websiteRules,linkedMfaIds,passwordActiveSince]);
    final initialSnapshot = snapshot();
    var confirmingDiscard = false;
    Future<void> cancel(BuildContext ctx) async {
      if (validating || closing || confirmingDiscard) return;
      confirmingDiscard = true;
      try {
        if (snapshot() != initialSnapshot && !await confirmDiscardChanges(ctx)) return;
        if (ctx.mounted) { closing = true; Navigator.pop(ctx, false); }
      } finally { confirmingDiscard = false; }
    }
    final ok = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) {
        dialogRoute ??= ModalRoute.of<bool>(ctx);
        return StatefulBuilder(
        builder: (ctx, setLocal) => PopScope(canPop: false, onPopInvokedWithResult: (didPop, _) { if (!didPop) cancel(ctx); }, child: AlertDialog(
        title: LText(isEdit ? tr('credentials.cancel.text') : tr('credentials.cancel.text.item2')),
        content: SizedBox(width: appEditDialogWidth(ctx), child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: appFormFields([
              AppFieldRow(label: tr('common.name'), child: TextField(
                controller: nameCtl,
                enabled: !validating,
                decoration: InputDecoration(hintText: tr('credentials.cancel.text.item3')),
              )),
              AppFieldRow(label: tr('common.group'), child: DropdownButtonFormField<String?>(
                isExpanded: true,
                value: groupId,
                decoration: InputDecoration(),
                items: [
                  const DropdownMenuItem(value: null, child: LText('common.ungroupedOption')),
                  ...groups.map(
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
                onChanged: validating ? null : (v) => setLocal(() => groupId = v),
              )),
              AppFieldRow(label: tr('common.username'), child: TextField(enabled: !validating, controller: userCtl, decoration: InputDecoration())),
              AppFieldRow(label: tr(isEdit ? tr('credentials.cancel.text.item4') : tr('common.password')), help: isEdit ? tr('credentials.cancel.text.item5') : null, child: TextField(
                controller: passCtl,
                enabled: !validating,
                obscureText: true,
                decoration: InputDecoration(suffixIcon: IconButton(tooltip: tr('credentials.cancel.text.item6'), icon: const Icon(Icons.auto_awesome), onPressed: validating ? null : () async {
                    final generated = await generatePasswordDialog(ctx);
                    if (ctx.mounted && !closing && generated != null) passCtl.text = generated;
                  })),
              )),
              if (!isEdit) PasswordActiveDateField(value: passwordActiveSince, enabled: !validating,
                onChanged: (v) => setLocal(() => passwordActiveSince = v)),
              WebsiteRulesEditor(rules: websiteRules, enabled: !validating),
              MfaBindingsEditor(linkedIds: linkedMfaIds, mfas: totps, enabled: !validating,
                onEdit: (mfa) async {
                  if (validating || closing) return;
                  setLocal(() => validating = true);
                  try {
                    if (await showTotpEditor(ctx, existing: mfa)) {
                      final updated = await AgentBridge.listTotp(partitionId: partition);
                      if (ctx.mounted) setLocal(() => totps = updated);
                    }
                  } finally {
                    if (ctx.mounted && !closing) setLocal(() => validating = false);
                  }
                }),
              if (formError.isNotEmpty) Text(formError, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
            ]),
          ),
        )),
        actions: [
          TextButton(onPressed: validating || closing ? null : () => cancel(ctx), child: const LText('common.cancel')),
          FilledButton(onPressed: validating || closing ? null : () async {
            if (validating || closing) return;
            setLocal(() { validating = true; formError = ''; });
            try {
              final validationError = await websiteRulesError(websiteRules);
              if (!ctx.mounted) return;
              if (validationError == null) {
                if (isEdit && !await requireTouchId(ctx, reason: tr('credentials.cancel.reason'))) return;
                final origin = websiteRules.first['uri'].toString().trim();
                final user = userCtl.text.trim();
                final displayName = nameCtl.text.trim();
                if (isEdit) {
                  await AgentBridge.updateLogin(
                    credentialId: existing['id'] as String,
                    expectedRevision: existing['current_revision'] as String,
                    origin: origin,
                    websiteRules: websiteRules,
                    linkedMfaIds: linkedMfaIds,
                    username: user,
                    displayName: displayName,
                    groupId: groupId,
                    connectionHost: existing['connection_host']?.toString() ?? '',
                    linkedTotpId: linkedTotp,
                    password: passCtl.text.isEmpty ? null : passCtl.text,
                  );
                } else {
                  await AgentBridge.createLogin(
                    partitionId: partition,
                    origin: origin,
                    websiteRules: websiteRules,
                    linkedMfaIds: linkedMfaIds,
                    username: user,
                    password: passCtl.text,
                    passwordActiveSinceMs: passwordActiveSince,
                    displayName: displayName,
                    groupId: groupId,
                    linkedTotpId: linkedTotp,
                  );
                }
                if (ctx.mounted && !closing) {
                  closing = true;
                  Navigator.pop(ctx, true);
                }
                return;
              }
              setLocal(() => formError = validationError);
            } catch (e) {
              if (ctx.mounted && !closing) setLocal(() => formError = e is AgentException ? e.message : tr('common.saveFailed'));
            } finally {
              if (ctx.mounted && !closing) setLocal(() => validating = false);
            }
          }, child: LText(validating ? tr('common.saving') : tr('common.save'))),
        ],
      )),
        );
      },
    );
    // pop 的结果早于退出动画；待路由移除后再释放仍被输入框使用的控制器。
    await dialogRoute?.completed;
    for (final controller in [nameCtl, userCtl, passCtl]) { controller.dispose(); }
    return ok == true;
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
        title: tr('credentials.build.title'),
        message: tr('credentials.build.message'),
        action: FilledButton.icon(
            onPressed: onUnlock,
            icon: const Icon(Icons.lock_open_rounded),
            label: const LText('common.unlockFirst')),
      );
    }
    return DefaultTabController(
      length: 7,
      child: Column(
        children: [
          Align(alignment: Alignment.centerRight, child: Padding(padding: const EdgeInsets.symmetric(horizontal: 24),
            child: OutlinedButton.icon(onPressed: () => showPartitionMigration(context, AgentBridge.activePartitionId),
              icon: const Icon(Icons.drive_file_move_outlined, size: 18), label: const LText('partitions.move')))),
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
                Tab(child: LText('credentials.login.title')),
                Tab(child: LText('MFA / TOTP')),
                Tab(child: LText('credentials.ssh.title')),
                Tab(child: LText('credentials.server.title')),
                Tab(child: LText('credentials.passkey.title')),
                Tab(child: LText('credentials.tools.title')),
                Tab(child: LText('credentials.trash.title')),
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
                const PasskeysPanel(),
                const VaultToolsPanel(),
                const VaultToolsPanel(trashOnly: true),
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
  int _refreshGeneration = 0;

  void _onVaultChanged() { if (mounted) _refresh(); }

  @override
  void initState() {
    super.initState();
    AgentBridge.vaultChanges.addListener(_onVaultChanged);
    _refresh();
  }

  @override
  void dispose() {
    AgentBridge.vaultChanges.removeListener(_onVaultChanged);
    _search.dispose();
    super.dispose();
  }

  Future<void> _refresh() async {
    if (!mounted) return;
    final generation = ++_refreshGeneration;
    setState(() => _busy = true);
    try {
      final q = _search.text.trim();
      final items = await AgentBridge.listCredentials(q.isEmpty ? null : q);
      final groups = await loadCredentialGroups('login');
      if (!mounted || generation != _refreshGeneration) return;
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
      if (generation == _refreshGeneration) _status = AgentBridge.friendlyMessage(e);
    } finally {
      if (mounted && generation == _refreshGeneration) setState(() => _busy = false);
    }
  }

  Future<void> _addOrEdit({Map<String, dynamic>? existing}) async {
    if (await showLoginEditor(context, existing: existing) && mounted) await _refresh();
  }

  Future<void> _copyPassword(String id) async {
    if (!await requireTouchId(context, reason: tr('server.copyPassword.reason'))) return;
    final detail = await AgentBridge.getCredential(id);
    await AgentBridge.copyConcealed(detail['password'] as String? ?? '');
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('server.copyPassword.text.item2')));
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
          title: tr('credentials.login.title'),
          subtitle: tr('credentials.login.count', args: {'count': visibleItems.length}),
          action: Wrap(spacing: 8, runSpacing: 8, children: [
            OutlinedButton.icon(
              onPressed: _busy ? null : () async {
                if (await importGooglePasswords(context) && mounted) await _refresh();
              },
              icon: const Icon(Icons.file_upload_outlined),
              label: const LText('import.google.action')),
            FilledButton.icon(
              onPressed: _busy ? null : () => _addOrEdit(),
              icon: const Icon(Icons.add_rounded),
              label: const LText('credentials.build.text')),
          ]),
        ),
        Row(children: [
          Expanded(
              child: TextField(
            controller: _search,
            decoration: InputDecoration(
                hintText: tr('credentials.build.text.item2'),
                prefixIcon: Icon(Icons.search_rounded)),
            onSubmitted: (_) => _refresh(),
          )),
          const SizedBox(width: 8),
          IconButton(
              onPressed: _busy ? null : _refresh,
              tooltip: tr('passkey.build.text'),
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
              ? AppEmptyState(
                  icon: Icons.key_outlined,
                  title: tr('credentials.build.title.item2'),
                  message: tr('credentials.build.message.item2'))
              : ListView(
                  children: buildGroupedListTiles(
                  scope: 'login',
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
                      onTap: () => setState(() { _selected = row; }),
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
                              tr('credentials.build.text.item3')),
                  fields: {
                    tr('common.website'): _selected!['origin']?.toString() ?? '',
                    tr('common.username'): _selected!['username']?.toString() ?? '',
                    tr('common.password'): '••••••••',
                    tr('credentials.build.text.item4'): vaultDate(_selected!['password_active_since_ms'])
                  },
                ),
          actions: _selected == null
                ? null
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      CredentialActionSection(
                        title: tr('credentials.build.title.item3'),
                        children: [
                          OutlinedButton(
                            onPressed: () {
                              final u = _selected!['username']?.toString() ?? '';
                              Clipboard.setData(ClipboardData(text: u));
                              ScaffoldMessenger.of(context).showSnackBar(
                                  const SnackBar(content: LText('credentials.build.text.item5')));
                            },
                            child: const LText('credentials.build.text.item6'),
                          ),
                          OutlinedButton(
                            onPressed: () =>
                                _copyPassword(_selected!['id'] as String),
                            child: const LText('server.build.text.item11'),
                          ),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('credentials.build.title.item4'),
                        children: [
                          OutlinedButton(onPressed: () async { await showPasswordVersions(context, _selected!); if (mounted) await _refresh(); }, child: const LText('credentials.build.text.item7')),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('credentials.build.title.item5'),
                        children: [
                          OutlinedButton(
                            onPressed: () => _addOrEdit(existing: _selected),
                            child: const LText('common.edit'),
                          ),
                          OutlinedButton(onPressed: () async { await editItemDetails(context, _selected!); if (mounted) await _refresh(); }, child: const LText('credentials.build.text.item8')),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('server.build.title.item5'),
                        dangerous: true,
                        children: [
                          OutlinedButton(
                            onPressed: () async {
                              final title = _selected!['title']?.toString() ??
                                  _selected!['origin']?.toString() ??
                                  tr('credentials.build.text.item3');
                              if (!await confirmCredentialDanger(
                                context,
                                title: tr('credentials.build.title.item6'),
                                message: tr('credentials.login.deleteConfirmation', args: {'title': title}),
                              )) {
                                return;
                              }
                              if (!await requireTouchId(context, reason: tr('credentials.build.title.item6'), confirmed: true))
                                return;
                              final itemId = _selected!['item_id'] as String?;
                              if (itemId == null) return;
                              await AgentBridge.trashCredential(itemId);
                              _selected = null;
                              await _refresh();
                            },
                            child: const LText('common.delete'),
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
      final items = await AgentBridge.listTotp();
      final groups = await loadCredentialGroups('totp');
      if (!mounted || generation != _refreshGeneration) return;
      final selectedId = _selected?['id'];
      setState(() {
        _items = items;
        _groups = groups;
        _selected = null;
        for (final row in items) {
          if (row['id'] == selectedId) _selected = row;
        }
        _filterGroupId = dropdownValueIfPresent(_filterGroupId, groups);
        _liveCode = null;
        _liveCodeForId = null;
        _status = '';
      });
    } on AgentException catch (e) {
      if (mounted && generation == _refreshGeneration) setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  Future<void> _addTotp() async {
    if (await showTotpEditor(context, groups: _groups) && mounted) await _refresh();
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
    final reveal = await _revealAfterTouchId(tr('credentials.showQrCode.text'));
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
              LText('credentials.showQrCode.text.item2', style: Theme.of(ctx).textTheme.bodySmall),
            ],
          ),
        ),
        actions: [
          FilledButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.close')),
        ],
      ),
    );
  }

  Future<void> _showOtpauthUri() async {
    final reveal = await _revealAfterTouchId(tr('credentials.showOtpauthUri.text'));
    if (reveal == null || !mounted) return;
    await _showTextRevealDialog(
      context,
      title: 'otpauth URI',
      body: reveal['otpauth_uri'] as String? ?? '',
      touchIdToCopy: true,
      touchIdCopyReason: tr('credentials.showOtpauthUri.text.item2'),
    );
  }

  Future<void> _showSecret() async {
    final reveal = await _revealAfterTouchId(tr('credentials.showSecret.text'));
    if (reveal == null || !mounted) return;
    await _showTextRevealDialog(
      context,
      title: tr('credentials.showSecret.title'),
      body: reveal['secret_base32'] as String? ?? '',
      touchIdToCopy: true,
      touchIdCopyReason: tr('credentials.showSecret.text.item2'),
    );
  }

  Future<void> _deleteTotp(Map<String, dynamic> row) async {
    if (!await confirmCredentialDanger(
      context,
      title: tr('credentials.deleteTotp.title'),
      message: tr('mfa.delete.confirmation', args: {'issuer': row['issuer'], 'account': row['account']}),
    )) {
      return;
    }
    if (!await requireTouchId(context, reason: tr('credentials.deleteTotp.title'), confirmed: true)) return;
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
            title: tr('credentials.build.title.item7'),
            subtitle: tr('credentials.mfa.count', args: {'count': visibleItems.length}),
            action: FilledButton.icon(
                onPressed: _addTotp,
                icon: const Icon(Icons.add_rounded),
                label: const LText('credentials.build.text.item9')),
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
                    LText('mfa.code.current', args: {'code': _liveCode},
                        style: Theme.of(context).textTheme.titleLarge),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.copy),
                      onPressed: () async {
                        await AgentBridge.copyConcealed(_liveCode!);
                        if (!mounted) return;
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: LText('credentials.build.text.item11')),
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
                ? AppEmptyState(
                    icon: Icons.pin_outlined,
                    title: tr('credentials.build.title.item8'),
                    message: tr('credentials.build.message.item4'))
                : ListView(
                    children: buildGroupedListTiles(
                      scope: 'totp',
                      groups: _groups,
                      items: visibleItems,
                      tileBuilder: (row) {
                        final selected = _selected?['id'] == row['id'];
                        return selectableCredentialTile(
                          context: context,
                          selected: selected,
                          icon: Icons.pin_outlined,
                          title: Text(row['issuer']?.toString() ?? 'TOTP'),
                          subtitle: Text('${row['account'] ?? ''}${(row['pending_rule_count'] as num? ?? 0) > 0 ? tr('credentials.labels.text') : ''}'),
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
                      tr('mfa.fields.issuer'): _selected!['issuer']?.toString() ?? '',
                      tr('credentials.build.text.item12'): _selected!['account']?.toString() ?? '',
                      tr('credentials.build.text.item13'): tr('credentials.build.text.item14')
                    },
                  ),
            actions: _selected == null
                ? null
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      CredentialActionSection(
                        title: tr('credentials.build.title.item9'),
                        children: [
                          FilledButton.tonal(
                            onPressed: () => _copyCode(_selected!['id'] as String),
                            child: const LText('credentials.build.text.item15'),
                          ),
                          OutlinedButton(
                            onPressed: () => _showCode(_selected!['id'] as String),
                            child: LText(_liveCodeForId == _selected!['id']
                                ? tr('credentials.build.text.item16')
                                : tr('credentials.build.text.item17')),
                          ),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('credentials.build.title.item10'),
                        children: [
                          OutlinedButton(
                              onPressed: _showQrCode, child: const LText('credentials.build.text.item18')),
                          OutlinedButton(
                              onPressed: _showOtpauthUri,
                              child: const LText('otpauth URI')),
                          OutlinedButton(
                              onPressed: _showSecret, child: const LText('credentials.build.text.item19')),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('credentials.build.title.item5'),
                        children: [
                          OutlinedButton(onPressed: () async { await editTotp(context, _selected!); if (mounted) await _refresh(); }, child: const LText('common.edit')),
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
                            child: const LText('credentials.build.text.item20'),
                          ),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('server.build.title.item5'),
                        dangerous: true,
                        children: [
                          OutlinedButton(
                            onPressed: () => _deleteTotp(_selected!),
                            child: const LText('common.delete'),
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
      final response = await AgentBridge.request({'type': 'ssh_key_list'});
      final payload = AgentBridge.payloadOf(response);
      final items = (payload['items'] as List<dynamic>? ?? [])
          .map((item) => Map<String, dynamic>.from(item as Map)).toList();
      if (!mounted || generation != _refreshGeneration) return;
      final groups = await loadCredentialGroups('ssh');
      if (!mounted || generation != _refreshGeneration) return;
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
      if (mounted && generation == _refreshGeneration) setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  Future<void> _generate() async {
    if (_deleting) return;
    if (await showSshKeyGenerator(context, initialGroupId: _filterGroupId) && mounted) await _refresh();
  }

  void _copyPublicKey(Map<String, dynamic> row) {
    final pub = row['public_openssh']?.toString() ?? '';
    Clipboard.setData(ClipboardData(text: pub));
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('credentials.copyPublicKey.text')));
  }

  Future<void> _delete(Map<String, dynamic> row) async {
    if (_deleting) return;
    final itemId = row['item_id'] as String?;
    if (itemId == null) return;
    setState(() => _deleting = true);
    try {
      if (!await confirmCredentialDanger(context,
          title: tr('credentials.delete.title'),
          message: tr('ssh.delete.confirmation', args: {'label': row['label'] ?? 'SSH'}))) return;
      if (!mounted || !await requireTouchId(context,
          reason: tr('credentials.delete.title'), confirmed: true)) return;
      await AgentBridge.trashCredential(itemId);
      await _refresh();
      if (mounted) setState(() => _status = tr('credentials.delete.text'));
    } on AgentException catch (e) {
      if (mounted) setState(() => _status = AgentBridge.friendlyMessage(e));
    } catch (_) {
      if (mounted) setState(() => _status = tr('credentials.delete.text.item2'));
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
            title: tr('credentials.ssh.title'),
            subtitle: tr('credentials.ssh.count', args: {'count': visibleItems.length}),
            action: FilledButton.icon(
                onPressed: _generate,
                icon: const Icon(Icons.add_rounded),
                label: const LText('credentials.build.text.item21')),
          ),
          TextButton.icon(onPressed: () async { await transferSshKey(context); if (mounted) await _refresh(); }, icon: const Icon(Icons.file_open_outlined), label: const LText('credentials.build.text.item22')),
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
                ? AppEmptyState(
                    icon: Icons.terminal_rounded,
                    title: tr('credentials.build.title.item11'),
                    message: tr('credentials.build.message.item5'))
                : ListView(
                    children: buildGroupedListTiles(
                      scope: 'ssh',
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
                              ? const Chip(label: LText('credentials.build.text.item23'))
                              : null,
                          onTap: () => setState(() { _selected = row; }),
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
                      tr('ssh.fields.publicKey'): _selected!['public_openssh']?.toString() ?? '',
                      tr('credentials.build.text.item24'): _selected!['is_default'] == true ? tr('common.yes') : tr('common.no'),
                      tr('vault.vaultOverview.text.item13'): tr('credentials.build.text.item25'),
                      tr('credentials.build.text.item26'): _storagePath,
                      tr('credentials.build.text.item27'): _agentSocket,
                      tr('ssh.fields.privateKeyFile'): tr('ssh.storage.noPrivateKeyFile'),
                    },
                  ),
            actions: _selected == null
                ? null
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      CredentialActionSection(
                        title: tr('credentials.build.title.item12'),
                        children: [
                          FilledButton.tonal(
                            onPressed: () => _copyPublicKey(_selected!),
                            child: const LText('credentials.build.text.item28'),
                          ),
                          OutlinedButton(onPressed: () async {
                            if (!await requireTouchId(context, reason: tr('credentials.build.reason'))) return;
                            try { await AgentBridge.request({'type':'ssh_select_key','key_id':_selected!['id']}); if (mounted) setState(() => _status=tr('credentials.build.text.item29')); } catch(e) { vaultMessage(context,e); }
                          }, child: const LText('credentials.build.text.item30')),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('credentials.build.title.item13'),
                        children: [
                          OutlinedButton(onPressed: () => transferSshKey(context, keyId: _selected!['id'].toString()), child: const LText('credentials.build.text.item31')),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('credentials.build.title.item5'),
                        children: [
                          OutlinedButton(onPressed: () => editItemDetails(context, _selected!), child: const LText('credentials.build.text.item8')),
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
                            child: const LText('credentials.build.text.item20'),
                          ),
                        ],
                      ),
                      CredentialActionSection(
                        title: tr('server.build.title.item5'),
                        dangerous: true,
                        children: [
                          OutlinedButton.icon(
                            onPressed: () => _delete(_selected!),
                            icon: const Icon(Icons.delete_outline_rounded),
                            label: const LText('common.delete'),
                          ),
                        ],
                      ),
                    ],
                  ),
          )),
          LText(
            'credentials.build.text.item32',
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
  Map<String, dynamic> _backupStatus = {};
  List<Map<String, dynamic>> _restorePoints = [];
  List<Map<String, dynamic>> _recoveryCodes = [];
  String _log = '';
  final _serviceName = TextEditingController();
  final _codesText = TextEditingController();
  final _recoveryKey = TextEditingController();
  final _rebuildPassword = TextEditingController();

  void _onVaultChanged() { if (mounted && widget.unlocked) _loadAll(); }

  @override
  void initState() {
    super.initState();
    AgentBridge.vaultChanges.addListener(_onVaultChanged);
    if (widget.unlocked) {
      _loadAll();
    }
  }

  @override
  void dispose() {
    AgentBridge.vaultChanges.removeListener(_onVaultChanged);
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
      final backupStatus = await AgentBridge.backupStatus();
      final restorePoints = await AgentBridge.listRestorePoints();
      final recoveryCodes = await AgentBridge.listRecoveryCodes();
      // 页面保留在导航栈中，旧请求不能把锁定前的数据重新写回。
      if (!mounted || !widget.unlocked || generation != _loadGeneration) return;
      setState(() {
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

  Future<void> _importGoogle() async {
    if (await importGooglePasswords(context) && mounted) await _loadAll();
  }

  Future<void> _addRecoveryCodes() async {
    final name = _serviceName.text.trim();
    final codes = _codesText.text
        .split(RegExp(r'[\s,;]+'))
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
    if (name.isEmpty || codes.isEmpty) {
      setState(() => _log = tr('credentials.addRecoveryCodes.text'));
      return;
    }
    try {
      await AgentBridge.createRecoveryCodes(name, codes);
      _serviceName.clear();
      _codesText.clear();
      await _loadAll();
      setState(() => _log = tr('credentials.addRecoveryCodes.text.item2'));
    } on AgentException catch (e) {
      setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  Future<void> _recoverPoint(Map<String, dynamic> point) async {
    String? password;
    if (point['requires_password'] == true) {
      final controller = TextEditingController();
      password = await showDialog<String>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const LText('credentials.recoverPoint.text'),
          content: SizedBox(width: appEditDialogWidth(ctx), child: Column(
            mainAxisSize: MainAxisSize.min,
            children: appFormFields([
              const LText('credentials.recoverPoint.text.item2'),
              AppFieldRow(label: tr('credentials.recoverPoint.text.item3'), child: TextField(controller: controller, obscureText: true, autofocus: true,
                decoration: InputDecoration())),
            ]),
          )),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.cancel')),
            FilledButton(onPressed: () => Navigator.pop(ctx, controller.text), child: const LText('common.continue')),
          ],
        ),
      );
      controller.dispose();
      if (password == null || !mounted) return;
    }
    final target = await AgentBridge.pickDirectory();
    if (target == null || !mounted) return;
    if (!await requireTouchId(context, reason: tr('credentials.recoverPoint.reason'))) return;
    final ts = point['created_at_ms'] as int? ?? 0;
    try {
      await AgentBridge.recoverRestorePoint(ts, target, password: password);
      await AgentBridge.lockVault();
      await AgentBridge.vaultOpenDir(target);
      widget.onVaultSwitched?.call();
      setState(() => _log = tr('credentials.recoverPoint.text.item4', args: {'target': target}));
    } on AgentException catch (e) {
      setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  Future<void> _migrateVault() async {
    if (!await requireTouchId(context, reason: tr('credentials.migrateVault.reason'))) return;
    final target = await AgentBridge.pickDirectory();
    if (target == null) return;
    try {
      await AgentBridge.migrateVault(target);
      setState(() => _log = tr('credentials.migrateVault.text', args: {'target': target}));
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
      setState(() => _log = tr('credentials.recoverOvbToEmptyDir.text', args: {'target': target}));
    } on AgentException catch (e) {
      setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  @override
  void didUpdateWidget(covariant SecurityCenterTab oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!widget.unlocked && oldWidget.unlocked) {
      _loadGeneration++;
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
        title: tr('credentials.build.title.item14'),
        message: tr('credentials.build.message.item6'),
        action: FilledButton.icon(
            onPressed: widget.onUnlock,
            icon: const Icon(Icons.lock_open_rounded),
            label: const LText('common.unlockFirst')),
      );
    }
    return ListView(
      padding: const EdgeInsets.fromLTRB(24, 6, 24, 24),
      children: [
        if (_log.isNotEmpty) AppNotice(_log),
        const CredentialSecurityReport(),
        const SizedBox(height: 16),
        AppPanel(
          title: tr('credentials.build.title.item15'),
          subtitle: tr('credentials.build.description.item4'),
          icon: Icons.cloud_done_outlined,
          trailing: IconButton(
              onPressed: _loadAll,
              tooltip: tr('credentials.build.text.item33'),
              icon: const Icon(Icons.refresh_rounded)),
          child: Column(children: [
            _backupRow(tr('credentials.build.text.item34'), 'local_restore_verified_ms'),
            _backupRow(tr('credentials.build.text.item35'), 'ovb_export_verified_ms'),
            _backupRow(tr('credentials.build.text.item36'), 'ovb_decrypt_verified_ms'),
            _backupRow(tr('credentials.build.text.item37'), 'recovery_key_verified_ms'),
          ]),
        ),
        const SizedBox(height: 16),
        AppPanel(
          title: tr('credentials.recovery.websiteCodes'),
          subtitle: tr('credentials.build.description.item5'),
          icon: Icons.verified_user_outlined,
          child:
              Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            if (_recoveryCodes.isEmpty)
              AppNotice(tr('credentials.build.text.item38')),
            ..._recoveryCodes.map((r) => ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(Icons.verified_user_outlined,
                      color: AppColors.primary),
                  title: Text(r['service_name']?.toString() ?? ''),
                  subtitle: LText('recovery.codes.remaining', args: {'remaining': r['remaining_count'] ?? 0, 'total': r['code_count'] ?? 0}),
                  trailing: const Icon(Icons.chevron_right_rounded, size: 18),
                  onTap: () => _openRecoveryCode(r),
                )),
            const SizedBox(height: 12),
            AppFieldRow(label: tr('credentials.build.text.item40'), child: TextField(
                controller: _serviceName,
                decoration: InputDecoration(hintText: tr('credentials.build.text.item41')))),
            const SizedBox(height: 12),
            AppFieldRow(label: tr('credentials.recovery.title'), child: TextField(
                controller: _codesText,
                minLines: 2,
                maxLines: 4,
                decoration: InputDecoration(hintText: tr('credentials.build.text.item42')))),
            const SizedBox(height: 14),
            Align(
                alignment: Alignment.centerLeft,
                child: FilledButton.icon(
                    onPressed: _addRecoveryCodes,
                    icon: const Icon(Icons.add_rounded),
                    label: const LText('credentials.build.text.item43'))),
          ]),
        ),
        const SizedBox(height: 16),
        AppPanel(
          title: tr('credentials.build.text.item34'),
          subtitle: tr('credentials.build.description.item6'),
          icon: Icons.history_rounded,
          child: _restorePoints.isEmpty
              ? AppNotice(tr('credentials.build.text.item44'))
              : Column(
                  children: _restorePoints
                      .map((point) => ListTile(
                            contentPadding: EdgeInsets.zero,
                            leading: const Icon(Icons.restore_rounded),
                            title:
                                Text(displayDateTime(point['created_at_ms'])),
                            trailing: OutlinedButton(
                                onPressed: () => _recoverPoint(point),
                                child: const LText('common.restore')),
                          ))
                      .toList()),
        ),
        const SizedBox(height: 16),
        AppPanel(
          title: tr('credentials.build.title.item16'),
          subtitle: tr('credentials.build.description.item7'),
          icon: Icons.drive_file_move_outlined,
          child: Wrap(spacing: 10, runSpacing: 10, children: [
            OutlinedButton.icon(
                onPressed: _importBitwarden,
                icon: const Icon(Icons.file_upload_outlined),
                label: const LText('credentials.build.text.item45')),
            OutlinedButton.icon(
                onPressed: _importGoogle,
                icon: const Icon(Icons.file_upload_outlined),
                label: const LText('import.google.action')),
            OutlinedButton.icon(
                onPressed: _migrateVault,
                icon: const Icon(Icons.folder_outlined),
                label: const LText('credentials.build.text.item46')),
          ]),
        ),
        const SizedBox(height: 16),
        Card(
            child: ExpansionTile(
          shape: const Border(),
          collapsedShape: const Border(),
          leading: Icon(Icons.settings_backup_restore_rounded,
              color: AppColors.primary),
          title: const LText('credentials.build.text.item47'),
          subtitle: const LText('credentials.build.text.item48'),
          childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
          children: [
            AppNotice(tr('credentials.build.text.item49')),
            AppFieldRow(label: tr('vault.vaultOverview.text.item26'), child: TextField(
                controller: _rebuildPassword,
                obscureText: true,
                decoration: InputDecoration())),
            const SizedBox(height: 12),
            AppFieldRow(label: tr('vault.fields.recoveryKey'), child: TextField(
                controller: _recoveryKey,
                obscureText: true,
                decoration: InputDecoration())),
            const SizedBox(height: 14),
            Align(
                alignment: Alignment.centerLeft,
                child: OutlinedButton(
                    onPressed: _recoverOvbToEmptyDir,
                    child: const LText('credentials.build.text.item50'))),
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
