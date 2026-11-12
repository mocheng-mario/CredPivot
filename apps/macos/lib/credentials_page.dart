import 'dart:convert';
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
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
import 'ssh_git_ui.dart';
import 'credential_list_tile.dart';
import 'linked_refs.dart';
import 'server_login_page.dart';
import 'touch_id_gate.dart';
import 'passkeys_page.dart';
import 'credential_partitions.dart';
import 'duplicate_logins.dart';

Future<void> _showTextRevealDialog(
  BuildContext context, {
  required String title,
  required String body,
  required int session,
  bool allowCopy = true,
  bool touchIdToCopy = false,
  String touchIdCopyReason = 'credentials.showTextRevealDialog.text',
}) async {
  if (!context.mounted) return;
  await showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(title),
      content: SelectableText(body),
      actions: [
        if (allowCopy)
          TextButton(
            onPressed: () async {
              try {
                if (touchIdToCopy) {
                  if (!await requireTouchId(ctx, reason: touchIdCopyReason)) return;
                }
                await AgentBridge.copyConcealed(body, session: session);
              } catch (error) { vaultMessage(ctx, error); return; }
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
    List<Map<String, dynamic>> sshKeys = [];
    List<Map<String, dynamic>> groups = [];
    try {
      totps = await AgentBridge.listTotp(partitionId: partition);
      sshKeys = await AgentBridge.listSshKeys(partitionId: partition);
      groups = await loadCredentialGroups('login', partitionId: partition);
    } on AgentException catch (e) {
      if (context.mounted) vaultMessage(context, e);
      return false;
    }
    List<Map<String, dynamic>> websiteRules = [newWebsiteRule()];
    List<String> linkedMfaIds = [];
    List<String> linkedSshKeyIds = [];
    var passwordActiveSince = DateTime.now().millisecondsSinceEpoch;
    if (isEdit) {
      try {
        final result = await AgentBridge.manage({'action': 'login_website_rules', 'credential_id': existing['id']});
        websiteRules = (result['rules'] as List).map((row) => Map<String, dynamic>.from(row as Map)).toList();
        linkedMfaIds = (result['linked_mfa_ids'] as List? ?? []).cast<String>();
        linkedSshKeyIds = (result['linked_ssh_key_ids'] as List? ?? []).cast<String>();
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
    String snapshot() => jsonEncode([nameCtl.text,userCtl.text,passCtl.text,groupId,websiteRules,linkedMfaIds,linkedSshKeyIds,passwordActiveSince]);
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
        builder: (ctx, setLocal) => PopScope(canPop: false, onPopInvokedWithResult: (didPop, _) { if (!didPop) cancel(ctx); }, child: AppEditDialog(
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
                        credentialGroupLabel(g),
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
              for (final key in sshKeys)
                CheckboxListTile(
                  value: linkedSshKeyIds.contains(key['id']),
                  title: Text(key['label']?.toString() ?? 'SSH'),
                  onChanged: validating ? null : (checked) => setLocal(() {
                    final id = key['id'].toString();
                    if (checked == true) {
                      if (!linkedSshKeyIds.contains(id)) linkedSshKeyIds.add(id);
                    } else {
                      linkedSshKeyIds.remove(id);
                    }
                  }),
                ),
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
                    linkedSshKeyIds: linkedSshKeyIds,
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
                    linkedSshKeyIds: linkedSshKeyIds,
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
  const CredentialsTab({super.key, required this.unlocked, this.onUnlock, this.mobile = false});

  final bool unlocked;
  final VoidCallback? onUnlock;
  final bool mobile;

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
      length: mobile ? 5 : 7,
      child: Column(
        children: [
          if (!mobile) Align(alignment: Alignment.centerRight, child: Padding(padding: const EdgeInsets.symmetric(horizontal: 24),
            child: OutlinedButton.icon(onPressed: () => showPartitionMigration(context, AgentBridge.activePartitionId),
              icon: const Icon(Icons.drive_file_move_outlined, size: 18), label: const LText('partitions.move')))),
          Row(children: [Expanded(child: Container(
            margin: mobile ? const EdgeInsets.fromLTRB(16, 0, 0, 4) : const EdgeInsets.fromLTRB(24, 4, 24, 8),
            padding: const EdgeInsets.all(4),
            decoration: BoxDecoration(
                color: AppColors.sidebar,
                borderRadius: BorderRadius.circular(12)),
            child: TabBar(
              dividerHeight: mobile ? 0 : 1,
              isScrollable: true,
              tabAlignment: TabAlignment.start,
              splashBorderRadius: BorderRadius.all(Radius.circular(9)),
              tabs: [
                Tab(child: LText('credentials.login.title')),
                Tab(child: LText('MFA / TOTP')),
                if (!mobile) Tab(child: LText('credentials.ssh.title')),
                if (!mobile) Tab(child: LText('credentials.server.title')),
                Tab(child: LText('credentials.passkey.title')),
                Tab(child: LText('credentials.tools.title')),
                Tab(child: LText('credentials.trash.title')),
              ],
            ),
          )),
            if (mobile) IconButton(
              tooltip: tr('partitions.move'),
              onPressed: () => showPartitionMigration(context, AgentBridge.activePartitionId),
              icon: const Icon(Icons.drive_file_move_outlined)),
          ]),
          Expanded(
            child: TabBarView(
              children: [
                _LoginPasswordPanel(),
                _TotpPanel(),
                if (!mobile) _SshKeysPanel(),
                if (!mobile) const ServerLoginPanel(),
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
  const _LoginPasswordPanel({this.initialSelection});
  final Map<String, dynamic>? initialSelection;

  @override
  State<_LoginPasswordPanel> createState() => _LoginPasswordPanelState();
}

class _LoginPasswordPanelState extends State<_LoginPasswordPanel> {
  final _search = TextEditingController();
  Timer? _searchDebounce;
  List<Map<String, dynamic>> _items = [];
  List<Map<String, dynamic>> _groups = [];
  List<Map<String, dynamic>> _passkeys = [];
  Map<String, dynamic>? _passkeySites;
  bool _passkeysUnavailable = false;
  String? _filterGroupId;
  Map<String, dynamic>? _selected;
  String _status = '';
  bool _busy = false;
  int _refreshGeneration = 0;

  void _onVaultChanged() { if (mounted) _refresh(); }

  @override
  void initState() {
    super.initState();
    _selected = widget.initialSelection;
    AgentBridge.vaultChanges.addListener(_onVaultChanged);
    _refresh();
  }

  @override
  void dispose() {
    AgentBridge.vaultChanges.removeListener(_onVaultChanged);
    _search.dispose();
    _searchDebounce?.cancel();
    super.dispose();
  }

  Future<void> _refresh() async {
    _searchDebounce?.cancel();
    if (!mounted) return;
    final generation = ++_refreshGeneration;
    setState(() => _busy = true);
    try {
      final q = _search.text.trim();
      final partition = AgentBridge.activePartitionId;
      final items = await AgentBridge.listCredentials(q.isEmpty ? null : q, partition);
      final groups = await loadCredentialGroups('login', partitionId: partition);
      List<Map<String, dynamic>> passkeys = [];
      var passkeysUnavailable = false;
      try {
        final response = AgentBridge.payloadOf(await AgentBridge.request({'type': 'passkey_list'}, partitionId: partition));
        passkeys = (response['items'] as List? ?? []).map((row) => Map<String, dynamic>.from(row as Map)).toList();
      } catch (_) { passkeysUnavailable = true; }
      final sites = await AgentBridge.passkeySites();
      if (!mounted || generation != _refreshGeneration) return;
      final selectedId = _selected?['id'];
      _items = items;
      _groups = groups;
      _passkeys = passkeys;
      _passkeySites = sites;
      _passkeysUnavailable = passkeysUnavailable;
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
    try {
      final session = await AgentBridge.clipboardSession();
      if (!mounted || !await requireTouchId(context, reason: tr('server.copyPassword.reason'))) return;
      final detail = await AgentBridge.getCredential(id);
      await AgentBridge.copyConcealed(detail['password'] as String? ?? '', session: session);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('server.copyPassword.text.item2')));
      }
    } catch (error) { vaultMessage(context, error); }
  }

  Future<void> _deleteLogin(bool withLinks) async {
    final login = _selected;
    final itemId = login?['item_id']?.toString();
    if (login == null || itemId == null) return;
    final title = login['title']?.toString() ?? login['origin']?.toString() ?? '';
    if (!withLinks) {
      if (!await confirmCredentialDanger(context, title: tr('credentials.build.title.item6'), message: tr('credentials.login.deleteConfirmation', args: {'title': title}))) return;
      if (!mounted || !await requireTouchId(context, reason: tr('credentials.build.title.item6'), confirmed: true)) return;
      await AgentBridge.trashCredential(itemId);
    } else {
      Map<String, dynamic> preview;
      try {
        preview = await AgentBridge.manage({'action': 'login_delete_preview', 'item_id': itemId});
      } catch (error) { vaultMessage(context, error); return; }
      if (!mounted) return;
      final items = (preview['items'] as List? ?? []).map((row) => Map<String, dynamic>.from(row as Map)).toList();
      final chosen = <String>{};
      final ok = await showDialog<bool>(context: context, builder: (ctx) => StatefulBuilder(builder: (ctx, setLocal) => AlertDialog(
        title: const Text('删除账户及勾选的关联内容'),
        content: SizedBox(width: appEditDialogWidth(ctx), child: SingleChildScrollView(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text('将删除账户「$title」。勾选的关联内容一起删除，没勾的只解除关联。'),
          const SizedBox(height: 8),
          if (items.isEmpty) const Text('这个账户没有直接关联的 MFA、SSH 密钥或通行密钥。'),
          for (final item in items)
            CheckboxListTile(
              contentPadding: EdgeInsets.zero,
              value: chosen.contains(item['item_id']),
              title: Text(item['title']?.toString() ?? ''),
              subtitle: Text([
                item['kind'] == 'mfa' ? 'MFA' : item['kind'] == 'ssh_key' ? 'SSH 密钥' : '通行密钥',
                if ((item['other_accounts'] as List?)?.isNotEmpty == true)
                  '其他账户也在使用：${(item['other_accounts'] as List).join('、')}',
              ].join(' · ')),
              onChanged: (value) => setLocal(() {
                final id = item['item_id'].toString();
                if (value == true) { chosen.add(id); } else { chosen.remove(id); }
              }),
            ),
        ]))),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('common.cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const LText('common.delete')),
        ],
      )));
      if (ok != true || !mounted) return;
      if (!await requireTouchId(context, reason: '删除账户及勾选的关联内容', confirmed: true)) return;
      await AgentBridge.manage({'action': 'login_delete_apply', 'item_id': itemId, 'also': chosen.toList()});
    }
    _selected = null;
    await _refresh();
    if (mounted && widget.initialSelection != null && ModalRoute.of(context)?.isCurrent == true) Navigator.pop(context);
  }

  Future<void> _select(Map<String, dynamic> row) async {
    if (defaultTargetPlatform == TargetPlatform.android) {
      await showCredentialDetailSheet(context, _LoginPasswordPanel(initialSelection: row));
      if (mounted) await _refresh();
      return;
    }
    setState(() {
      _selected = row;
    });
  }

  @override
  Widget build(BuildContext context) {
    final visibleItems = _items
        .where((row) =>
            _filterGroupId == null || row['group_id'] == _filterGroupId)
        .toList();
    final linkedPasskeys = _passkeys.where((passkey) =>
        (passkey['linked_logins'] as List? ?? []).any((login) => login['id'] == _selected?['id'])).toList();
    return CredentialPanel(
      detailsOnly: widget.initialSelection != null,
      detailNotice: _status.isEmpty ? null : AppNotice(_status),
      header: [
        AppSectionHeader(
          compact: defaultTargetPlatform == TargetPlatform.android,
          title: tr('credentials.login.title'),
          subtitle: tr('credentials.login.count', args: {'count': visibleItems.length}),
          action: Wrap(spacing: 8, runSpacing: 8, children: [
            if (defaultTargetPlatform == TargetPlatform.android)
              IconButton(tooltip:tr('duplicates.title'),onPressed:_busy ? null : () => showDuplicateLogins(context),icon:const Icon(Icons.compare_arrows))
            else OutlinedButton.icon(onPressed:_busy ? null : () => showDuplicateLogins(context),icon:const Icon(Icons.compare_arrows),label:const LText('duplicates.title')),
            if (defaultTargetPlatform == TargetPlatform.android) ...[
              IconButton.outlined(
                tooltip: tr('import.google.action'),
                onPressed: _busy ? null : () async {
                  if (await importGooglePasswords(context) && mounted) await _refresh();
                },
                icon: const Icon(Icons.file_upload_outlined)),
              IconButton.filled(
                tooltip: tr('credentials.build.text'),
                onPressed: _busy ? null : () => _addOrEdit(),
                icon: const Icon(Icons.add_rounded)),
            ] else ...[
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
            ],
          ]),
        ),
        Row(children: [
          Expanded(
              child: TextField(
            controller: _search,
            decoration: InputDecoration(
                isDense: defaultTargetPlatform == TargetPlatform.android,
                hintText: tr('credentials.build.text.item2'),
                prefixIcon: Icon(Icons.search_rounded),
                suffixIcon: _search.text.isEmpty ? null : IconButton(tooltip: tr('credentials.list.clearSearch'),
                  icon: const Icon(Icons.clear), onPressed: () { _searchDebounce?.cancel(); _search.clear(); _refresh(); })),
            onChanged: (_) {
              _searchDebounce?.cancel(); ++_refreshGeneration;
              setState(() {});
              _searchDebounce = Timer(const Duration(milliseconds:250), _refresh);
            },
            onSubmitted: (_) { _searchDebounce?.cancel(); _refresh(); },
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
      ],
      body: CredentialWorkspace(
        detailsOnly: widget.initialSelection != null,
          list: visibleItems.isEmpty
              ? AppEmptyState(
                  icon: Icons.key_outlined,
                  title: tr('credentials.build.title.item2'),
                  message: tr('credentials.build.message.item2'))
              : buildGroupedList(
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
                      onTap: () => _select(row),
                    );
                  },
                ),
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
                    tr('credentials.passkey.title'): _passkeysUnavailable ? tr('passkey.links.loadFailed')
                        : linkedPasskeys.isEmpty ? tr('common.notLinked')
                        : linkedPasskeys.map((passkey) => '${passkey['rp_id']} · ${passkey['username']} · ${AgentBridge.passkeySiteLabel(_passkeySites, passkey['rp_id'])}').join('\n'),
                    tr('credentials.build.text.item4'): vaultDate(_selected!['password_active_since_ms'])
                  },
                  copyableFields: {tr('common.website')},
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
                        title: tr('credentials.passkey.title'),
                        children: [
                          OutlinedButton(onPressed: _busy ? null : () async {
                            await editItemDetails(context, _selected!);
                            if (mounted) await _refresh();
                          }, child: const LText('passkey.links.manage')),
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
                            onPressed: () => _deleteLogin(false),
                            child: const LText('common.delete'),
                          ),
                          OutlinedButton(
                            onPressed: () => _deleteLogin(true),
                            child: const Text('删除账户及勾选的关联内容'),
                          ),
                        ],
                      ),
                    ],
                  ),
      ),
    );
  }
}

class _TotpPanel extends StatefulWidget {
  const _TotpPanel({this.initialSelection});
  final Map<String, dynamic>? initialSelection;

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
  String _recoveryLine = '未录入';
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
    _selected = widget.initialSelection;
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
      await _loadRecovery();
    } on AgentException catch (e) {
      if (mounted && generation == _refreshGeneration) setState(() => _status = AgentBridge.friendlyMessage(e));
    }
  }

  Future<void> _loadRecovery() async {
    final itemId = _selected?['item_id']?.toString();
    if (itemId == null) return;
    try {
      final status = await AgentBridge.manage({'action': 'mfa_recovery_status', 'item_id': itemId});
      if (!mounted || _selected?['item_id']?.toString() != itemId) return;
      setState(() => _recoveryLine = status['attached'] == true ? '剩余 ${status['remaining'] ?? 0} / 共 ${status['total'] ?? 0}' : '未录入');
    } catch (_) {
      if (mounted) setState(() => _recoveryLine = '未能读取');
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
    try {
      final session = await AgentBridge.clipboardSession();
      if (!mounted || !await requireTouchId(context, reason: reason)) return null;
      final reveal = await AgentBridge.totpReveal(id);
      return {...reveal, 'clipboard_session': session};
    } on AgentException catch (e) {
      if (mounted) setState(() => _status = AgentBridge.friendlyMessage(e));
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
      session: reveal['clipboard_session'] as int,
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
      session: reveal['clipboard_session'] as int,
      touchIdToCopy: true,
      touchIdCopyReason: tr('credentials.showSecret.text.item2'),
    );
  }

  Future<void> _showRecovery(Map<String, dynamic> row) async {
    final itemId = row['item_id']?.toString();
    if (itemId == null) return;
    try {
      final status = await AgentBridge.manage({'action': 'mfa_recovery_status', 'item_id': itemId});
      if (!mounted) return;
      if (status['attached'] == true) {
        await showDialog<void>(context: context, builder: (ctx) => AlertDialog(
          title: const Text('恢复码'),
          content: Text('剩余 ${status['remaining'] ?? 0} / 共 ${status['total'] ?? 0}'),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.close')),
            FilledButton(onPressed: () async {
              Navigator.pop(ctx);
              await manageRecoveryEntries(context, {'id': status['id'], 'item_id': status['item_id']});
            }, child: const Text('查看并标记')),
          ],
        ));
        return;
      }
      final codes = TextEditingController();
      final save = await showDialog<bool>(context: context, builder: (ctx) => AlertDialog(
        title: const Text('录入恢复码'),
        content: TextField(controller: codes, minLines: 3, maxLines: 8, decoration: const InputDecoration(hintText: '每行一条')),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('common.cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const LText('common.save')),
        ],
      ));
      final text = codes.text;
      codes.dispose();
      if (save != true || !mounted) return;
      if (!await requireTouchId(context, reason: '录入恢复码', confirmed: true)) return;
      await AgentBridge.manage({'action': 'mfa_recovery_save', 'item_id': itemId, 'codes': text.split(RegExp(r'[\s,;]+')).where((code) => code.trim().isNotEmpty).toList()});
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('恢复码已录入')));
    } catch (error) { vaultMessage(context, error); }
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
      if (mounted && widget.initialSelection != null && ModalRoute.of(context)?.isCurrent == true) Navigator.pop(context);
    } on AgentException catch (e) {
      if (mounted) setState(() => _status = e.message);
    }
  }

  Future<void> _select(Map<String, dynamic> row) async {
    if (defaultTargetPlatform == TargetPlatform.android) {
      await showCredentialDetailSheet(context, _TotpPanel(initialSelection: row));
      if (mounted) await _refresh();
      return;
    }
    setState(() {
      _selected = row;
      _liveCode = null;
      _liveCodeForId = null;
    });
    await _loadRecovery();
  }

  @override
  Widget build(BuildContext context) {
    final visibleItems = _items
        .where((row) =>
            _filterGroupId == null || row['group_id'] == _filterGroupId)
        .toList();
    return CredentialPanel(
      detailsOnly: widget.initialSelection != null,
      detailNotice: _status.isEmpty ? null : AppNotice(_status),
      header: [
          AppSectionHeader(
            compact: defaultTargetPlatform == TargetPlatform.android,
            title: tr('credentials.build.title.item7'),
            subtitle: tr('credentials.mfa.count', args: {'count': visibleItems.length}),
            action: defaultTargetPlatform == TargetPlatform.android
                ? IconButton.filled(
                    tooltip: tr('credentials.build.text.item9'),
                    onPressed: _addTotp,
                    icon: const Icon(Icons.add_rounded))
                : FilledButton.icon(
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
                        final code = _liveCode;
                        if (code == null) return;
                        try {
                          final session = await AgentBridge.clipboardSession();
                          if (!mounted) return;
                          await AgentBridge.copyConcealed(code, session: session);
                        } catch (error) { vaultMessage(context, error); return; }
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
      ],
      body: CredentialWorkspace(
        detailsOnly: widget.initialSelection != null,
            list: visibleItems.isEmpty
                ? AppEmptyState(
                    icon: Icons.pin_outlined,
                    title: tr('credentials.build.title.item8'),
                    message: tr('credentials.build.message.item4'))
                : buildGroupedList(
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
                          onTap: () => _select(row),
                        );
                      },
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
                        title: '恢复码',
                        children: [
                          Text(_recoveryLine),
                          OutlinedButton(onPressed: () async { await _showRecovery(_selected!); await _loadRecovery(); }, child: const Text('查看或录入')),
                        ],
                      ),
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
            action: Wrap(spacing: 8, runSpacing: 8, children: [
              if (Theme.of(context).platform == TargetPlatform.macOS)
                OutlinedButton.icon(onPressed: () => showGitSshSettings(context), icon: const Icon(Icons.settings_ethernet), label: const LText('ssh.git.settings')),
              FilledButton.icon(
                onPressed: _generate,
                icon: const Icon(Icons.add_rounded),
                label: const LText('credentials.build.text.item21')),
            ]),
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
                : buildGroupedList(
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
  String _log = '';
  String _restoreError = '';
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
      // 页面保留在导航栈中，旧请求不能把锁定前的数据重新写回。
      if (!mounted || !widget.unlocked || generation != _loadGeneration) return;
      setState(() {
        _backupStatus = backupStatus;
        _restorePoints = restorePoints;
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

  Future<void> _recoverPoint(Map<String, dynamic> point) async {
    String? password;
    if (point['requires_password'] == true) {
      final controller = TextEditingController();
      final form = GlobalKey<FormState>();
      ModalRoute<String>? route;
      try {
        password = await showDialog<String>(
          context: context,
          builder: (ctx) {
            route = ModalRoute.of<String>(ctx);
            return AlertDialog(
              title: const LText('credentials.recoverPoint.text'),
              content: Form(key: form, child: SizedBox(width: appEditDialogWidth(ctx), child: Column(
                mainAxisSize: MainAxisSize.min,
                children: appFormFields([
                  const LText('credentials.recoverPoint.text.item2'),
                  AppFieldRow(label: tr('credentials.recoverPoint.text.item3'), child: TextFormField(controller: controller, obscureText: true, autofocus: true,
                    autocorrect: false, enableSuggestions: false, enableIMEPersonalizedLearning: false,
                    validator: (value) => (value ?? '').isEmpty ? tr('vault.recoverOvb.passwordRequired') : null,
                    decoration: InputDecoration())),
                ]),
              ))),
              actions: [
                TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.cancel')),
                FilledButton(onPressed: () {
                  if (form.currentState?.validate() == true) Navigator.pop(ctx, controller.text);
                }, child: const LText('common.continue')),
              ],
            );
          },
        );
      } finally { await route?.completed; controller.dispose(); }
      if (password == null || !mounted) return;
    }
    final target = await AgentBridge.pickDirectory();
    if (target == null || !mounted) return;
    if (!await requireTouchId(context, reason: tr('credentials.recoverPoint.reason')) || !mounted) return;
    final ts = point['created_at_ms'] as int? ?? 0;
    try {
      await AgentBridge.recoverRestorePoint(ts, target, password: password);
      await AgentBridge.lockVault();
      await AgentBridge.vaultOpenDir(target);
      widget.onVaultSwitched?.call();
      if (mounted) setState(() => _log = tr('credentials.recoverPoint.text.item4', args: {'target': target}));
    } on AgentException catch (e) {
      if (mounted) setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  Future<void> _migrateVault() async {
    if (!mounted || !widget.unlocked) return;
    final target = await AgentBridge.pickDirectory();
    if (target == null || !mounted || !widget.unlocked) return;
    // 系统目录选择可能耗时很久，应在选定目标后才取得短期敏感授权。
    if (!await requireTouchId(context, reason: tr('credentials.migrateVault.reason')) || !mounted) return;
    try {
      await AgentBridge.migrateVault(target);
      if (!mounted) return;
      setState(() => _log = tr('credentials.migrateVault.text', args: {'target': target}));
      await _loadAll();
    } on AgentException catch (e) {
      if (mounted) setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  Future<void> _recoverOvbToEmptyDir() async {
    if (!mounted || !widget.unlocked) return;
    final password = _rebuildPassword.text;
    final recoveryKey = _recoveryKey.text.trim();
    if (password.isEmpty && recoveryKey.isEmpty) {
      setState(() => _restoreError = tr('vault.recoverOvb.credentialsRequired'));
      return;
    }
    setState(() => _restoreError = '');
    final ovb = await AgentBridge.pickOpenFile();
    if (ovb == null || !mounted || !widget.unlocked) return;
    final target = await AgentBridge.pickDirectory();
    if (target == null || !mounted || !widget.unlocked) return;
    try {
      await AgentBridge.vaultRecoverOvb(
        ovbPath: ovb,
        targetDir: target,
        password: password.isNotEmpty ? password : null,
        recoveryKey: recoveryKey.isNotEmpty ? recoveryKey : null,
      );
      await AgentBridge.lockVault();
      await AgentBridge.vaultOpenDir(target);
      widget.onVaultSwitched?.call();
      if (mounted) setState(() => _log = tr('credentials.recoverOvbToEmptyDir.text', args: {'target': target}));
    } on AgentException catch (e) {
      if (mounted) setState(() => _log = AgentBridge.diagnosticMessage(e));
    }
  }

  @override
  void didUpdateWidget(covariant SecurityCenterTab oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!widget.unlocked && oldWidget.unlocked) {
      _loadGeneration++;
      _backupStatus = {};
      _restorePoints = [];
      _log = '';
      _recoveryKey.clear();
      _rebuildPassword.clear();
      _restoreError = '';
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
            if (_restoreError.isNotEmpty) AppNotice(_restoreError),
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
