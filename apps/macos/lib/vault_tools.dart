import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'agent_bridge.dart';
import 'touch_id_gate.dart';
import 'app_ui.dart';
import 'totp_editor.dart';
import 'credentials_page.dart' show showLoginEditor;
import 'server_login_page.dart' show showServerProfileEditor;
import 'credential_confirm.dart';
import 'credential_group_ui.dart';
import 'credential_list_tile.dart';
import 'ssh_git_ui.dart';

Future<Map<String, dynamic>> vaultAction(
    BuildContext context, Map<String, dynamic> action,
    {bool confirmed = false}) async {
  final sensitive = !{
    'generate_password',
    'login_website_rules',
    'website_rules_test',
    'totp_parse',
    'item_search',
    'security_report',
    'trash_list',
    'note_create'
  }.contains(action['action']);
  if (sensitive &&
      !await requireTouchId(context, reason: tr('vaultTools.vaultAction.reason'), confirmed: confirmed))
    throw AgentException('cancelled', tr('common.cancelled'));
  return AgentBridge.manage(action);
}

Future<bool> confirmVaultAction(
        BuildContext context, String title, String message) async =>
    await showDialog<bool>(
        context: context,
        builder: (ctx) =>
            AlertDialog(title: LText(title), content: LText(message), actions: [
              TextButton(
                  onPressed: () => Navigator.pop(ctx, false),
                  child: const LText('common.cancel')),
              FilledButton(
                  onPressed: () => Navigator.pop(ctx, true),
                  child: const LText('common.confirm')),
            ])) ==
    true;
void vaultMessage(BuildContext context, Object error) {
  if (!context.mounted) return;
  final text = error is AgentException
      ? (error.code == 'cancelled' ? tr('common.cancelled') : error.message)
      : tr('common.operationFailed');
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: LText(text)));
}

String vaultDate(dynamic ms) => ms is num && ms > 0
    ? DateTime.fromMillisecondsSinceEpoch(ms.toInt())
        .toLocal()
        .toString()
        .split('.')
        .first
    : tr('common.unknown');

/// 0 为未知；选择日期时记录当地零点，未修改则保留原来的完整时间。
class PasswordActiveDateField extends StatelessWidget {
  const PasswordActiveDateField({super.key, required this.value, required this.onChanged, this.enabled = true});
  final int value;
  final ValueChanged<int> onChanged;
  final bool enabled;

  @override
  Widget build(BuildContext context) => AppFieldRow(
    label: tr('vaultTools.build.text'), help: tr('vaultTools.build.text.item2'),
    child: InputDecorator(
    decoration: const InputDecoration(),
    child: Row(children: [
      Expanded(child: Text(value > 0 ? vaultDate(value) : tr('common.unknown'))),
      TextButton(onPressed: !enabled ? null : () async {
        final now = DateTime.now();
        final current = value > 0 ? DateTime.fromMillisecondsSinceEpoch(value) : now;
        final first = DateTime(1970, 1, 2);
        final date = await showDatePicker(context: context,
          initialDate: current.isBefore(first) || current.isAfter(now) ? now : current,
          firstDate: first, lastDate: now);
        if (context.mounted && date != null) onChanged(date.millisecondsSinceEpoch);
      }, child: const LText('vaultTools.build.text.item3')),
      TextButton(onPressed: !enabled ? null : () => onChanged(0), child: const LText('common.unknown')),
    ]),
  ));
}

Future<void> showPasswordVersions(
    BuildContext context, Map<String, dynamic> row) async {
  try {
    final initial = await vaultAction(
        context, {'action': 'password_versions', 'credential_id': row['id']});
    if (!context.mounted) return;
    await showDialog<void>(
        context: context,
        builder: (_) => _PasswordVersions(row: row, initial: initial));
  } catch (e) {
    vaultMessage(context, e);
  }
}

class _PasswordVersions extends StatefulWidget {
  const _PasswordVersions({required this.row, required this.initial});
  final Map<String, dynamic> row, initial;
  @override
  State<_PasswordVersions> createState() => _PasswordVersionsState();
}

class _PasswordVersionsState extends State<_PasswordVersions> {
  late Map<String, dynamic> data = widget.initial;
  bool busy = false;
  final Set<String> visible = {};
  Future<void> toggleVisible(String id) async {
    if (visible.contains(id)) {
      setState(() => visible.remove(id));
      return;
    }
    try {
      if (await requireTouchId(context, reason: tr('vaultTools.toggleVisible.reason')) && mounted) {
        setState(() => visible.add(id));
      }
    } catch (e) {
      vaultMessage(context, e);
    }
  }

  Future<void> _operate(
      String action, Map<String, dynamic> version, bool candidate) async {
    final title = action == 'candidate_activate'
        ? tr('vaultTools.operate.text')
        : action == 'history_restore'
            ? tr('vaultTools.operate.text.item2')
            : tr('vaultTools.operate.text.item3');
    if (!await confirmVaultAction(
        context,
        title,
        action == 'candidate_activate'
            ? tr('vaultTools.operate.text.item4')
            : action == 'history_restore'
                ? tr('vaultTools.operate.text.item5')
                : tr('vaultTools.operate.text.item6'))) return;
    setState(() => busy = true);
    try {
      await vaultAction(
          context,
          {
            'action': action,
            'credential_id': widget.row['id'],
            if (action != 'candidate_discard')
              'expected_revision': data['current_revision'],
            (candidate ? 'candidate_id' : 'history_id'): version['id']
          },
          confirmed: true);
      final next = await vaultAction(context,
          {'action': 'password_versions', 'credential_id': widget.row['id']},
          confirmed: true);
      if (mounted)
        setState(() {
          data = next;
          visible.clear();
        });
    } catch (e) {
      vaultMessage(context, e);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Widget _versions(String title, String key, bool candidate) {
    final values = (data[key] as List? ?? []).cast<Map>();
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      LText('${tr(title)} · ${values.length}',
          style: Theme.of(context).textTheme.titleMedium),
      if (values.isEmpty)
        const Padding(padding: EdgeInsets.all(12), child: LText('common.noRecords')),
      for (final v in values)
        Card(
            child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      LText(candidate
                          ? tr('passwordVersions.candidate.createdAt', args: {'date': vaultDate(v['created_at_ms'])})
                          : tr('passwordVersions.history.dates', args: {'activatedAt': vaultDate(v['activated_at_ms']), 'retiredAt': vaultDate(v['retired_at_ms'])})),
                      if (candidate &&
                          v['base_active_revision'] !=
                              data['active_password_revision'])
                        const LText('vaultTools.versions.text.item3'),
                      const SizedBox(height: 8),
                      SelectableText(
                          visible.contains(v['id'])
                              ? v['secret'].toString()
                              : '••••••••••••',
                          style: const TextStyle(fontFamily: 'monospace')),
                      Wrap(spacing: 8, children: [
                        TextButton(
                            onPressed: busy
                                ? null
                                : () => toggleVisible(v['id'].toString()),
                            child: const LText('common.toggleVisibility')),
                        TextButton(
                            onPressed: busy
                                ? null
                                : () async {
                                    try {
                                      final session = await AgentBridge.clipboardSession();
                                      if (!mounted) return;
                                      if (await requireTouchId(context,
                                          reason: tr('server.build.text.item11')))
                                        await AgentBridge.copyConcealed(
                                            v['secret'].toString(), session: session);
                                    } catch (e) {
                                      vaultMessage(context, e);
                                    }
                                  },
                            child: const LText('common.copy')),
                        TextButton(
                            onPressed: busy ||
                                    (candidate &&
                                        v['base_active_revision'] !=
                                            data['active_password_revision'])
                                ? null
                                : () => _operate(
                                    candidate
                                        ? 'candidate_activate'
                                        : 'history_restore',
                                    Map<String, dynamic>.from(v),
                                    candidate),
                            child: LText(candidate ? tr('vaultTools.versions.text.item4') : tr('vaultTools.versions.text.item5'))),
                        if (candidate)
                          TextButton(
                              onPressed: busy
                                  ? null
                                  : () => _operate('candidate_discard',
                                      Map<String, dynamic>.from(v), true),
                              child: const LText('vaultTools.versions.text.item6')),
                      ])
                    ]))),
    ]);
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
          title: const LText('vaultTools.build.text.item4'),
          content: SizedBox(
              width: 620,
              height: 440,
              child: SingleChildScrollView(
                  child: Column(children: [
                const LText('vaultTools.build.text.item5'),
                const SizedBox(height: 16),
                _versions(tr('vaultTools.build.text.item6'), 'candidates', true),
                const SizedBox(height: 16),
                _versions(tr('vaultTools.build.text.item7'), 'history', false),
              ]))),
          actions: [
            TextButton(
                onPressed: busy ? null : () => Navigator.pop(context),
                child: const LText('common.close'))
          ]);
}

Future<void> editItemDetails(
    BuildContext context, Map<String, dynamic> row) async {
  try {
    final result = await vaultAction(context,
        {'action': 'item_details', 'item_id': row['item_id'] ?? row['id']});
    final all =
        await AgentBridge.manage({'action': 'item_search', 'query': ''}, partitionId: row['partition_id']?.toString());
    final groups = await loadCredentialGroups(credentialGroupScope(result['kind'] as String), partitionId: result['partition_id'] as String);
    if (!context.mounted) return;
    await showDialog<void>(
        context: context,
        barrierDismissible: false,
        builder: (_) => _ItemDetailsDialog(
            row: {...row, 'kind': result['kind']}, data: result, all: (all['items'] as List).cast<Map>(), groups: groups));
  } catch (e) {
    vaultMessage(context, e);
  }
}

class _ItemDetailsDialog extends StatefulWidget {
  const _ItemDetailsDialog(
      {required this.row, required this.data, required this.all, required this.groups});
  final Map<String, dynamic> row, data;
  final List<Map> all;
  final List<Map<String, dynamic>> groups;
  @override
  State<_ItemDetailsDialog> createState() => _ItemDetailsDialogState();
}

class _ItemDetailsDialogState extends State<_ItemDetailsDialog> {
  late final Map<String, dynamic> details =
      Map<String, dynamic>.from(widget.data['details'] as Map);
  late final title =
      TextEditingController(text: widget.row['title']?.toString() ?? '');
  late final notes =
      TextEditingController(text: details['notes']?.toString() ?? '');
  late final gitRules = TextEditingController(text: (details['ssh_git_rules'] as List? ?? []).join('\n'));
  late final tags =
      TextEditingController(text: (details['tags'] as List? ?? []).join(', '));
  late final category =
      TextEditingController(text: details['category']?.toString() ?? '');
  late final history =
      TextEditingController(text: details['history_limit']?.toString() ?? '');
  late final reminder =
      TextEditingController(text: details['reminder_days']?.toString() ?? '');
  late final List<Map<String, dynamic>> fields =
      (details['custom_fields'] as List? ?? [])
          .map((e) => Map<String, dynamic>.from(e as Map))
          .toList();
  bool get isLogin => widget.row['kind'] == 'login' || widget.row.containsKey('origin');
  bool generalRelation(Map item) => !(isLogin && item['kind'] == 'passkey')
      && !(widget.row['kind'] == 'passkey' && item['kind'] == 'login');
  late String? groupId = widget.groups.any((group) => group['id'] == widget.data['group_id']) ? widget.data['group_id'] as String? : null;
  late int activeSince = (widget.data['password_active_since_ms'] as num?)?.toInt() ?? 0;
  late final Set<String> related = (details['related_item_ids'] as List? ?? [])
      .map((e) => e.toString())
      .toSet();
  bool busy = false;
  String message = '';
  bool closing = false, confirmingDiscard = false;
  late final String initialSnapshot;
  String snapshot() => jsonEncode([title.text,notes.text,tags.text,category.text,history.text,reminder.text,fields,related.toList()..sort(),activeSince,details['favorite'],details['mfa_state'],details['ssh_sign_policy'],groupId,gitRules.text]);
  @override
  void initState() { super.initState(); initialSnapshot = snapshot(); }
  Future<void> cancel() async {
    if (busy || closing || confirmingDiscard) return;
    confirmingDiscard = true;
    try {
      if (snapshot() != initialSnapshot && !await confirmDiscardChanges(context)) return;
      if (mounted) { closing = true; Navigator.pop(context); }
    } finally { confirmingDiscard = false; }
  }
  @override
  void dispose() {
    for (final c in [title, notes, tags, category, history, reminder, gitRules]) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> save() async {
    if (busy || closing) return;
    final h = history.text.trim().isEmpty ? null : int.tryParse(history.text);
    final r = reminder.text.trim().isEmpty ? null : int.tryParse(reminder.text);
    if ((history.text.isNotEmpty && (h == null || h < 0 || h > 50)) ||
        (reminder.text.isNotEmpty && (r == null || r < 0 || r > 3650))) {
      setState(() => message = tr('vaultTools.save.message'));
      return;
    }
    setState(() => busy = true);
    try {
      if (!await confirmVaultAction(context, tr('vaultTools.save.text'), isLogin ? tr('vaultTools.save.text.item2') : tr('vaultTools.save.text.item3'))) return;
      if (!mounted) return;
      await vaultAction(
          context,
          {
            'action': 'item_details_save',
            'item_id': widget.row['item_id'] ?? widget.row['id'],
            'expected_revision': widget.data['current_revision'],
            if (widget.row['kind'] == 'secure_note') 'title': title.text,
            if (isLogin) 'password_active_since_ms': activeSince,
            'group_id': groupId ?? '',
            'details': {
              ...details,
              'notes': notes.text,
              'ssh_git_rules': sshGitRules(gitRules),
              'tags': tags.text
                  .split(RegExp('[,，]'))
                  .map((v) => v.trim())
                  .where((v) => v.isNotEmpty)
                  .toList(),
              'category': category.text.trim(),
              'history_limit': h,
              'reminder_days': r,
              'custom_fields': fields,
              'related_item_ids': related.toList(),
            }
          },
          confirmed: true);
      AgentBridge.notifyVaultChanged();
      if (mounted) { closing = true; Navigator.pop(context); }
    } catch (e) {
      if (mounted)
        setState(() => message = e is AgentException ? e.message : tr('vaultTools.save.message.item2'));
    } finally {
      if (mounted && !closing) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => PopScope(canPop: false, onPopInvokedWithResult: (didPop, _) { if (!didPop) cancel(); }, child: AppEditDialog(
          title: LText(
              'credentials.details.title', args: {'title': widget.row['title'] ?? widget.row['display_name'] ?? ''}),
          content: SizedBox(
              width: appEditDialogWidth(context),
              height: Theme.of(context).platform == TargetPlatform.android ? null : MediaQuery.sizeOf(context).height * .6,
              child: AbsorbPointer(absorbing: busy, child: SingleChildScrollView(
                  child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: appFormFields([
                    LText('vaultTools.build.text.item9', style: Theme.of(context).textTheme.titleMedium),
                    AppFieldRow(label: tr('common.group'), child: DropdownButtonFormField<String>(value: groupId, isExpanded: true,
                      items: [const DropdownMenuItem(value: null, child: LText('common.ungroupedOption')),
                        for (final group in widget.groups) DropdownMenuItem(value: group['id'] as String,
                          child: Text(credentialGroupLabel(group), overflow: TextOverflow.ellipsis))],
                      onChanged: busy ? null : (value) => setState(() => groupId = value))),
                    if (widget.row['kind'] == 'secure_note')
                      AppFieldRow(label: tr('common.title'), child: TextField(
                          controller: title,
                          decoration: InputDecoration())),
                    AppFieldRow(label: tr('vaultTools.build.text.item10'),
                      child: Align(alignment: Alignment.centerLeft, child: Switch(
                        value: details['favorite'] == true,
                        onChanged: busy
                            ? null
                            : (v) => setState(() => details['favorite'] = v)))),
                    AppFieldRow(label: tr('vaultTools.build.text.item11'), child: TextField(
                        controller: tags,
                        // 身份验证结束后重新建立编辑焦点和原生文本输入连接。
                        autofocus: true,
                        decoration: InputDecoration())),
                    AppFieldRow(label: tr('vaultTools.build.text.item12'), child: TextField(
                        controller: category,
                        decoration: InputDecoration())),
                    AppFieldRow(label: tr('vaultTools.build.text.item13'), child: TextField(
                        controller: notes,
                        minLines: 3,
                        maxLines: 8,
                        decoration:
                            InputDecoration())),
                    const SizedBox(height: 16),
                    LText('vaultTools.build.text.item14',
                        style: Theme.of(context).textTheme.titleMedium),
                    for (final f in fields)
                      Row(key: ObjectKey(f), children: [
                        Expanded(
                            child: AppFieldRow(label: tr('vaultTools.build.text.item15'), child: TextFormField(
                                initialValue: f['name']?.toString() ?? '',
                                decoration:
                                    InputDecoration(),
                                onChanged: (v) => f['name'] = v))),
                        const SizedBox(width: 8),
                        Expanded(
                            child: AppFieldRow(label: tr('common.value'), child: TextFormField(
                                initialValue: f['value']?.toString() ?? '',
                                obscureText: f['secret'] == true,
                                decoration: InputDecoration(),
                                onChanged: (v) => f['value'] = v))),
                        Checkbox(
                            value: f['secret'] == true,
                            onChanged: (v) async {
                              if (v == false &&
                                  !await requireTouchId(context,
                                      reason: tr('vaultTools.build.reason'))) return;
                              if (mounted) setState(() => f['secret'] = v);
                            }),
                        IconButton(
                            onPressed: () => setState(() => fields.remove(f)),
                            icon: const Icon(Icons.close))
                      ]),
                    TextButton.icon(
                        onPressed: () => setState(() => fields
                            .add({'name': '', 'value': '', 'secret': true})),
                        icon: const Icon(Icons.add),
                        label: const LText('vaultTools.build.text.item16')),
                    const SizedBox(height: 12),
                    if (widget.row['kind'] == 'ssh_key') AppFieldRow(label: tr('vaultTools.build.text.item17'), child: DropdownButtonFormField<String>(isExpanded: true,
                      value: details['ssh_sign_policy']?.toString() ?? '',
                      decoration: InputDecoration(),
                      items: const [DropdownMenuItem(value:'',child:LText('vaultTools.build.text.item18')),DropdownMenuItem(value:'session',child:LText('settings.build.text.item19')),DropdownMenuItem(value:'confirm',child:LText('settings.build.text.item20')),DropdownMenuItem(value:'biometric',child:LText('settings.build.text.item21'))],
                      onChanged: busy ? null : (v) => setState(() => details['ssh_sign_policy'] = v))),
                    if (widget.row['kind'] == 'ssh_key') SshGitRulesField(controller: gitRules, enabled: !busy),
                    if (isLogin) ...[
                    const Divider(),
                    LText('vaultTools.build.text.item19', style: Theme.of(context).textTheme.titleMedium),
                    PasswordActiveDateField(value: activeSince, enabled: !busy, onChanged: (v) => setState(() => activeSince = v)),
                    Row(children: [
                      Expanded(
                          child: AppFieldRow(label: tr('vaultTools.build.text.item20'), help: tr('vaultTools.build.text.item21'), child: TextField(
                              controller: history,
                              keyboardType: TextInputType.number,
                              decoration: InputDecoration()))),
                      const SizedBox(width: 12),
                      Expanded(
                          child: AppFieldRow(label: tr('vaultTools.build.text.item22'), help: tr('vaultTools.build.text.item23'), child: TextField(
                              controller: reminder,
                              keyboardType: TextInputType.number,
                              decoration: InputDecoration())))
                    ]),
                    AppFieldRow(label: tr('vaultTools.build.text.item24'), help: tr('vaultTools.build.text.item25'), child: DropdownButtonFormField<String>(isExpanded: true,
                        value: ['enabled', 'disabled', 'unknown']
                                .contains(details['mfa_state'])
                            ? details['mfa_state'] as String
                            : 'unknown',
                        decoration: InputDecoration(),
                        items: const [
                          DropdownMenuItem(
                              value: 'unknown', child: LText('common.unknown')),
                          DropdownMenuItem(
                              value: 'enabled', child: LText('common.enabled')),
                          DropdownMenuItem(
                              value: 'disabled', child: LText('common.disabled.variant1'))
                        ],
                        onChanged: busy ? null : (v) => setState(() => details['mfa_state'] = v))),
                    ],
                    if (isLogin) ...[
                      const Divider(),
                      LText('credentials.passkey.title', style: Theme.of(context).textTheme.titleMedium),
                      const LText('passkey.links.accountHelp'),
                      if (!widget.all.any((item) => item['kind'] == 'passkey')) const LText('common.noRecords'),
                      for (final item in widget.all.where((item) => item['kind'] == 'passkey')) CheckboxListTile(
                        dense: true,
                        title: Text(item['title']?.toString() ?? ''),
                        value: related.contains(item['id']),
                        onChanged: busy ? null : (value) => setState(() => value == true
                            ? related.add(item['id'].toString()) : related.remove(item['id'])),
                      ),
                    ],
                    const Divider(),
                    LText('vaultTools.build.text.item26', style: Theme.of(context).textTheme.titleMedium),
                    const LText('vaultTools.build.text.item27'),
                    if (related.isNotEmpty) Wrap(spacing: 8, runSpacing: 8, children: [
                      for (final item in widget.all.where((v) => generalRelation(v) && related.contains(v['id']))) ActionChip(
                        avatar: const Icon(Icons.open_in_new, size: 16),
                        label: Text(item['title']?.toString() ?? ''),
                        onPressed: busy ? null : () => openCredentialActions(context, Map<String, dynamic>.from(item))),
                    ]),
                    if (widget.all.any((v) => generalRelation(v) && (v['related_item_ids'] as List? ?? []).contains(widget.row['item_id'] ?? widget.row['id']))) ...[
                      const LText('vaultTools.build.text.item28'),
                      Wrap(spacing: 8, runSpacing: 8, children: [
                        for (final item in widget.all.where((v) => generalRelation(v) && (v['related_item_ids'] as List? ?? []).contains(widget.row['item_id'] ?? widget.row['id']))) ActionChip(
                          label: Text(item['title']?.toString() ?? ''),
                          onPressed: busy ? null : () => openCredentialActions(context, Map<String, dynamic>.from(item))),
                      ]),
                    ],
                    const LText('vaultTools.build.text.item29'),
                    for (final stale in related
                        .where(
                            (id) => !widget.all.any((item) => item['id'] == id))
                        .toList())
                      InputChip(
                          label: const LText('vaultTools.build.text.item30'),
                          onDeleted: () =>
                              setState(() => related.remove(stale))),
                    for (final item in widget.all.where((v) =>
                        generalRelation(v) && v['id'] != (widget.row['item_id'] ?? widget.row['id'])))
                      CheckboxListTile(
                          dense: true,
                          title: LText('${item['title']} · ${item['kind']}'),
                          value: related.contains(item['id']),
                          onChanged: (v) => setState(() => v == true
                              ? related.add(item['id'].toString())
                              : related.remove(item['id']))),
                    if (message.isNotEmpty) Text(message),
                  ]))))),
          actions: [
            TextButton(
                onPressed: busy ? null : cancel,
                child: const LText('common.cancel')),
            FilledButton(
                onPressed: busy ? null : save, child: const LText('common.save'))
          ]));
}

class VaultToolsPanel extends StatefulWidget {
  const VaultToolsPanel({super.key, this.trashOnly = false});
  final bool trashOnly;
  @override
  State<VaultToolsPanel> createState() => _VaultToolsPanelState();
}

class _VaultToolsPanelState extends State<VaultToolsPanel> {
  String mode = 'items', query = '', message = '';
  final _queryController = TextEditingController();
  Timer? _searchDebounce;
  int _loadGeneration = 0;
  bool busy = false, favorites = false, _changingTrash = false;
  bool get _working => busy || _changingTrash;
  List<Map<String, dynamic>> items = [];
  List<Map<String, dynamic>> groups = [];
  String? filterGroupId;
  List<Map<String, dynamic>> get visibleItems => items.where((row) => mode != 'items' ||
    ((!favorites || row['favorite'] == true) && (filterGroupId == null || row['group_id'] == filterGroupId))).toList();
  void _onVaultChanged() { if (mounted && !_changingTrash) load(); }

  @override
  void dispose() {
    AgentBridge.vaultChanges.removeListener(_onVaultChanged);
    _queryController.dispose();
    _searchDebounce?.cancel();
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
    if (widget.trashOnly) mode = 'trash';
    AgentBridge.vaultChanges.addListener(_onVaultChanged);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) load();
    });
  }

  Future<void> load() async {
    _searchDebounce?.cancel();
    final generation = ++_loadGeneration;
    setState(() => busy = true);
    try {
      final result = await vaultAction(context, {
        'action': mode == 'trash'
            ? 'trash_list'
            : mode == 'security'
                ? 'security_report'
                : 'item_search',
        if (mode == 'items') 'query': query
      });
      final availableGroups = mode == 'items' ? await loadCredentialGroups('shared') : <Map<String, dynamic>>[];
      if (mounted && generation == _loadGeneration)
        setState(() {
          items = (result['items'] as List? ?? [])
              .map((v) => Map<String, dynamic>.from(v as Map))
              .toList();
          groups = availableGroups;
          if (!groups.any((group) => group['id'] == filterGroupId)) filterGroupId = null;
          message =
              mode == 'security' ? result['weak_rule']?.toString() ?? '' : '';
        });
    } catch (e) {
      if (generation == _loadGeneration) vaultMessage(context, e);
    } finally {
      if (mounted && generation == _loadGeneration) setState(() => busy = false);
    }
  }

  Future<void> note() async {
    if (await showNoteEditor(context) && mounted) await load();
  }

  Future<void> trashChange(Map<String, dynamic> row, bool purge) async {
    if (_working) return;
    setState(() => _changingTrash = true);
    try {
      final identifier = [row['title'], row['account']]
          .where((value) => value is String && value.trim().isNotEmpty)
          .join(' · ');
      final confirmed = purge
          ? await confirmCredentialDanger(context,
              title: tr('vaultTools.trashChange.text'),
              message: '${tr('vaultTools.trashChange.text.item3')}\n\n$identifier',
              confirmLabel: 'common.permanentlyDelete')
          : await confirmVaultAction(context,
              tr('vaultTools.trashChange.text.item2'),
              '${tr('vaultTools.trashChange.text.item4')}\n\n$identifier');
      if (!confirmed || !mounted) return;
      await vaultAction(
          context,
          {
            'action': purge ? 'trash_purge' : 'trash_restore',
            'item_id': row['id'],
            'expected_revision': row['current_revision']
          },
          confirmed: true);
      // 恢复/删除会影响其他凭据的关联信息，通知已打开的列表一起刷新。
      AgentBridge.notifyVaultChanged();
      if (!mounted) return;
      await load();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: LText(
            purge ? 'credentials.trash.purged' : 'credentials.trash.restored')));
      }
    } catch (e) {
      vaultMessage(context, e);
    } finally {
      if (mounted) setState(() => _changingTrash = false);
    }
  }

  String trashKind(dynamic kind) => tr(const {
    'login': 'credentials.login.title',
    'totp': 'MFA / TOTP',
    'ssh_key': 'credentials.ssh.title',
    'server_login': 'credentials.server.title',
    'passkey': 'credentials.passkey.title',
    'secure_note': 'credentials.notes.title',
    'recovery_codes': 'credentials.recovery.title',
  }[kind] ?? 'credentials.trash.other');

  @override
  Widget build(BuildContext context) {
    final mobile = defaultTargetPlatform == TargetPlatform.android;
    final search = TextField(
      controller: _queryController,
      decoration: InputDecoration(
        isDense: mobile,
        hintText: mobile ? tr('vaultTools.build.text.item35') : null,
        prefixIcon: mobile ? const Icon(Icons.search_rounded) : null,
        suffixIcon: query.isEmpty ? null : IconButton(tooltip: tr('credentials.list.clearSearch'), icon: const Icon(Icons.clear),
          onPressed: () { _searchDebounce?.cancel(); _queryController.clear(); query = ''; load(); }),
      ),
      onChanged: (v) {
        _searchDebounce?.cancel(); ++_loadGeneration;
        setState(() => query = v);
        _searchDebounce = Timer(const Duration(milliseconds:250), load);
      },
      onSubmitted: (_) { _searchDebounce?.cancel(); load(); },
    );
    return CredentialPanel(
      desktopPadding: const EdgeInsets.all(24),
      header: [
        AppSectionHeader(
          compact: mobile,
          title: tr(widget.trashOnly ? 'credentials.trash.title' : 'credentials.tools.title'),
          subtitle: tr(widget.trashOnly ? 'credentials.trash.description' : 'vaultTools.build.description'),
          action: Wrap(spacing: 8, runSpacing: 8, children: [
            if (mobile) ...[
              IconButton(
                tooltip: tr('common.loadRefresh'),
                onPressed: _working ? null : load,
                icon: const Icon(Icons.refresh)),
              if (!widget.trashOnly) IconButton.filled(
                tooltip: tr('vaultTools.build.text.item31'),
                onPressed: _working ? null : note,
                icon: const Icon(Icons.note_add_outlined)),
            ] else ...[
            OutlinedButton.icon(
                onPressed: _working ? null : load,
                icon: const Icon(Icons.refresh),
                label: const LText('common.loadRefresh')),
            if (!widget.trashOnly) FilledButton.icon(
                onPressed: _working ? null : note,
                icon: const Icon(Icons.note_add_outlined),
                label: const LText('vaultTools.build.text.item31')),
            ],
          ]),
        ),
        if (!widget.trashOnly) Wrap(spacing: 8, runSpacing: 8, children: [
          for (final entry in {
            'items': tr('vaultTools.build.text.item32'),
            'security': tr('vaultTools.build.text.item33'),
          }.entries)
            ChoiceChip(
                label: LText(entry.value),
                selected: mode == entry.key,
                onSelected: _working
                    ? null
                    : (_) {
                        setState(() => mode = entry.key);
                        load();
                      }),
        ]),
        const SizedBox(height: 12),
        if (mode == 'items')
          Row(children: [
            Expanded(child: mobile ? search : AppFieldRow(label: tr('vaultTools.build.text.item35'), child: search)),
            const SizedBox(width: 12),
            FilterChip(
                label: const LText('vaultTools.build.text.item36'),
                selected: favorites,
                onSelected: (v) => setState(() => favorites = v))
          ]),
        if (message.isNotEmpty)
          Padding(padding: const EdgeInsets.all(12), child: Text(message)),
        if (mode == 'items') buildGroupFilterBar(groups: groups, selectedGroupId: filterGroupId,
          onChanged: (value) => setState(() => filterGroupId = value),
          onManage: () async { await showManageGroupsDialog(context, 'shared'); if (mounted) await load(); }),
        if (_working) const LinearProgressIndicator(),
      ],
      body: mode != 'security' && visibleItems.isNotEmpty
        ? CredentialBatchList(
            key: ValueKey('tools-batch:${AgentBridge.activePartitionId}:$mode'),
            scope: mode == 'trash' ? 'trash' : 'shared', groups: groups, items: visibleItems, grouped: false, trashed: mode == 'trash',
            tileBuilder: (row) => _itemTile(context, row, mobile))
        : ListView(children: [
          if (visibleItems.isEmpty && !_working)
            Padding(
                padding: EdgeInsets.all(24),
                child: LText(widget.trashOnly ? 'credentials.trash.empty' : 'vaultTools.build.text.item37')),
          if (mode != 'items') for (final row in visibleItems) _itemTile(context, row, mobile),
      ]),
    );
  }

  Widget _itemTile(BuildContext context, Map<String, dynamic> row, bool mobile) => Card(
                child: ListTile(
                    title: Text(row['title']?.toString() ?? '', maxLines: mobile ? 2 : null, overflow: mobile ? TextOverflow.ellipsis : null),
                    subtitle: LText(mode == 'trash'
                        ? [
                            if ((row['account']?.toString() ?? '').isNotEmpty) row['account'],
                            tr('trash.item.deletedAt', args: {'kind': trashKind(row['kind']), 'date': vaultDate(row['trashed_at_ms'])})
                          ].join('\n')
                        : mode == 'security'
                            ? (row['reasons'] as List)
                                .map((r) =>
                                    {
                                      'weak': tr('vaultTools.build.text.item39'),
                                      'reused': tr('vaultTools.build.text.item40'),
                                      'activation_unknown': tr('vaultTools.build.text.item41'),
                                      'reminder_due': tr('vaultTools.build.text.item42'),
                                      'mfa_disabled': tr('vaultTools.build.text.item43'),
                                      'mfa_unknown': tr('vaultTools.build.text.item44'),
                                      'unused': tr('vaultTools.build.text.item45')
                                    }[r] ??
                                    r)
                                .join(' · ')
                            : tr('credentials.search.resultMetadata', args: {'username': row['kind'], 'origin': (row['tags'] as List? ?? []).join(' / '), 'date': vaultDate(row['last_used_at_ms'])})),
                    onTap: mode == 'trash'
                        ? null
                        : () async {
                            if (mode == 'security') { await openCredentialActions(context, row); }
                            else { await editItemDetails(context, row); }
                            if (mounted) load();
                          },
                    trailing: mode == 'trash'
                        ? mobile
                            ? PopupMenuButton<bool>(
                                enabled: !_working,
                                onSelected: (purge) => trashChange(row, purge),
                                itemBuilder: (_) => const [
                                  PopupMenuItem(value: false, child: LText('common.restore')),
                                  PopupMenuItem(value: true, child: LText('common.permanentlyDelete')),
                                ],
                              )
                            : Wrap(children: [
                            TextButton(
                                onPressed:
                                    _working ? null : () => trashChange(row, false),
                                child: const LText('common.restore')),
                            TextButton(
                                onPressed:
                                    _working ? null : () => trashChange(row, true),
                                style: TextButton.styleFrom(foregroundColor: Theme.of(context).colorScheme.error),
                                child: const LText('common.permanentlyDelete'))
                          ])
                        : mode == 'security'
                            ? PopupMenuButton<String>(
                                tooltip: tr('vaultTools.build.text.item47'),
                                onSelected: (action) => openCredentialActions(context, row, action: action),
                                itemBuilder: (_) => const [
                                  PopupMenuItem(value: 'edit', child: LText('vaultTools.build.text.item48')),
                                  PopupMenuItem(value: 'history', child: LText('vaultTools.build.text.item4')),
                                  PopupMenuItem(value: 'details', child: LText('vaultTools.build.text.item49')),
                                ],
                              )
                            : Wrap(children: [
                            IconButton(
                                icon: const Icon(Icons.more_horiz),
                                onPressed: () async {
                                  await editItemDetails(context, row);
                                  if (mounted) load();
                                }),
                            IconButton(
                                tooltip: tr('vaultTools.build.text.item50'),
                                icon: const Icon(Icons.delete_outline),
                                onPressed: busy
                                    ? null
                                    : () async {
                                        if (!await confirmVaultAction(
                                            context, tr('vaultTools.build.text.item51'), tr('vaultTools.build.text.item52')))
                                          return;
                                        if (!context.mounted ||
                                            !await requireTouchId(context,
                                                reason: tr('vaultTools.build.reason.item2'),
                                                confirmed: true)) return;
                                        try {
                                          await AgentBridge.trashCredential(
                                              row['item_id']?.toString() ??
                                                  row['id'].toString());
                                          if (mounted) await load();
                                        } catch (e) {
                                          vaultMessage(context, e);
                                        }
                                      })
                          ])));

}

Future<void> manageRecoveryEntries(
    BuildContext context, Map<String, dynamic> row) async {
  try {
    final result = await vaultAction(
        context, {'action': 'recovery_entries', 'id': row['id']});
    if (!context.mounted) return;
    await showDialog<void>(
        context: context,
        builder: (_) => _RecoveryEntriesDialog(row: row, initial: result));
  } catch (e) {
    vaultMessage(context, e);
  }
}

class _RecoveryEntriesDialog extends StatefulWidget {
  const _RecoveryEntriesDialog({required this.row, required this.initial});
  final Map<String, dynamic> row, initial;
  @override
  State<_RecoveryEntriesDialog> createState() => _RecoveryEntriesDialogState();
}

class _RecoveryEntriesDialogState extends State<_RecoveryEntriesDialog> {
  late Map<String, dynamic> data = widget.initial;
  bool busy = false;
  final Set<String> visible = {};
  Future<void> toggleVisible(String id) async {
    if (visible.contains(id)) {
      setState(() => visible.remove(id));
      return;
    }
    try {
      if (await requireTouchId(context, reason: tr('vaultTools.toggleVisible.reason.item2')) && mounted) {
        setState(() => visible.add(id));
      }
    } catch (e) {
      vaultMessage(context, e);
    }
  }

  Future<void> use(Map row, bool used) async {
    if (!await confirmVaultAction(
        context, used ? tr('vaultTools.use.text') : tr('vaultTools.use.text.item2'), tr('vaultTools.use.text.item3')))
      return;
    setState(() => busy = true);
    try {
      await vaultAction(
          context,
          {
            'action': 'recovery_entry_use',
            'id': widget.row['id'],
            'entry_id': row['id'],
            'expected_revision': data['current_revision'],
            'used': used
          },
          confirmed: true);
      final next = await vaultAction(
          context, {'action': 'recovery_entries', 'id': widget.row['id']},
          confirmed: true);
      if (mounted) setState(() => data = next);
    } catch (e) {
      vaultMessage(context, e);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final list = (data['items'] as List).cast<Map>();
    return AlertDialog(
        title: LText(
            'recovery.item.remaining', args: {'service': widget.row['service_name'], 'remaining': list.where((v) => v['used_at_ms'] == null).length, 'total': list.length}),
        content: SizedBox(
            width: 560,
            height: 400,
            child: ListView(children: [
              for (final row in list)
                Card(
                    child: Padding(
                        padding: const EdgeInsets.all(12),
                        child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              SelectableText(visible.contains(row['id'])
                                  ? row['code'].toString()
                                  : '••••••••'),
                              LText(row['used_at_ms'] == null
                                  ? tr('vaultTools.build.text.item54')
                                  : tr('recovery.code.usedAt', args: {'date': vaultDate(row['used_at_ms'])})),
                              Wrap(children: [
                                TextButton(
                                    onPressed: busy
                                        ? null
                                        : () =>
                                            toggleVisible(row['id'].toString()),
                                    child: const LText('common.toggleVisibility')),
                                TextButton(
                                    onPressed: busy
                                        ? null
                                        : () async {
                                            try {
                                              final session = await AgentBridge.clipboardSession();
                                              if (!mounted) return;
                                              if (await requireTouchId(context,
                                                  reason: tr('vaultTools.build.reason.item3'))) {
                                                await AgentBridge.copyConcealed(
                                                    row['code'].toString(), session: session);
                                              }
                                            } catch (e) {
                                              vaultMessage(context, e);
                                            }
                                          },
                                    child: const LText('vaultTools.build.text.item56')),
                                TextButton(
                                    onPressed: busy
                                        ? null
                                        : () =>
                                            use(row, row['used_at_ms'] == null),
                                    child: LText(row['used_at_ms'] == null
                                        ? tr('vaultTools.build.text.item57')
                                        : tr('vaultTools.build.text.item58')))
                              ])
                            ])))
            ])),
        actions: [
          TextButton(
              onPressed: busy ? null : () => Navigator.pop(context),
              child: const LText('common.close'))
        ]);
  }
}

Future<void> importBitwardenWithPreview(BuildContext context) async {
  try {
    await _importBitwardenWithPreview(context);
  } catch (e) {
    vaultMessage(context, e);
  }
}

Future<void> _importBitwardenWithPreview(BuildContext context) async {
  final path = await AgentBridge.pickOpenFile();
  if (path == null || !context.mounted) return;
  final password = TextEditingController(), namespace = TextEditingController(text: 'personal');
  var busy = false;
  var error = '';
  try {
    final preview = await showDraftDialog<Map<String,dynamic>>(context: context,
      hasChanges: () => password.text.isNotEmpty || namespace.text != 'personal', isBusy: () => busy,
      builder: (ctx) => StatefulBuilder(builder: (ctx, update) => AlertDialog(
        title: const LText('vaultTools.importBitwardenWithPreview.text'),
        content: SizedBox(width: appEditDialogWidth(ctx), child: Column(mainAxisSize: MainAxisSize.min, children: appFormFields([
          const LText('vaultTools.importBitwardenWithPreview.text.item2'),
          AppFieldRow(label: tr('vaultTools.importBitwardenWithPreview.text.item3'), child: TextField(controller: namespace, enabled: !busy, decoration: InputDecoration())),
          AppFieldRow(label: tr('vaultTools.importBitwardenWithPreview.text.item4'), child: TextField(controller: password, enabled: !busy, obscureText: true, decoration: InputDecoration())),
          if (error.isNotEmpty) LText(error),
        ]))),
        actions: [
          TextButton(onPressed: busy ? null : () => Navigator.maybePop(ctx), child: const LText('common.cancel')),
          FilledButton(onPressed: busy ? null : () async {
            update(() { busy = true; error = ''; });
            try {
              final value = await vaultAction(ctx, {'action':'bitwarden_preview','path':path,'password':password.text,'namespace':namespace.text});
              if (ctx.mounted) Navigator.pop(ctx,value);
            } catch (e) { if (ctx.mounted) update(() { error = e is AgentException ? e.message : tr('vaultTools.importBitwardenWithPreview.message'); busy = false; }); }
          }, child: LText(busy ? tr('vaultTools.importBitwardenWithPreview.text.item5') : tr('vaultTools.importBitwardenWithPreview.text.item6'))),
        ],
      )));
    if (preview == null || !context.mounted) return;
    final list = (preview['items'] as List).cast<Map>();
    final choices = <String,String>{for(final item in list) item['source_id'].toString(): item['state'] == 'new' ? 'import' : 'skip'};
    final initialChoices = jsonEncode(choices);
    busy = false;
    error = '';
    final report = await showDraftDialog<Map<String,dynamic>>(context: context,
      hasChanges: () => jsonEncode(choices) != initialChoices, isBusy: () => busy,
      builder: (ctx) => StatefulBuilder(builder: (ctx, update) => AlertDialog(
        title: const LText('vaultTools.importBitwardenWithPreview.text.item7'),
        content: SizedBox(width: appEditDialogWidth(ctx), height: 440, child: Column(children: [
          const LText('vaultTools.importBitwardenWithPreview.text.item8'),
          if (error.isNotEmpty) LText(error),
          if (busy) const LinearProgressIndicator(),
          Expanded(child: ListView(children: [for(final item in list) ListTile(
            title: Text(item['title'].toString()),
            subtitle: LText('import.preview.changes', args: {'state': {'new':tr('vaultTools.labels.text'),'changed':tr('vaultTools.labels.text.item2'),'unchanged':tr('vaultTools.labels.text.item3'),'unsupported':tr('vaultTools.labels.text.item4')}[item['state']], 'fields': (item['changed_fields'] as List? ?? []).join('、'), 'warnings': (item['warnings'] as List? ?? []).join('\n')}),
            trailing: DropdownButton<String>(value:choices[item['source_id']],
              items: [const DropdownMenuItem(value:'skip',child:LText('vaultTools.importBitwardenWithPreview.text.item10')),
                if(item['state']=='new') const DropdownMenuItem(value:'import',child:LText('common.import')),
                if(['changed','unchanged'].contains(item['state'])) ...const [DropdownMenuItem(value:'update',child:LText('vaultTools.importBitwardenWithPreview.text.item11')),DropdownMenuItem(value:'copy',child:LText('vaultTools.importBitwardenWithPreview.text.item12'))]],
              onChanged: busy ? null : (value) => update(() => choices[item['source_id'].toString()] = value ?? 'skip'))),
          ])),
        ])),
        actions: [
          TextButton(onPressed: busy ? null : () => Navigator.maybePop(ctx), child: const LText('common.cancel')),
          FilledButton(onPressed: busy ? null : () async {
            update(() { busy = true; error = ''; });
            try {
              final value = await vaultAction(ctx, {'action':'bitwarden_import','path':path,'password':password.text,
                'namespace':namespace.text,'choices':choices,'preview_token':preview['preview_token']}, confirmed:true);
              AgentBridge.notifyVaultChanged();
              if (ctx.mounted) Navigator.pop(ctx,value);
            } catch (e) { if (ctx.mounted) update(() { error = e is AgentException ? e.message : tr('vaultTools.importBitwardenWithPreview.message.item2'); busy = false; }); }
          }, child: LText(busy ? tr('vaultTools.importBitwardenWithPreview.text.item13') : tr('common.confirmImport'))),
        ],
      )));
    if (report == null || !context.mounted) return;
    await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
                title: const LText('vaultTools.importBitwardenWithPreview.text.item14'),
                content: SizedBox(
                    width: 620,
                    height: 400,
                    child: SingleChildScrollView(
                        child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                          LText(
                              'import.summary', args: {'created': report['imported'], 'updated': report['updated'], 'copied': report['copied'], 'skipped': report['skipped'], 'unsupported': report['skipped_invalid']}),
                          for (final item
                              in (report['items'] as List).cast<Map>())
                            Padding(
                                padding: const EdgeInsets.only(top: 10),
                                child: LText(
                                    '${item['title']}：${item['result']}\n${(item['warnings'] as List? ?? []).join('\n')}'))
                        ]))),
                actions: [
                  TextButton(
                      onPressed: () => Navigator.pop(ctx),
                      child: const LText('common.close'))
                ]));
  } catch (e) { vaultMessage(context,e); }
  finally { password.dispose(); namespace.dispose(); }
}

Future<void> transferSshKey(BuildContext context, {String? keyId}) async {
  final exporting = keyId != null;
  final label = TextEditingController(), passphrase = TextEditingController();
  String? pem;
  var busy = false, closing = false;
  var error = '';
  try {
    if (!exporting) {
      final path = await AgentBridge.pickOpenFile();
      if (path == null) return;
      pem = await AgentBridge.readTextFile(path);
    }
    if (!context.mounted) return;
    Future<void> save(BuildContext ctx, StateSetter update) async {
      if (busy || closing) return;
      update(() { busy = true; error = ''; });
      try {
        String? output;
        if (exporting) {
          output = await AgentBridge.pickSaveFile('id_ed25519');
          if (output == null || !ctx.mounted) return;
        }
        final result = await vaultAction(ctx, exporting
          ? {'action':'ssh_export','id':keyId,'passphrase':passphrase.text}
          : {'action':'ssh_import','label':label.text,'pem':pem,'passphrase':passphrase.text}, confirmed: true);
        if (exporting) await AgentBridge.writeTextFile(output!, result['pem'].toString());
        else AgentBridge.notifyVaultChanged();
        if (ctx.mounted) {
          closing = true;
          Navigator.pop(ctx);
          ScaffoldMessenger.of(ctx).showSnackBar(SnackBar(content: LText(exporting ? tr('vaultTools.save.text.item4', args: {'output': output}) : tr('vaultTools.save.text.item5'))));
        }
      } catch (e) { if (ctx.mounted) update(() => error = e is AgentException ? e.message : tr('common.operationFailed')); }
      finally { if (ctx.mounted && !closing) update(() => busy = false); }
    }
    await showDraftDialog<void>(context: context,
        hasChanges: () => label.text.isNotEmpty || passphrase.text.isNotEmpty, isBusy: () => busy,
        builder: (ctx) => StatefulBuilder(builder: (ctx, update) => AlertDialog(
                title: LText(exporting ? tr('vaultTools.save.text.item6') : tr('vaultTools.save.text.item7')),
                content: SizedBox(
                    width: appEditDialogWidth(ctx),
                    child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: appFormFields([
                      LText(exporting
                          ? tr('vaultTools.save.text.item8')
                          : tr('vaultTools.save.text.item9')),
                      if (!exporting)
                        AppFieldRow(label: tr('common.name'), child: TextField(
                            enabled: !busy, controller: label,
                            decoration: InputDecoration())),
                      if (error.isNotEmpty) LText(error, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
                      AppFieldRow(label: tr(exporting ? tr('vaultTools.save.text.item10') : tr('vaultTools.save.text.item11')), child: TextField(
                          enabled: !busy, controller: passphrase,
                          obscureText: true,
                          decoration: InputDecoration()))
                    ])))),
                actions: [
                  TextButton(
                      onPressed: busy ? null : () => Navigator.maybePop(ctx),
                      child: const LText('common.cancel')),
                  FilledButton(
                      onPressed: busy ? null : () => save(ctx, update),
                      child: LText(exporting ? tr('common.confirmExport') : tr('common.import')))
                ])));
  } catch (e) { vaultMessage(context,e); }
  finally { label.dispose(); passphrase.dispose(); }
}

Future<void> editTotp(BuildContext context, Map<String, dynamic> row) async {
  await showTotpEditor(context, existing: row);
}

Future<void> showTotpStatus(BuildContext context, String id) async {
  try {
    final result = await vaultAction(
        context, {'action': 'totp_status', 'id': id, 'min_valid_seconds': 0});
    if (!context.mounted) return;
    await showDialog<void>(
        context: context,
        builder: (_) => _TotpStatusDialog(id: id, initial: result));
  } catch (e) {
    vaultMessage(context, e);
  }
}

class _TotpStatusDialog extends StatefulWidget {
  const _TotpStatusDialog({required this.id, required this.initial});
  final String id;
  final Map<String, dynamic> initial;
  @override
  State<_TotpStatusDialog> createState() => _TotpStatusDialogState();
}

class _TotpStatusDialogState extends State<_TotpStatusDialog> {
  late String code = widget.initial['code']?.toString() ?? '';
  late int remaining =
      (widget.initial['remaining_seconds'] as num?)?.toInt() ?? 0;
  late int period = (widget.initial['period'] as num?)?.toInt() ?? 30;
  late DateTime expires = DateTime.fromMillisecondsSinceEpoch(
      (widget.initial['expires_at_ms'] as num?)?.toInt() ??
          DateTime.now().millisecondsSinceEpoch + remaining * 1000);
  String message = '';
  Timer? timer;
  bool loading = false;
  @override
  void initState() {
    super.initState();
    timer = Timer.periodic(const Duration(seconds: 1), (_) {
      final next = (expires.difference(DateTime.now()).inMilliseconds / 1000)
          .ceil()
          .clamp(0, period)
          .toInt();
      if (next != remaining) {
        setState(() => remaining = next);
      }
      if (remaining == 0 && code.isNotEmpty) {
        setState(() => code = '');
        refresh(false);
      }
    });
  }

  @override
  void dispose() {
    timer?.cancel();
    super.dispose();
  }

  Future<void> refresh(bool authenticate) async {
    if (loading) return;
    setState(() => loading = true);
    try {
      final result = authenticate
          ? await vaultAction(context, {
              'action': 'totp_status',
              'id': widget.id,
              'min_valid_seconds': 0
            })
          : await AgentBridge.manage({
              'action': 'totp_status',
              'id': widget.id,
              'min_valid_seconds': 0,
              'passive': true
            });
      if (mounted)
        setState(() {
          code = result['code']?.toString() ?? '';
          remaining = (result['remaining_seconds'] as num?)?.toInt() ?? 0;
          period = (result['period'] as num?)?.toInt() ?? 30;
          expires = DateTime.fromMillisecondsSinceEpoch(
              (result['expires_at_ms'] as num?)?.toInt() ??
                  DateTime.now().millisecondsSinceEpoch + remaining * 1000);
          message = '';
        });
    } catch (_) {
      if (mounted) setState(() => message = tr('vaultTools.refresh.message'));
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  Future<void> copy() async {
    try {
      final session = await AgentBridge.clipboardSession();
      if (!mounted) return;
      var result = await vaultAction(context,
          {'action': 'totp_status', 'id': widget.id, 'min_valid_seconds': 5});
      final wait = (result['wait_seconds'] as num?)?.toInt();
      if (wait != null) {
        if (mounted) setState(() => message = tr('vaultTools.copy.message'));
        await Future<void>.delayed(Duration(seconds: wait + 1));
        if (!mounted) return;
        result = await vaultAction(context,
            {'action': 'totp_status', 'id': widget.id, 'min_valid_seconds': 0});
      }
      final nextCode = result['code']?.toString() ?? '';
      if (mounted && nextCode.isNotEmpty)
        await AgentBridge.copyConcealed(nextCode, session: session);
    } catch (e) {
      vaultMessage(context, e);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
          title: const LText('credentials.build.title.item7'),
          content: SizedBox(
              width: 340,
              child: Column(mainAxisSize: MainAxisSize.min, children: [
                SelectableText(code.isEmpty ? '••••••' : code,
                    style: const TextStyle(
                        fontSize: 36,
                        fontFamily: 'monospace',
                        letterSpacing: 6)),
                const SizedBox(height: 16),
                LinearProgressIndicator(
                    value: period > 0 ? remaining / period : 0),
                LText('mfa.code.secondsRemaining', args: {'remaining': remaining}),
                if (message.isNotEmpty) Text(message)
              ])),
          actions: [
            TextButton(
                onPressed: loading ? null : () => refresh(true),
                child: const LText('common.refresh')),
            TextButton(
                onPressed: loading ? null : copy, child: const LText('common.copy')),
            TextButton(
                onPressed: () => Navigator.pop(context),
                child: const LText('common.close'))
          ]);
}

Future<void> copyTotpCode(BuildContext context, String id) async {
  try {
    final session = await AgentBridge.clipboardSession();
    if (!context.mounted) return;
    var result = await vaultAction(
        context, {'action': 'totp_status', 'id': id, 'min_valid_seconds': 5});
    final wait = (result['wait_seconds'] as num?)?.toInt();
    if (wait != null) {
      if (context.mounted)
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: LText('vaultTools.copy.message')));
      await Future<void>.delayed(Duration(seconds: wait + 1));
      if (!context.mounted) return;
      result = await vaultAction(
          context, {'action': 'totp_status', 'id': id, 'min_valid_seconds': 0});
    }
    final code = result['code']?.toString() ?? '';
    if (code.isNotEmpty && context.mounted) {
      await AgentBridge.copyConcealed(code, session: session);
      if (context.mounted)
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: LText('vaultTools.copyTotpCode.text')));
    }
  } catch (e) {
    vaultMessage(context, e);
  }
}

Future<String?> generatePasswordDialog(BuildContext context) async {
  return showDialog<String>(
      context: context, builder: (_) => const _PasswordGeneratorDialog());
}

class _PasswordGeneratorDialog extends StatefulWidget {
  const _PasswordGeneratorDialog();
  @override
  State<_PasswordGeneratorDialog> createState() =>
      _PasswordGeneratorDialogState();
}

class _PasswordGeneratorDialogState extends State<_PasswordGeneratorDialog> {
  int length = 24;
  bool symbols = true, excludeAmbiguous = true, busy = false;
  String password = '';
  Future<void> generate() async {
    setState(() => busy = true);
    try {
      final result = await vaultAction(context, {
        'action': 'generate_password',
        'length': length,
        'symbols': symbols,
        'exclude_ambiguous': excludeAmbiguous
      });
      if (mounted) setState(() => password = result['password'].toString());
    } catch (e) {
      vaultMessage(context, e);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => AppEditDialog(
          title: const LText('vaultTools.build.text.item60'),
          content: SizedBox(
              width: appEditDialogWidth(context),
              child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
                LText('passwordGenerator.length', args: {'length': length}),
                Slider(
                    value: length.toDouble(),
                    min: 12,
                    max: 128,
                    divisions: 116,
                    label: length.toString(),
                    onChanged: busy
                        ? null
                        : (v) => setState(() {
                              length = v.round();
                              password = '';
                            })),
                AppFieldRow(label: tr('vaultTools.build.text.item62'),
                  child: Align(alignment: Alignment.centerLeft, child: Switch(
                    value: symbols,
                    onChanged: busy
                        ? null
                        : (v) => setState(() {
                              symbols = v;
                              password = '';
                            })))),
                AppFieldRow(label: tr('vaultTools.build.text.item63'),
                  child: Align(alignment: Alignment.centerLeft, child: Switch(
                    value: excludeAmbiguous,
                    onChanged: busy
                        ? null
                        : (v) => setState(() {
                              excludeAmbiguous = v;
                              password = '';
                            })))),
                if (password.isNotEmpty)
                  SelectableText(password,
                      style: const TextStyle(fontFamily: 'monospace')),
                const SizedBox(height: 12),
                FilledButton(
                    onPressed: busy ? null : generate,
                    child: const LText('credentials.cancel.text.item6'))
              ]))),
          actions: [
            TextButton(
                onPressed: busy ? null : () => Navigator.pop(context),
                child: const LText('common.cancel')),
            TextButton(
                onPressed: password.isEmpty || busy
                    ? null
                    : () async {
                        try {
                          final session = await AgentBridge.clipboardSession();
                          if (!mounted) return;
                          if (await requireTouchId(context, reason: tr('vaultTools.build.reason.item4')))
                            await AgentBridge.copyConcealed(password, session: session);
                        } catch (error) { vaultMessage(context, error); }
                      },
                child: const LText('common.copy')),
            FilledButton(
                onPressed: password.isEmpty || busy
                    ? null
                    : () => Navigator.pop(context, password),
                child: const LText('vaultTools.build.text.item64'))
          ]);
}

Future<void> copySelectedCredential(BuildContext context, Map<String, dynamic> row) async {
  try {
    final kind = row['kind'];
    if (kind == 'totp') { await copyTotpCode(context, row['id'].toString()); return; }
    if (kind != 'login' && kind != 'ssh_key') return;
    final session = await AgentBridge.clipboardSession();
    if (!context.mounted) return;
    if (kind == 'ssh_key') { await AgentBridge.copyConcealed(row['public_openssh']?.toString() ?? '', session: session); return; }
    if (!await requireTouchId(context, reason: tr('vaultTools.copySelectedCredential.reason'))) return;
    final detail = await AgentBridge.getCredential(row['id'].toString());
    await AgentBridge.copyConcealed(detail['password']?.toString() ?? '', session: session);
    if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('vaultTools.copySelectedCredential.text')));
  } catch (e) { vaultMessage(context, e); }
}

Future<void> openCredentialActions(BuildContext context, Map<String, dynamic> item, {String? action}) async {
  try {
    final result = await AgentBridge.manage({'action':'item_search','query':''}, allPartitions: true);
    final itemId = item['item_id'] ?? item['id'];
    final matches = (result['items'] as List).cast<Map>().where((v) => v['id'] == itemId);
    if (matches.isEmpty) throw AgentException('not_found',tr('vaultTools.openCredentialActions.text'));
    final meta = Map<String, dynamic>.from(matches.first);
    final kind = meta['kind'];
    final partition = meta['partition_id']?.toString();
    Map<String, dynamic> current = meta;
    if (kind == 'login') {
      final rows = await AgentBridge.listCredentials(null, partition);
      current = rows.firstWhere((v) => v['item_id'] == itemId);
    } else if (kind == 'totp') {
      current = (await AgentBridge.listTotp(partitionId: partition)).firstWhere((v) => v['item_id'] == itemId);
    } else if (kind == 'ssh_key') {
      current = (await AgentBridge.listSshKeys(partitionId: partition)).firstWhere((v) => v['item_id'] == itemId);
    } else if (kind == 'recovery_codes') {
      current = (await AgentBridge.listRecoveryCodes(partitionId: partition)).firstWhere((v) => v['item_id'] == itemId);
    } else if (kind == 'server_login') {
      current = (await AgentBridge.listServerProfiles(partitionId: partition)).firstWhere((v) => v['item_id'] == itemId);
    }
    if (!context.mounted) return;
    if (action == 'details') { await editItemDetails(context,{...meta,...current,'item_id':itemId,'kind':kind}); AgentBridge.notifyVaultChanged(); return; }
    if (action == 'edit' && kind == 'login') { await showLoginEditor(context, existing: current); AgentBridge.notifyVaultChanged(); return; }
    if (action == 'edit' && kind == 'totp') { if (await showTotpEditor(context, existing: current)) AgentBridge.notifyVaultChanged(); return; }
    if (action == 'history' && kind == 'login') { await showPasswordVersions(context,current); AgentBridge.notifyVaultChanged(); return; }
    await showDialog<void>(context: context, builder: (ctx) => SimpleDialog(
      title: Text(meta['title']?.toString() ?? ''),
      children: [
        if (kind == 'login') ...[
          Padding(padding: const EdgeInsets.fromLTRB(24, 0, 24, 12), child: Column(children: [
            CredentialPreviewValue(current['origin']?.toString() ?? ''),
            CredentialPreviewValue(current['username']?.toString() ?? ''),
          ])),
          SimpleDialogOption(onPressed: () => openCredentialActions(ctx,meta,action:'edit'), child: const LText('vaultTools.openCredentialActions.text.item2')),
          SimpleDialogOption(onPressed: () => openCredentialActions(ctx,meta,action:'history'), child: const LText('vaultTools.build.text.item4')),
          SimpleDialogOption(onPressed: () => copySelectedCredential(ctx,{...current,'kind':'login'}), child: const LText('vaultTools.openCredentialActions.text.item3')),
        ],
        if (kind == 'totp') ...[
          SimpleDialogOption(onPressed: () => openCredentialActions(ctx,meta,action:'edit'), child: const LText('mfaLinks.card.text.item11')),
          SimpleDialogOption(onPressed: () => showTotpStatus(ctx,current['id'].toString()), child: const LText('vaultTools.openCredentialActions.text.item4')),
          SimpleDialogOption(onPressed: () => copyTotpCode(ctx,current['id'].toString()), child: const LText('credentials.build.text.item15')),
        ],
        if (kind == 'ssh_key') Padding(padding: const EdgeInsets.symmetric(horizontal:24), child: SelectableText(current['public_openssh']?.toString() ?? '')),
        if (kind == 'server_login') Padding(padding: const EdgeInsets.symmetric(horizontal:24), child: Column(children: [
          CredentialPreviewValue('${current['host']}:${current['port']}'),
          CredentialPreviewValue(current['manual_username']?.toString() ?? ''),
        ])),
        if (kind == 'recovery_codes') SimpleDialogOption(onPressed: () => manageRecoveryEntries(ctx,current), child: const LText('vaultTools.openCredentialActions.text.item5')),
        SimpleDialogOption(onPressed: () async { await editItemDetails(ctx,{...meta,...current,'item_id':itemId,'kind':kind}); AgentBridge.notifyVaultChanged(); }, child: const LText('vaultTools.openCredentialActions.text.item6')),
        SimpleDialogOption(onPressed: () => Navigator.pop(ctx), child: const LText('common.close')),
      ],
    ));
  } catch (e) { vaultMessage(context,e); }
}

Future<void> showCredentialSearch(BuildContext context) => showDialog<void>(context: context, builder: (_) => const _CredentialSearch());
class _CredentialSearch extends StatefulWidget {
  const _CredentialSearch();
  @override
  State<_CredentialSearch> createState() => _CredentialSearchState();
}
class _CredentialSearchState extends State<_CredentialSearch> {
  final query = TextEditingController();
  Timer? debounce;
  int generation = 0;
  List<Map<String, dynamic>> rows = [];
  String error = '';
  bool loading = false;
  void _onVaultChanged() { if (mounted) search(); }
  @override
  void initState() { super.initState(); AgentBridge.vaultChanges.addListener(_onVaultChanged); search(); }
  @override
  void dispose() { AgentBridge.vaultChanges.removeListener(_onVaultChanged); debounce?.cancel(); query.dispose(); super.dispose(); }
  Future<void> search() async {
    final version = ++generation;
    setState(() {loading=true;error='';});
    try {
      final result = await AgentBridge.manage({'action':'item_search','query':query.text.trim()}, allPartitions: true);
      if (mounted && version == generation) setState(() => rows = (result['items'] as List).map((v) => Map<String,dynamic>.from(v as Map)).toList());
    } catch (e) { if (mounted && version == generation) setState(() => error = e is AgentException ? e.message : tr('vaultTools.search.message')); }
    finally { if (mounted && version == generation) setState(() => loading=false); }
  }
  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const LText('vault.build.text.item4'),
    content: SizedBox(width:appEditDialogWidth(context),height:400,child:Column(children:[
      TextField(controller:query,autofocus:true,decoration:InputDecoration(hintText:tr('vaultTools.build.text.item65')),
        onChanged:(_){generation++;debounce?.cancel();debounce=Timer(const Duration(milliseconds:250),search);},onSubmitted:(_)=>search()),
      if(loading) const LinearProgressIndicator(),
      if(error.isNotEmpty) AppNotice(error),
      Expanded(child:ListView(children:[for(final row in rows.take(100)) ListTile(title:Text(row['title']?.toString()??''),subtitle:Text([row['kind'],row['partition_name']].where((v)=>v!=null).join(' · ')),onTap:()=>openCredentialActions(context,row)),
        if(rows.length>100) const ListTile(title:LText('vaultTools.build.text.item66'))])),
    ])),
    actions:[TextButton(onPressed:()=>Navigator.pop(context),child:const LText('common.close'))],
  );
}

Future<void> showNewCredentialMenu(BuildContext context) async {
  ModalRoute<String>? route;
  final choice = await showDialog<String>(context:context,builder:(ctx) {
    route = ModalRoute.of<String>(ctx);
    return SimpleDialog(title:const LText('credentials.actions.new'),children:[
    SimpleDialogOption(onPressed:()=>Navigator.pop(ctx,'login'),child:const LText('credentials.login.title')),
    SimpleDialogOption(onPressed:()=>Navigator.pop(ctx,'totp'),child:const LText('MFA / TOTP')),
    SimpleDialogOption(onPressed:()=>Navigator.pop(ctx,'ssh_generate'),child:const LText('vaultTools.showNewCredentialMenu.text')),
    SimpleDialogOption(onPressed:()=>Navigator.pop(ctx,'ssh'),child:const LText('vaultTools.showNewCredentialMenu.text.item2')),
    SimpleDialogOption(onPressed:()=>Navigator.pop(ctx,'server'),child:const LText('vaultTools.showNewCredentialMenu.text.item3')),
    SimpleDialogOption(onPressed:()=>Navigator.pop(ctx,'recovery'),child:const LText('credentials.recovery.websiteCodes')),
    SimpleDialogOption(onPressed:()=>Navigator.pop(ctx,'note'),child:const LText('credentials.notes.title')),
  ]);
  });
  await route?.completed;
  if(!context.mounted)return;
  if(choice=='login'){if(await showLoginEditor(context))AgentBridge.notifyVaultChanged();}
  if(choice=='totp'){if(await showTotpEditor(context))AgentBridge.notifyVaultChanged();}
  if(choice=='ssh'){await transferSshKey(context);AgentBridge.notifyVaultChanged();}
  if(choice=='ssh_generate'){if(await showSshKeyGenerator(context))AgentBridge.notifyVaultChanged();}
  if(choice=='server'){if(await showServerProfileEditor(context))AgentBridge.notifyVaultChanged();}
  if(choice=='recovery'){if(await showRecoveryCodesEditor(context))AgentBridge.notifyVaultChanged();}
  if(choice=='note'){if(await showNoteEditor(context))AgentBridge.notifyVaultChanged();}
}

Future<bool> showNoteEditor(BuildContext context) async {
  final title = TextEditingController(), text = TextEditingController();
  ModalRoute<bool>? route;
  var closing = false, confirmingDiscard = false, saving = false;
  var error = '';
  Future<void> cancel(BuildContext ctx) async {
    if (closing || confirmingDiscard || saving) return;
    confirmingDiscard = true;
    try {
      if ((title.text.isNotEmpty || text.text.isNotEmpty) && !await confirmDiscardChanges(ctx)) return;
      if (ctx.mounted) { closing = true; Navigator.pop(ctx, false); }
    } finally { confirmingDiscard = false; }
  }
  Future<void> save(BuildContext ctx, StateSetter setLocal) async {
    if (closing || saving) return;
    if (title.text.trim().isEmpty) { setLocal(() => error = tr('vaultTools.save.text.item12')); return; }
    setLocal(() { saving = true; error = ''; });
    try {
      await vaultAction(ctx, {'action':'note_create','title':title.text,'text':text.text});
      if (ctx.mounted && !closing) { closing = true; Navigator.pop(ctx, true); }
    } catch (e) {
      if (ctx.mounted && !closing) setLocal(() => error = e is AgentException ? e.message : tr('vaultTools.save.message.item3'));
    } finally { if (ctx.mounted && !closing) setLocal(() => saving = false); }
  }
  try {
    final ok = await showDialog<bool>(context: context, builder: (ctx) {
      route = ModalRoute.of<bool>(ctx);
      return PopScope(canPop: false, onPopInvokedWithResult: (didPop, _) { if (!didPop) cancel(ctx); }, child: StatefulBuilder(builder: (ctx, setLocal) => AppEditDialog(
        title: const LText('vaultTools.build.text.item31'),
        content: SizedBox(width: appEditDialogWidth(ctx), child: AbsorbPointer(absorbing: saving, child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: appFormFields([
          AppFieldRow(label: tr('common.title'), child: TextField(controller: title, decoration: InputDecoration())),
          AppFieldRow(label: tr('common.content'), child: TextField(controller: text, minLines: 4, maxLines: 8, decoration: InputDecoration())),
          if (error.isNotEmpty) Text(error, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
        ]))))),
        actions: [
          TextButton(onPressed: saving ? null : () => cancel(ctx), child: const LText('common.cancel')),
          FilledButton(onPressed: saving ? null : () => save(ctx, setLocal), child: LText(saving ? tr('vaultTools.save.text.item13') : tr('groups.showManageGroupsDialog.text.item6'))),
        ],
      )));
    });
    return ok == true;
  } catch (e) { vaultMessage(context,e); return false; }
  finally { await route?.completed; title.dispose(); text.dispose(); }
}

Future<bool> showSshKeyGenerator(BuildContext context, {String? initialGroupId}) async {
  final label = TextEditingController(), comment = TextEditingController(), gitRules = TextEditingController();
  try {
    final groups = await AgentBridge.listCredentialGroups('ssh');
    final keys = await AgentBridge.listSshKeys();
    if (!context.mounted) return false;
    label.text = 'Key ${keys.length + 1}';
    final initialLabel = label.text;
    var groupId = groups.any((g) => g['id'] == initialGroupId) ? initialGroupId : null;
    final originalGroup = groupId;
    var setDefault = keys.isEmpty, busy = false, closing = false;
    var signPolicy = '';
    final originalDefault = setDefault;
    String error = '';
    return await showDraftDialog<bool>(context: context,
      hasChanges: () => label.text != initialLabel || comment.text.isNotEmpty || gitRules.text.isNotEmpty || signPolicy.isNotEmpty || groupId != originalGroup || setDefault != originalDefault,
      isBusy: () => busy,
      builder: (ctx) => StatefulBuilder(builder: (ctx, update) => AlertDialog(
        title: const LText('vaultTools.showNewCredentialMenu.text'),
        content: SizedBox(width: appEditDialogWidth(ctx), child: AbsorbPointer(absorbing: busy, child: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: appFormFields([
            AppFieldRow(label: tr('common.name'), child: TextField(controller: label, autofocus: true, maxLength: 80,
              decoration: InputDecoration(hintText: tr('ssh.create.nameHint')))),
            AppFieldRow(label: tr('ssh.create.algorithm'), help: tr('ssh.create.algorithmHelp'), child: const Text('Ed25519')),
            AppFieldRow(label: tr('ssh.create.comment'), help: tr('ssh.create.commentHelp'), child: TextField(controller: comment, maxLength: 256,
              decoration: InputDecoration(hintText: tr('ssh.create.commentHint')))),
            AppFieldRow(label: tr('common.group'), child: DropdownButtonFormField<String>(isExpanded: true, value: groupId,
              decoration: InputDecoration(),
              items: [const DropdownMenuItem(value: null, child: LText('common.ungroupedOption')),
                for (final group in groups) DropdownMenuItem(value: group['id'] as String, child: Text(credentialGroupLabel(group), overflow: TextOverflow.ellipsis))],
              onChanged: (value) => update(() => groupId = value))),
            AppFieldRow(label: tr('vaultTools.build.text.item17'), help: tr('ssh.create.policyHelp'), child: DropdownButtonFormField<String>(
              isExpanded: true, value: signPolicy,
              items: const [DropdownMenuItem(value: '', child: LText('vaultTools.build.text.item18')),
                DropdownMenuItem(value: 'session', child: LText('settings.build.text.item19')),
                DropdownMenuItem(value: 'confirm', child: LText('settings.build.text.item20')),
                DropdownMenuItem(value: 'biometric', child: LText('settings.build.text.item21'))],
              onChanged: (value) => update(() => signPolicy = value ?? ''))),
            CheckboxListTile(value: setDefault, title: const LText('vaultTools.showSshKeyGenerator.text'), contentPadding: EdgeInsets.zero,
              subtitle: const LText('ssh.create.defaultHelp'),
              onChanged: (value) => update(() => setDefault = value ?? false)),
            const LText('ssh.create.storageHelp'),
            SshGitRulesField(controller: gitRules, enabled: !busy),
            if (error.isNotEmpty) LText(error, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
          ]))))),
        actions: [
          TextButton(onPressed: busy ? null : () => Navigator.maybePop(ctx), child: const LText('common.cancel')),
          FilledButton(onPressed: busy ? null : () async {
            if (label.text.trim().isEmpty) { update(() => error = tr('vaultTools.showSshKeyGenerator.text.item2')); return; }
            update(() { busy = true; error = ''; });
            try {
              if (!await confirmVaultAction(ctx, tr('vaultTools.showSshKeyGenerator.text.item3'), tr('vaultTools.showSshKeyGenerator.text.item4'))) return;
              if (!ctx.mounted) return;
              await AgentBridge.generateSshKey(label: label.text.trim(), setDefault: setDefault, groupId: groupId,
                comment: comment.text.trim(), signPolicy: signPolicy, gitRules: sshGitRules(gitRules));
              AgentBridge.notifyVaultChanged();
              if (ctx.mounted) { closing = true; Navigator.pop(ctx, true); }
            } catch (e) { if (ctx.mounted) update(() => error = e is AgentException ? e.message : tr('vaultTools.showSshKeyGenerator.message')); }
            finally { if (ctx.mounted && !closing) update(() => busy = false); }
          }, child: LText(busy ? tr('vaultTools.showSshKeyGenerator.text.item5') : tr('common.generate'))),
        ],
      ))) == true;
  } catch (e) { vaultMessage(context,e); return false; }
  finally { label.dispose(); comment.dispose(); gitRules.dispose(); }
}

Future<bool> showRecoveryCodesEditor(BuildContext context) async {
  final service = TextEditingController(), codes = TextEditingController();
  var busy = false, closing = false;
  var error = '';
  try {
    return await showDraftDialog<bool>(context: context,
      hasChanges: () => service.text.isNotEmpty || codes.text.isNotEmpty, isBusy: () => busy,
      builder: (ctx) => StatefulBuilder(builder: (ctx, update) => AppEditDialog(
        title: const LText('vaultTools.showRecoveryCodesEditor.text'),
        content: SizedBox(width: appEditDialogWidth(ctx), child: AbsorbPointer(absorbing: busy, child: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: appFormFields([
            AppFieldRow(label: tr('credentials.build.text.item40'), child: TextField(controller: service, decoration: InputDecoration())),
            AppFieldRow(label: tr('credentials.recovery.title'), help: tr('credentials.build.text.item42'), child: TextField(controller: codes, minLines: 3, maxLines: 8,
              decoration: InputDecoration())),
            if (error.isNotEmpty) LText(error, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
          ]))))),
        actions: [
          TextButton(onPressed: busy ? null : () => Navigator.maybePop(ctx), child: const LText('common.cancel')),
          FilledButton(onPressed: busy ? null : () async {
            final values = codes.text.split(RegExp(r'[\s,;]+')).where((v) => v.isNotEmpty).toList();
            if (service.text.trim().isEmpty || values.isEmpty) { update(() => error = tr('credentials.addRecoveryCodes.text')); return; }
            update(() { busy = true; error = ''; });
            try {
              await AgentBridge.createRecoveryCodes(service.text.trim(), values);
              if (ctx.mounted) { closing = true; Navigator.pop(ctx, true); }
            } catch (e) { if (ctx.mounted) update(() => error = e is AgentException ? e.message : tr('common.saveFailed')); }
            finally { if (ctx.mounted && !closing) update(() => busy = false); }
          }, child: LText(busy ? tr('common.saving') : tr('common.save'))),
        ],
      ))) == true;
  } catch (e) { vaultMessage(context,e); return false; }
  finally { service.dispose(); codes.dispose(); }
}

class CredentialSecurityReport extends StatefulWidget {
  const CredentialSecurityReport({super.key});
  @override
  State<CredentialSecurityReport> createState() => _CredentialSecurityReportState();
}

class _CredentialSecurityReportState extends State<CredentialSecurityReport> {
  static const labels = {'all':'common.all','weak':'vaultTools.build.text.item39','reused':'vaultTools.build.text.item40','reminder_due':'vaultTools.showRecoveryCodesEditor.text.item2',
    'activation_unknown':'vaultTools.build.text.item41','mfa_unknown':'vaultTools.build.text.item44','mfa_disabled':'vaultTools.build.text.item43','unused':'vaultTools.showRecoveryCodesEditor.text.item3'};
  List<Map<String, dynamic>> rows = [];
  String filter = 'all', error = '';
  bool loading = false;
  int generation = 0;
  @override
  void initState() { super.initState(); AgentBridge.vaultChanges.addListener(load); load(); }
  @override
  void dispose() { AgentBridge.vaultChanges.removeListener(load); super.dispose(); }
  Future<void> load() async {
    final version = ++generation;
    if (!mounted) return;
    setState(() { loading = true; error = ''; });
    try {
      final result = await AgentBridge.manage({'action':'security_report'});
      if (mounted && version == generation) setState(() => rows =
        (result['items'] as List).map((v) => Map<String,dynamic>.from(v as Map)).toList());
    } catch (e) { if (mounted && version == generation) setState(() => error = e is AgentException ? e.message : tr('vaultTools.load.message')); }
    finally { if (mounted && version == generation) setState(() => loading = false); }
  }
  @override
  Widget build(BuildContext context) => AppPanel(title: tr('vaultTools.build.title'), icon: Icons.security_outlined,
    subtitle: tr('vaultTools.build.description.item2'),
    trailing: IconButton(onPressed: loading ? null : load, tooltip: tr('vaultTools.build.text.item67'), icon: const Icon(Icons.refresh_rounded)),
    child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Wrap(spacing: 8, runSpacing: 8, children: [for (final entry in labels.entries)
        ChoiceChip(label: Row(mainAxisSize: MainAxisSize.min, children: [LText(entry.value), Text(' · ${entry.key == 'all' ? rows.length : rows.where((row) => (row['reasons'] as List).contains(entry.key)).length}')]),
          selected: filter == entry.key, onSelected: (_) => setState(() => filter = entry.key))]),
      const SizedBox(height: 12),
      if (loading) const LinearProgressIndicator(),
      if (error.isNotEmpty) AppNotice(error),
      if (!loading && error.isEmpty && rows.where((row) => filter == 'all' || (row['reasons'] as List).contains(filter)).isEmpty)
        const LText('vaultTools.build.text.item68'),
      ConstrainedBox(constraints: const BoxConstraints(maxHeight: 360), child: ListView(shrinkWrap: true, children: [
        for (final row in rows.where((row) => filter == 'all' || (row['reasons'] as List).contains(filter))) ListTile(
          contentPadding: EdgeInsets.zero, title: Text(row['title']?.toString() ?? ''),
          subtitle: LText((row['reasons'] as List).map((value) => tr(labels[value] ?? value.toString())).join(' · ')),
          onTap: () => openCredentialActions(context,row),
          trailing: PopupMenuButton<String>(tooltip: tr('vaultTools.build.text.item47'), onSelected: (action) => openCredentialActions(context,row,action:action),
            itemBuilder: (_) => const [
              PopupMenuItem(value:'edit',child:LText('vaultTools.build.text.item48')),
              PopupMenuItem(value:'history',child:LText('vaultTools.build.text.item4')),
              PopupMenuItem(value:'details',child:LText('vaultTools.build.text.item49')),
            ])),
      ])),
    ]));
}
