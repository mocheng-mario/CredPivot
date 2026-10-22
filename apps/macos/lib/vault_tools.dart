import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'agent_bridge.dart';
import 'touch_id_gate.dart';
import 'app_ui.dart';
import 'totp_editor.dart';
import 'credentials_page.dart' show showLoginEditor;
import 'credential_confirm.dart';

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
      !await requireTouchId(context, reason: '管理保险库凭据', confirmed: confirmed))
    throw AgentException('cancelled', '已取消');
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
                  child: const LText('取消')),
              FilledButton(
                  onPressed: () => Navigator.pop(ctx, true),
                  child: const LText('确认')),
            ])) ==
    true;
void vaultMessage(BuildContext context, Object error) {
  if (!context.mounted) return;
  final text = error is AgentException
      ? (error.code == 'cancelled' ? '已取消' : error.message)
      : '操作失败，请重试';
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
}

String vaultDate(dynamic ms) => ms is num && ms > 0
    ? DateTime.fromMillisecondsSinceEpoch(ms.toInt())
        .toLocal()
        .toString()
        .split('.')
        .first
    : '未知';

/// 0 为未知；选择日期时记录当地零点，未修改则保留原来的完整时间。
class PasswordActiveDateField extends StatelessWidget {
  const PasswordActiveDateField({super.key, required this.value, required this.onChanged, this.enabled = true});
  final int value;
  final ValueChanged<int> onChanged;
  final bool enabled;

  @override
  Widget build(BuildContext context) => InputDecorator(
    decoration: InputDecoration(labelText: tr('当前密码启用日期'), helperText: tr('用于密码年龄与改密提醒，不会修改密码'), helperMaxLines: 2),
    child: Row(children: [
      Expanded(child: Text(value > 0 ? vaultDate(value) : tr('未知'))),
      TextButton(onPressed: !enabled ? null : () async {
        final now = DateTime.now();
        final current = value > 0 ? DateTime.fromMillisecondsSinceEpoch(value) : now;
        final first = DateTime(1970, 1, 2);
        final date = await showDatePicker(context: context,
          initialDate: current.isBefore(first) || current.isAfter(now) ? now : current,
          firstDate: first, lastDate: now);
        if (context.mounted && date != null) onChanged(date.millisecondsSinceEpoch);
      }, child: const LText('选择日期')),
      TextButton(onPressed: !enabled ? null : () => onChanged(0), child: const LText('未知')),
    ]),
  );
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
      if (await requireTouchId(context, reason: '显示密码') && mounted) {
        setState(() => visible.add(id));
      }
    } catch (e) {
      vaultMessage(context, e);
    }
  }

  Future<void> _operate(
      String action, Map<String, dynamic> version, bool candidate) async {
    final title = action == 'candidate_activate'
        ? '确认已在网站应用此密码？'
        : action == 'history_restore'
            ? '恢复为候选密码？'
            : '丢弃候选密码？';
    if (!await confirmVaultAction(
        context,
        title,
        action == 'candidate_activate'
            ? '启用后将用于浏览器填充和 SSH 密码登录。请先在目标网站或系统完成改密。'
            : action == 'history_restore'
                ? '历史恢复只创建候选，不会直接替换当前密码。'
                : '丢弃后将移除这条候选，当前已启用的密码不受影响。')) return;
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
        const Padding(padding: EdgeInsets.all(12), child: LText('暂无记录')),
      for (final v in values)
        Card(
            child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      LText(candidate
                          ? '创建：${vaultDate(v['created_at_ms'])}'
                          : '启用：${vaultDate(v['activated_at_ms'])} · 退役：${vaultDate(v['retired_at_ms'])}'),
                      if (candidate &&
                          v['base_active_revision'] !=
                              data['active_password_revision'])
                        const LText('候选基于旧密码版本，请重新创建后再启用'),
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
                            child: const LText('显示 / 隐藏')),
                        TextButton(
                            onPressed: busy
                                ? null
                                : () async {
                                    try {
                                      if (await requireTouchId(context,
                                          reason: '复制密码'))
                                        await AgentBridge.copyConcealed(
                                            v['secret'].toString());
                                    } catch (e) {
                                      vaultMessage(context, e);
                                    }
                                  },
                            child: const LText('复制')),
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
                            child: LText(candidate ? '已在网站应用，启用' : '恢复为候选')),
                        if (candidate)
                          TextButton(
                              onPressed: busy
                                  ? null
                                  : () => _operate('candidate_discard',
                                      Map<String, dynamic>.from(v), true),
                              child: const LText('丢弃')),
                      ])
                    ]))),
    ]);
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
          title: const LText('密码候选与历史'),
          content: SizedBox(
              width: 620,
              height: 440,
              child: SingleChildScrollView(
                  child: Column(children: [
                const LText('候选仅在确认已应用后启用。历史记录数量可在设置或单条凭据中调整。'),
                const SizedBox(height: 16),
                _versions('待启用候选', 'candidates', true),
                const SizedBox(height: 16),
                _versions('历史密码', 'history', false),
              ]))),
          actions: [
            TextButton(
                onPressed: busy ? null : () => Navigator.pop(context),
                child: const LText('关闭'))
          ]);
}

Future<void> editItemDetails(
    BuildContext context, Map<String, dynamic> row) async {
  try {
    final result = await vaultAction(context,
        {'action': 'item_details', 'item_id': row['item_id'] ?? row['id']});
    final all =
        await vaultAction(context, {'action': 'item_search', 'query': ''});
    if (!context.mounted) return;
    await showDialog<void>(
        context: context,
        barrierDismissible: false,
        builder: (_) => _ItemDetailsDialog(
            row: row, data: result, all: (all['items'] as List).cast<Map>()));
  } catch (e) {
    vaultMessage(context, e);
  }
}

class _ItemDetailsDialog extends StatefulWidget {
  const _ItemDetailsDialog(
      {required this.row, required this.data, required this.all});
  final Map<String, dynamic> row, data;
  final List<Map> all;
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
  late int activeSince = (widget.data['password_active_since_ms'] as num?)?.toInt() ?? 0;
  late final Set<String> related = (details['related_item_ids'] as List? ?? [])
      .map((e) => e.toString())
      .toSet();
  bool busy = false;
  String message = '';
  bool closing = false, confirmingDiscard = false;
  late final String initialSnapshot;
  String snapshot() => jsonEncode([title.text,notes.text,tags.text,category.text,history.text,reminder.text,fields,related.toList()..sort(),activeSince,details['favorite'],details['mfa_state'],details['ssh_sign_policy']]);
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
    for (final c in [title, notes, tags, category, history, reminder]) {
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
      setState(() => message = '历史数量 0–50，提醒天数 0–3650；留空继承全局配置');
      return;
    }
    setState(() => busy = true);
    try {
      if (!await confirmVaultAction(context, '保存详细资料？', isLogin ? '保存资料及密码设置；启用日期只描述当前密码，不会替换密码。' : '保存备注、标签和关联资料。')) return;
      if (!mounted) return;
      await vaultAction(
          context,
          {
            'action': 'item_details_save',
            'item_id': widget.row['item_id'] ?? widget.row['id'],
            'expected_revision': widget.data['current_revision'],
            if (widget.row['kind'] == 'secure_note') 'title': title.text,
            if (isLogin) 'password_active_since_ms': activeSince,
            'details': {
              ...details,
              'notes': notes.text,
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
      if (mounted) { closing = true; Navigator.pop(context); }
    } catch (e) {
      if (mounted)
        setState(() => message = e is AgentException ? e.message : '保存失败');
    } finally {
      if (mounted && !closing) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => PopScope(canPop: false, onPopInvokedWithResult: (didPop, _) { if (!didPop) cancel(); }, child: AlertDialog(
          title: LText(
              '详细资料 · ${widget.row['title'] ?? widget.row['display_name'] ?? ''}'),
          content: SizedBox(
              width: appEditDialogWidth(context),
              height: MediaQuery.sizeOf(context).height * .6,
              child: AbsorbPointer(absorbing: busy, child: SingleChildScrollView(
                  child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: appFormFields([
                    LText('基本资料', style: Theme.of(context).textTheme.titleMedium),
                    if (widget.row['kind'] == 'secure_note')
                      TextField(
                          controller: title,
                          decoration: InputDecoration(labelText: tr('标题'))),
                    SwitchListTile(
                        contentPadding: EdgeInsets.zero,
                        title: const LText('收藏'),
                        value: details['favorite'] == true,
                        onChanged: busy
                            ? null
                            : (v) => setState(() => details['favorite'] = v)),
                    TextField(
                        controller: tags,
                        // 身份验证结束后重新建立编辑焦点和原生文本输入连接。
                        autofocus: true,
                        decoration: InputDecoration(labelText: tr('标签（逗号分隔）'))),
                    TextField(
                        controller: category,
                        decoration: InputDecoration(labelText: tr('分类'))),
                    TextField(
                        controller: notes,
                        minLines: 3,
                        maxLines: 8,
                        decoration:
                            InputDecoration(labelText: tr('备注 / 安全笔记'))),
                    const SizedBox(height: 16),
                    LText('自定义字段',
                        style: Theme.of(context).textTheme.titleMedium),
                    for (final f in fields)
                      Row(key: ObjectKey(f), children: [
                        Expanded(
                            child: TextFormField(
                                initialValue: f['name']?.toString() ?? '',
                                decoration:
                                    InputDecoration(labelText: tr('字段名')),
                                onChanged: (v) => f['name'] = v)),
                        const SizedBox(width: 8),
                        Expanded(
                            child: TextFormField(
                                initialValue: f['value']?.toString() ?? '',
                                obscureText: f['secret'] == true,
                                decoration: InputDecoration(labelText: tr('值')),
                                onChanged: (v) => f['value'] = v)),
                        Checkbox(
                            value: f['secret'] == true,
                            onChanged: (v) async {
                              if (v == false &&
                                  !await requireTouchId(context,
                                      reason: '显示隐藏字段')) return;
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
                        label: const LText('添加字段（勾选为隐藏）')),
                    const SizedBox(height: 12),
                    if (widget.row['kind'] == 'ssh_key') DropdownButtonFormField<String>(
                      value: details['ssh_sign_policy']?.toString() ?? '',
                      decoration: InputDecoration(labelText: tr('SSH 签名授权策略')),
                      items: const [DropdownMenuItem(value:'',child:LText('继承本机默认')),DropdownMenuItem(value:'session',child:LText('同一连接限时复用')),DropdownMenuItem(value:'confirm',child:LText('每次签名确认')),DropdownMenuItem(value:'biometric',child:LText('每次确认并重新验证身份'))],
                      onChanged: busy ? null : (v) => setState(() => details['ssh_sign_policy'] = v)),
                    if (isLogin) ...[
                    const Divider(),
                    LText('密码设置', style: Theme.of(context).textTheme.titleMedium),
                    PasswordActiveDateField(value: activeSince, enabled: !busy, onChanged: (v) => setState(() => activeSince = v)),
                    Row(children: [
                      Expanded(
                          child: TextField(
                              controller: history,
                              keyboardType: TextInputType.number,
                              decoration: InputDecoration(
                                  labelText: tr('历史数量'),
                                  helperText: tr('留空继承全局；0 不保存')))),
                      const SizedBox(width: 12),
                      Expanded(
                          child: TextField(
                              controller: reminder,
                              keyboardType: TextInputType.number,
                              decoration: InputDecoration(
                                  labelText: tr('改密提醒（天）'),
                                  helperText: tr('留空继承全局；0 关闭'))))
                    ]),
                    DropdownButtonFormField<String>(
                        value: ['enabled', 'disabled', 'unknown']
                                .contains(details['mfa_state'])
                            ? details['mfa_state'] as String
                            : 'unknown',
                        decoration: InputDecoration(labelText: tr('网站 MFA 状态（手动标注）'), helperText: tr('仅用于安全报告，不会开启网站 MFA 或关联验证器'), helperMaxLines: 2),
                        items: const [
                          DropdownMenuItem(
                              value: 'unknown', child: LText('未知')),
                          DropdownMenuItem(
                              value: 'enabled', child: LText('已开启')),
                          DropdownMenuItem(
                              value: 'disabled', child: LText('未开启'))
                        ],
                        onChanged: busy ? null : (v) => setState(() => details['mfa_state'] = v)),
                    ],
                    const Divider(),
                    LText('关联信息', style: Theme.of(context).textTheme.titleMedium),
                    const LText('仅便于查阅相关凭据，不影响浏览器填充或 MFA 选择。'),
                    if (related.isNotEmpty) Wrap(spacing: 8, runSpacing: 8, children: [
                      for (final item in widget.all.where((v) => related.contains(v['id']))) ActionChip(
                        avatar: const Icon(Icons.open_in_new, size: 16),
                        label: Text(item['title']?.toString() ?? ''),
                        onPressed: busy ? null : () => openCredentialActions(context, Map<String, dynamic>.from(item))),
                    ]),
                    if (widget.all.any((v) => (v['related_item_ids'] as List? ?? []).contains(widget.row['item_id'] ?? widget.row['id']))) ...[
                      const LText('被以下凭据关联'),
                      Wrap(spacing: 8, runSpacing: 8, children: [
                        for (final item in widget.all.where((v) => (v['related_item_ids'] as List? ?? []).contains(widget.row['item_id'] ?? widget.row['id']))) ActionChip(
                          label: Text(item['title']?.toString() ?? ''),
                          onPressed: busy ? null : () => openCredentialActions(context, Map<String, dynamic>.from(item))),
                      ]),
                    ],
                    const LText('选择关联凭据（可多选；关系保持单向）'),
                    for (final stale in related
                        .where(
                            (id) => !widget.all.any((item) => item['id'] == id))
                        .toList())
                      InputChip(
                          label: const LText('已删除的关联'),
                          onDeleted: () =>
                              setState(() => related.remove(stale))),
                    for (final item in widget.all.where((v) =>
                        v['id'] != (widget.row['item_id'] ?? widget.row['id'])))
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
                child: const LText('取消')),
            FilledButton(
                onPressed: busy ? null : save, child: const LText('保存'))
          ]));
}

class VaultToolsPanel extends StatefulWidget {
  const VaultToolsPanel({super.key});
  @override
  State<VaultToolsPanel> createState() => _VaultToolsPanelState();
}

class _VaultToolsPanelState extends State<VaultToolsPanel> {
  String mode = 'items', query = '', message = '';
  int _loadGeneration = 0;
  bool busy = false, favorites = false;
  List<Map<String, dynamic>> items = [];
  void _onVaultChanged() { if (mounted) load(); }

  @override
  void dispose() {
    AgentBridge.vaultChanges.removeListener(_onVaultChanged);
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
    AgentBridge.vaultChanges.addListener(_onVaultChanged);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) load();
    });
  }

  Future<void> load() async {
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
      if (mounted && generation == _loadGeneration)
        setState(() {
          items = (result['items'] as List? ?? [])
              .map((v) => Map<String, dynamic>.from(v as Map))
              .toList();
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
    if (!await confirmVaultAction(
        context,
        purge ? '永久删除？' : '恢复凭据？',
        purge
            ? '当前库中将永久移除此记录，并清除其他凭据对它的引用。操作前会保留恢复点；已有备份不受影响。'
            : '恢复后可在对应凭据页面找到。')) return;
    try {
      await vaultAction(
          context,
          {
            'action': purge ? 'trash_purge' : 'trash_restore',
            'item_id': row['id'],
            'expected_revision': row['current_revision']
          },
          confirmed: true);
      await load();
    } catch (e) {
      vaultMessage(context, e);
    }
  }

  @override
  Widget build(BuildContext context) => Padding(
      padding: const EdgeInsets.all(24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        AppSectionHeader(
          title: '笔记 / 管理',
          subtitle: '查看安全笔记、凭据报告与回收站',
          action: Wrap(spacing: 8, runSpacing: 8, children: [
            OutlinedButton.icon(
                onPressed: busy ? null : load,
                icon: const Icon(Icons.refresh),
                label: const LText('加载 / 刷新')),
            FilledButton.icon(
                onPressed: busy ? null : note,
                icon: const Icon(Icons.note_add_outlined),
                label: const LText('新建安全笔记')),
          ]),
        ),
        Wrap(spacing: 8, runSpacing: 8, children: [
          for (final entry in {
            'items': '全部 / 安全笔记',
            'security': '安全报告',
            'trash': '回收站'
          }.entries)
            ChoiceChip(
                label: LText(entry.value),
                selected: mode == entry.key,
                onSelected: busy
                    ? null
                    : (_) {
                        setState(() => mode = entry.key);
                        load();
                      }),
        ]),
        const SizedBox(height: 12),
        if (mode == 'items')
          Row(children: [
            Expanded(
                child: TextField(
                    decoration:
                        InputDecoration(labelText: tr('搜索标题、账号、标签、备注或非隐藏字段')),
                    onChanged: (v) => query = v,
                    onSubmitted: (_) => load())),
            const SizedBox(width: 12),
            FilterChip(
                label: const LText('仅收藏'),
                selected: favorites,
                onSelected: (v) => setState(() => favorites = v))
          ]),
        if (message.isNotEmpty)
          Padding(padding: const EdgeInsets.all(12), child: Text(message)),
        if (busy) const LinearProgressIndicator(),
        Expanded(
            child: ListView(children: [
          if (items.isEmpty && !busy)
            const Padding(
                padding: EdgeInsets.all(24),
                child: LText('点击加载查看；秘密内容须身份验证后读取。')),
          for (final row in items.where(
              (r) => mode != 'items' || !favorites || r['favorite'] == true))
            Card(
                child: ListTile(
                    title: Text(row['title']?.toString() ?? ''),
                    subtitle: LText(mode == 'trash'
                        ? '${row['kind']} · 删除于 ${vaultDate(row['trashed_at_ms'])}'
                        : mode == 'security'
                            ? (row['reasons'] as List)
                                .map((r) =>
                                    {
                                      'weak': '弱密码',
                                      'reused': '重复密码',
                                      'activation_unknown': '启用时间未知',
                                      'reminder_due': '到期提醒',
                                      'mfa_disabled': 'MFA 未开启',
                                      'unused': '超过 180 天未使用'
                                    }[r] ??
                                    r)
                                .join(' · ')
                            : '${row['kind']} · ${(row['tags'] as List? ?? []).join(' / ')} · 最近使用：${vaultDate(row['last_used_at_ms'])}'),
                    onTap: mode == 'trash'
                        ? null
                        : () async {
                            if (mode == 'security') { await openCredentialActions(context, row); }
                            else { await editItemDetails(context, row); }
                            if (mounted) load();
                          },
                    trailing: mode == 'trash'
                        ? Wrap(children: [
                            TextButton(
                                onPressed:
                                    busy ? null : () => trashChange(row, false),
                                child: const LText('恢复')),
                            TextButton(
                                onPressed:
                                    busy ? null : () => trashChange(row, true),
                                child: const LText('永久删除'))
                          ])
                        : mode == 'security'
                            ? PopupMenuButton<String>(
                                tooltip: tr('处理此项'),
                                onSelected: (action) => openCredentialActions(context, row, action: action),
                                itemBuilder: (_) => const [
                                  PopupMenuItem(value: 'edit', child: LText('修改登录 / MFA 关联')),
                                  PopupMenuItem(value: 'history', child: LText('密码候选与历史')),
                                  PopupMenuItem(value: 'details', child: LText('启用日期与提醒')),
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
                                tooltip: tr('移入回收站'),
                                icon: const Icon(Icons.delete_outline),
                                onPressed: busy
                                    ? null
                                    : () async {
                                        if (!await confirmVaultAction(
                                            context, '移入回收站？', '可从回收站恢复此记录。'))
                                          return;
                                        if (!context.mounted ||
                                            !await requireTouchId(context,
                                                reason: '删除凭据',
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
                          ])))
        ])),
      ]));
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
      if (await requireTouchId(context, reason: '显示恢复码') && mounted) {
        setState(() => visible.add(id));
      }
    } catch (e) {
      vaultMessage(context, e);
    }
  }

  Future<void> use(Map row, bool used) async {
    if (!await confirmVaultAction(
        context, used ? '标记为已使用？' : '恢复为未使用？', '仅在确认实际使用状态后更改；复制不会自动消耗恢复码。'))
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
            '${widget.row['service_name']} · 剩余 ${list.where((v) => v['used_at_ms'] == null).length}/${list.length}'),
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
                                  ? '未使用'
                                  : '已使用 · ${vaultDate(row['used_at_ms'])}'),
                              Wrap(children: [
                                TextButton(
                                    onPressed: busy
                                        ? null
                                        : () =>
                                            toggleVisible(row['id'].toString()),
                                    child: const LText('显示 / 隐藏')),
                                TextButton(
                                    onPressed: busy
                                        ? null
                                        : () async {
                                            try {
                                              if (await requireTouchId(context,
                                                  reason: '复制恢复码')) {
                                                await AgentBridge.copyConcealed(
                                                    row['code'].toString());
                                              }
                                            } catch (e) {
                                              vaultMessage(context, e);
                                            }
                                          },
                                    child: const LText('复制此条')),
                                TextButton(
                                    onPressed: busy
                                        ? null
                                        : () =>
                                            use(row, row['used_at_ms'] == null),
                                    child: LText(row['used_at_ms'] == null
                                        ? '标记已使用'
                                        : '撤销使用标记'))
                              ])
                            ])))
            ])),
        actions: [
          TextButton(
              onPressed: busy ? null : () => Navigator.pop(context),
              child: const LText('关闭'))
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
  final password = TextEditingController(),
      namespace = TextEditingController(text: 'personal');
  final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
              title: const LText('Bitwarden 导入'),
              content: SizedBox(
                  width: appEditDialogWidth(ctx),
                  child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: appFormFields([
                    const LText(
                        '支持普通 JSON 和 Password protected JSON。来源账户名称用于重复导入识别，请保持一致。'),
                    TextField(
                        controller: namespace,
                        decoration: InputDecoration(labelText: tr('来源账户名称'))),
                    TextField(
                        controller: password,
                        obscureText: true,
                        decoration:
                            InputDecoration(labelText: tr('导出密码（普通 JSON 留空）')))
                  ])))),
              actions: [
                TextButton(
                    onPressed: () => Navigator.pop(ctx, false),
                    child: const LText('取消')),
                FilledButton(
                    onPressed: () => Navigator.pop(ctx, true),
                    child: const LText('预览差异'))
              ]));
  try {
    if (ok != true || !context.mounted) return;
    final preview = await vaultAction(context, {
      'action': 'bitwarden_preview',
      'path': path,
      'password': password.text,
      'namespace': namespace.text
    });
    if (!context.mounted) return;
    final list = (preview['items'] as List).cast<Map>();
    final choices = <String, String>{
      for (final item in list)
        item['source_id'].toString(): item['state'] == 'new' ? 'import' : 'skip'
    };
    final apply = await showDialog<bool>(
        context: context,
        builder: (ctx) => StatefulBuilder(
            builder: (ctx, setLocal) => AlertDialog(
                    title: const LText('导入预览'),
                    content: SizedBox(
                        width: 680,
                        height: 440,
                        child: ListView(children: [
                          const LText(
                              '密码启用时间未知；自定义字段、备注、收藏、文件夹、URI、TOTP 及历史将迁入。附件和 Passkey 不迁入。'),
                          for (final item in list)
                            ListTile(
                                title: Text(item['title'].toString()),
                                subtitle: LText('${{
                                  'new': '新增',
                                  'changed': '源数据已变化',
                                  'unchanged': '未变化',
                                  'unsupported': '不支持类型'
                                }[item['state']]}\n变更字段：${(item['changed_fields'] as List? ?? []).join('、')}\n${(item['warnings'] as List).join('\n')}'),
                                trailing: DropdownButton<String>(
                                    value: choices[item['source_id']],
                                    items: [
                                      const DropdownMenuItem(
                                          value: 'skip', child: LText('跳过')),
                                      if (item['state'] == 'new')
                                        const DropdownMenuItem(
                                            value: 'import',
                                            child: LText('导入')),
                                      if (['changed', 'unchanged']
                                          .contains(item['state'])) ...const [
                                        DropdownMenuItem(
                                            value: 'update',
                                            child: LText('更新现有')),
                                        DropdownMenuItem(
                                            value: 'copy', child: LText('保留副本'))
                                      ]
                                    ],
                                    onChanged: (v) => setLocal(() =>
                                        choices[item['source_id'].toString()] =
                                            v ?? 'skip')))
                        ])),
                    actions: [
                      TextButton(
                          onPressed: () => Navigator.pop(ctx, false),
                          child: const LText('取消')),
                      FilledButton(
                          onPressed: () => Navigator.pop(ctx, true),
                          child: const LText('确认导入'))
                    ])));
    if (apply != true || !context.mounted) return;
    final report = await vaultAction(
        context,
        {
          'action': 'bitwarden_import',
          'path': path,
          'password': password.text,
          'namespace': namespace.text,
          'choices': choices,
          'preview_token': preview['preview_token']
        },
        confirmed: true);
    if (!context.mounted) return;
    await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
                title: const LText('导入结果'),
                content: SizedBox(
                    width: 620,
                    height: 400,
                    child: SingleChildScrollView(
                        child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                          LText(
                              '新增 ${report['imported']} · 更新 ${report['updated']} · 副本 ${report['copied']} · 跳过 ${report['skipped']} · 不支持 ${report['skipped_invalid']}'),
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
                      child: const LText('关闭'))
                ]));
  } catch (e) {
    vaultMessage(context, e);
  } finally {
    password.dispose();
    namespace.dispose();
  }
}

Future<void> transferSshKey(BuildContext context, {String? keyId}) async {
  final exporting = keyId != null;
  final label = TextEditingController(), passphrase = TextEditingController();
  String? pem;
  try {
    if (!exporting) {
      final path = await AgentBridge.pickOpenFile();
      if (path == null) return;
      pem = await AgentBridge.readTextFile(path);
    }
    if (!context.mounted) return;
    final ok = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
                title: LText(exporting ? '导出 OpenSSH 私钥' : '导入 Ed25519 私钥'),
                content: SizedBox(
                    width: appEditDialogWidth(ctx),
                    child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: appFormFields([
                      LText(exporting
                          ? '可设置导出密码；留空会导出明文私钥，任何拿到文件的人都可使用。'
                          : '支持 OpenSSH 格式及加密私钥。导入后私钥保存在加密保险库中。'),
                      if (!exporting)
                        TextField(
                            controller: label,
                            decoration: InputDecoration(labelText: tr('名称'))),
                      TextField(
                          controller: passphrase,
                          obscureText: true,
                          decoration: InputDecoration(
                              labelText:
                                  tr(exporting ? '导出密码（建议设置）' : '私钥密码（未加密留空）')))
                    ])))),
                actions: [
                  TextButton(
                      onPressed: () => Navigator.pop(ctx, false),
                      child: const LText('取消')),
                  FilledButton(
                      onPressed: () => Navigator.pop(ctx, true),
                      child: LText(exporting ? '确认导出' : '导入'))
                ]));
    if (ok != true || !context.mounted) return;
    String? output;
    if (exporting) {
      output = await AgentBridge.pickSaveFile('id_ed25519');
      if (output == null || !context.mounted) return;
    }
    final result = await vaultAction(
        context,
        exporting
            ? {
                'action': 'ssh_export',
                'id': keyId,
                'passphrase': passphrase.text
              }
            : {
                'action': 'ssh_import',
                'label': label.text,
                'pem': pem,
                'passphrase': passphrase.text
              },
        confirmed: true);
    if (exporting) {
      await AgentBridge.writeTextFile(output!, result['pem'].toString());
    }
    if (context.mounted)
      ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: LText(exporting ? '已导出：$output' : '密钥已导入')));
  } catch (e) {
    vaultMessage(context, e);
  } finally {
    label.dispose();
    passphrase.dispose();
  }
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
      if (mounted) setState(() => message = '验证已过期，点击刷新后重新验证');
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  Future<void> copy() async {
    try {
      var result = await vaultAction(context,
          {'action': 'totp_status', 'id': widget.id, 'min_valid_seconds': 5});
      final wait = (result['wait_seconds'] as num?)?.toInt();
      if (wait != null) {
        if (mounted) setState(() => message = '验证码即将过期，等待下一周期…');
        await Future<void>.delayed(Duration(seconds: wait + 1));
        if (!mounted) return;
        result = await vaultAction(context,
            {'action': 'totp_status', 'id': widget.id, 'min_valid_seconds': 0});
      }
      final nextCode = result['code']?.toString() ?? '';
      if (mounted && nextCode.isNotEmpty)
        await AgentBridge.copyConcealed(nextCode);
    } catch (e) {
      vaultMessage(context, e);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
          title: const LText('动态验证码'),
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
                LText('剩余 $remaining 秒'),
                if (message.isNotEmpty) Text(message)
              ])),
          actions: [
            TextButton(
                onPressed: loading ? null : () => refresh(true),
                child: const LText('刷新')),
            TextButton(
                onPressed: loading ? null : copy, child: const LText('复制')),
            TextButton(
                onPressed: () => Navigator.pop(context),
                child: const LText('关闭'))
          ]);
}

Future<void> copyTotpCode(BuildContext context, String id) async {
  try {
    var result = await vaultAction(
        context, {'action': 'totp_status', 'id': id, 'min_valid_seconds': 5});
    final wait = (result['wait_seconds'] as num?)?.toInt();
    if (wait != null) {
      if (context.mounted)
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: LText('验证码即将过期，等待下一周期…')));
      await Future<void>.delayed(Duration(seconds: wait + 1));
      if (!context.mounted) return;
      result = await vaultAction(
          context, {'action': 'totp_status', 'id': id, 'min_valid_seconds': 0});
    }
    final code = result['code']?.toString() ?? '';
    if (code.isNotEmpty && context.mounted) {
      await AgentBridge.copyConcealed(code);
      if (context.mounted)
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: LText('验证码已复制')));
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
  Widget build(BuildContext context) => AlertDialog(
          title: const LText('密码生成器'),
          content: SizedBox(
              width: appEditDialogWidth(context),
              child: Column(mainAxisSize: MainAxisSize.min, children: [
                LText('长度：$length'),
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
                SwitchListTile(
                    title: const LText('包含符号'),
                    value: symbols,
                    onChanged: busy
                        ? null
                        : (v) => setState(() {
                              symbols = v;
                              password = '';
                            })),
                SwitchListTile(
                    title: const LText('排除易混淆字符'),
                    value: excludeAmbiguous,
                    onChanged: busy
                        ? null
                        : (v) => setState(() {
                              excludeAmbiguous = v;
                              password = '';
                            })),
                if (password.isNotEmpty)
                  SelectableText(password,
                      style: const TextStyle(fontFamily: 'monospace')),
                const SizedBox(height: 12),
                FilledButton(
                    onPressed: busy ? null : generate,
                    child: const LText('生成密码'))
              ])),
          actions: [
            TextButton(
                onPressed: busy ? null : () => Navigator.pop(context),
                child: const LText('取消')),
            TextButton(
                onPressed: password.isEmpty || busy
                    ? null
                    : () async {
                        if (await requireTouchId(context, reason: '复制生成的密码'))
                          await AgentBridge.copyConcealed(password);
                      },
                child: const LText('复制')),
            FilledButton(
                onPressed: password.isEmpty || busy
                    ? null
                    : () => Navigator.pop(context, password),
                child: const LText('使用此密码'))
          ]);
}

Future<void> copySelectedCredential(BuildContext context, Map<String, dynamic> row) async {
  try {
    final kind = row['kind'];
    if (kind == 'totp') { await copyTotpCode(context, row['id'].toString()); return; }
    if (kind == 'ssh_key') { await AgentBridge.copyConcealed(row['public_openssh']?.toString() ?? ''); return; }
    if (kind != 'login') return;
    if (!await requireTouchId(context, reason: '复制当前登录密码')) return;
    final detail = await AgentBridge.getCredential(row['id'].toString());
    await AgentBridge.copyConcealed(detail['password']?.toString() ?? '');
    if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('已复制，将按设置清除剪贴板')));
  } catch (e) { vaultMessage(context, e); }
}

Future<void> openCredentialActions(BuildContext context, Map<String, dynamic> item, {String? action}) async {
  try {
    final result = await AgentBridge.manage({'action':'item_search','query':''});
    final itemId = item['item_id'] ?? item['id'];
    final matches = (result['items'] as List).cast<Map>().where((v) => v['id'] == itemId);
    if (matches.isEmpty) throw AgentException('not_found','凭据已不存在，请刷新');
    final meta = Map<String, dynamic>.from(matches.first);
    final kind = meta['kind'];
    Map<String, dynamic> current = meta;
    if (kind == 'login') {
      final rows = await AgentBridge.listCredentials();
      current = rows.firstWhere((v) => v['item_id'] == itemId);
    } else if (kind == 'totp') {
      current = (await AgentBridge.listTotp()).firstWhere((v) => v['item_id'] == itemId);
    } else if (kind == 'ssh_key') {
      current = (await AgentBridge.listSshKeys()).firstWhere((v) => v['item_id'] == itemId);
    } else if (kind == 'recovery_codes') {
      current = (await AgentBridge.listRecoveryCodes()).firstWhere((v) => v['item_id'] == itemId);
    } else if (kind == 'server_login') {
      current = (await AgentBridge.listServerProfiles()).firstWhere((v) => v['item_id'] == itemId);
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
          Padding(padding: const EdgeInsets.fromLTRB(24, 0, 24, 12), child: SelectableText('${current['origin']}\n${current['username']}')),
          SimpleDialogOption(onPressed: () => openCredentialActions(ctx,meta,action:'edit'), child: const LText('编辑登录密码与 MFA 关联')),
          SimpleDialogOption(onPressed: () => openCredentialActions(ctx,meta,action:'history'), child: const LText('密码候选与历史')),
          SimpleDialogOption(onPressed: () => copySelectedCredential(ctx,{...current,'kind':'login'}), child: const LText('复制当前密码')),
        ],
        if (kind == 'totp') ...[
          SimpleDialogOption(onPressed: () => openCredentialActions(ctx,meta,action:'edit'), child: const LText('编辑 MFA 与适用网站')),
          SimpleDialogOption(onPressed: () => showTotpStatus(ctx,current['id'].toString()), child: const LText('查看动态验证码')),
          SimpleDialogOption(onPressed: () => copyTotpCode(ctx,current['id'].toString()), child: const LText('复制验证码')),
        ],
        if (kind == 'ssh_key') Padding(padding: const EdgeInsets.symmetric(horizontal:24), child: SelectableText(current['public_openssh']?.toString() ?? '')),
        if (kind == 'server_login') Padding(padding: const EdgeInsets.symmetric(horizontal:24), child: SelectableText('${current['host']}:${current['port']}\n${current['manual_username'] ?? ''}')),
        if (kind == 'recovery_codes') SimpleDialogOption(onPressed: () => manageRecoveryEntries(ctx,current), child: const LText('管理恢复码')),
        SimpleDialogOption(onPressed: () async { await editItemDetails(ctx,{...meta,...current,'item_id':itemId,'kind':kind}); AgentBridge.notifyVaultChanged(); }, child: const LText('详细资料与关联凭据')),
        SimpleDialogOption(onPressed: () => Navigator.pop(ctx), child: const LText('关闭')),
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
      final result = await AgentBridge.manage({'action':'item_search','query':query.text.trim()});
      if (mounted && version == generation) setState(() => rows = (result['items'] as List).map((v) => Map<String,dynamic>.from(v as Map)).toList());
    } catch (e) { if (mounted && version == generation) setState(() => error = e is AgentException ? e.message : '搜索失败'); }
    finally { if (mounted && version == generation) setState(() => loading=false); }
  }
  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const LText('搜索全部凭据'),
    content: SizedBox(width:appEditDialogWidth(context),height:400,child:Column(children:[
      TextField(controller:query,autofocus:true,decoration:InputDecoration(hintText:tr('搜索名称、网站、账号、标签或备注')),
        onChanged:(_){generation++;debounce?.cancel();debounce=Timer(const Duration(milliseconds:250),search);},onSubmitted:(_)=>search()),
      if(loading) const LinearProgressIndicator(),
      if(error.isNotEmpty) AppNotice(error),
      Expanded(child:ListView(children:[for(final row in rows.take(100)) ListTile(title:Text(row['title']?.toString()??''),subtitle:Text(row['kind'].toString()),onTap:()=>openCredentialActions(context,row)),
        if(rows.length>100) const ListTile(title:LText('结果较多，请细化搜索条件'))])),
    ])),
    actions:[TextButton(onPressed:()=>Navigator.pop(context),child:const LText('关闭'))],
  );
}

Future<void> showNewCredentialMenu(BuildContext context) async {
  ModalRoute<String>? route;
  final choice = await showDialog<String>(context:context,builder:(ctx) {
    route = ModalRoute.of<String>(ctx);
    return SimpleDialog(title:const LText('新建记录'),children:[
    SimpleDialogOption(onPressed:()=>Navigator.pop(ctx,'login'),child:const LText('登录密码')),
    SimpleDialogOption(onPressed:()=>Navigator.pop(ctx,'totp'),child:const LText('MFA / TOTP')),
    SimpleDialogOption(onPressed:()=>Navigator.pop(ctx,'ssh'),child:const LText('导入 SSH 密钥')),
    SimpleDialogOption(onPressed:()=>Navigator.pop(ctx,'note'),child:const LText('安全笔记')),
  ]);
  });
  await route?.completed;
  if(!context.mounted)return;
  if(choice=='login'){if(await showLoginEditor(context))AgentBridge.notifyVaultChanged();}
  if(choice=='totp'){if(await showTotpEditor(context))AgentBridge.notifyVaultChanged();}
  if(choice=='ssh'){await transferSshKey(context);AgentBridge.notifyVaultChanged();}
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
    if (title.text.trim().isEmpty) { setLocal(() => error = '请输入标题'); return; }
    setLocal(() { saving = true; error = ''; });
    try {
      await vaultAction(ctx, {'action':'note_create','title':title.text,'text':text.text});
      if (ctx.mounted && !closing) { closing = true; Navigator.pop(ctx, true); }
    } catch (e) {
      if (ctx.mounted && !closing) setLocal(() => error = e is AgentException ? e.message : '创建失败，请重试');
    } finally { if (ctx.mounted && !closing) setLocal(() => saving = false); }
  }
  try {
    final ok = await showDialog<bool>(context: context, builder: (ctx) {
      route = ModalRoute.of<bool>(ctx);
      return PopScope(canPop: false, onPopInvokedWithResult: (didPop, _) { if (!didPop) cancel(ctx); }, child: StatefulBuilder(builder: (ctx, setLocal) => AlertDialog(
        title: const LText('新建安全笔记'),
        content: SizedBox(width: appEditDialogWidth(ctx), child: AbsorbPointer(absorbing: saving, child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: appFormFields([
          TextField(controller: title, decoration: InputDecoration(labelText: tr('标题'))),
          TextField(controller: text, minLines: 4, maxLines: 8, decoration: InputDecoration(labelText: tr('内容'))),
          if (error.isNotEmpty) Text(error, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
        ]))))),
        actions: [
          TextButton(onPressed: saving ? null : () => cancel(ctx), child: const LText('取消')),
          FilledButton(onPressed: saving ? null : () => save(ctx, setLocal), child: LText(saving ? '创建中…' : '创建')),
        ],
      )));
    });
    return ok == true;
  } catch (e) { vaultMessage(context,e); return false; }
  finally { await route?.completed; title.dispose(); text.dispose(); }
}
