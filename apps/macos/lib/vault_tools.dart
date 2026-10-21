import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'agent_bridge.dart';
import 'touch_id_gate.dart';
import 'app_ui.dart';

Future<Map<String, dynamic>> vaultAction(
    BuildContext context, Map<String, dynamic> action,
    {bool confirmed = false}) async {
  final sensitive = !{
    'generate_password',
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
  late final List<Map<String, dynamic>> uris = (details['uris'] as List? ?? [])
      .map((e) => Map<String, dynamic>.from(e as Map))
      .toList();
  late final Set<String> related = (details['related_item_ids'] as List? ?? [])
      .map((e) => e.toString())
      .toSet();
  bool busy = false;
  String message = '';
  @override
  void dispose() {
    for (final c in [title, notes, tags, category, history, reminder]) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> save() async {
    final h = history.text.trim().isEmpty ? null : int.tryParse(history.text);
    final r = reminder.text.trim().isEmpty ? null : int.tryParse(reminder.text);
    if ((history.text.isNotEmpty && (h == null || h < 0 || h > 50)) ||
        (reminder.text.isNotEmpty && (r == null || r < 0 || r > 3650))) {
      setState(() => message = '历史数量 0–50，提醒天数 0–3650；留空继承全局配置');
      return;
    }
    if (!await confirmVaultAction(context, '保存详情？', '保存备注、标签、关联及凭据策略。')) return;
    setState(() => busy = true);
    try {
      await vaultAction(
          context,
          {
            'action': 'item_details_save',
            'item_id': widget.row['item_id'] ?? widget.row['id'],
            'expected_revision': widget.data['current_revision'],
            if (widget.row['kind'] == 'secure_note') 'title': title.text,
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
              'uris': uris,
            }
          },
          confirmed: true);
      if (mounted) Navigator.pop(context);
    } catch (e) {
      if (mounted)
        setState(() => message = e is AgentException ? e.message : '保存失败');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
          title: LText(
              '详情 · ${widget.row['title'] ?? widget.row['display_name'] ?? ''}'),
          content: SizedBox(
              width: 620,
              height: 470,
              child: SingleChildScrollView(
                  child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
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
                    const SizedBox(height: 12),
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
                        decoration: InputDecoration(labelText: tr('MFA 状态')),
                        items: const [
                          DropdownMenuItem(
                              value: 'unknown', child: LText('未知')),
                          DropdownMenuItem(
                              value: 'enabled', child: LText('已开启')),
                          DropdownMenuItem(
                              value: 'disabled', child: LText('未开启'))
                        ],
                        onChanged: (v) => details['mfa_state'] = v),
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
                    LText('网站匹配',
                        style: Theme.of(context).textTheme.titleMedium),
                    for (final uri in uris)
                      Row(key: ObjectKey(uri), children: [
                        Expanded(
                            child: TextFormField(
                                initialValue: uri['uri']?.toString() ?? '',
                                decoration:
                                    const InputDecoration(labelText: 'URI'),
                                onChanged: (v) => uri['uri'] = v)),
                        const SizedBox(width: 8),
                        DropdownButton<String>(
                            value:
                                uri['match_mode']?.toString() ?? 'exact_origin',
                            items: {
                              'exact_origin',
                              'never',
                              uri['match_mode']?.toString() ?? 'exact_origin'
                            }
                                .map((m) => DropdownMenuItem(
                                    value: m,
                                    child: LText(m == 'exact_origin'
                                        ? '精确来源'
                                        : m == 'never'
                                            ? '不匹配'
                                            : m)))
                                .toList(),
                            onChanged: (v) =>
                                setState(() => uri['match_mode'] = v)),
                        IconButton(
                            onPressed: () => setState(() => uris.remove(uri)),
                            icon: const Icon(Icons.close))
                      ]),
                    TextButton(
                        onPressed: () => setState(() => uris.add(
                            {'uri': 'https://', 'match_mode': 'exact_origin'})),
                        child: const LText('添加网站')),
                    const SizedBox(height: 12),
                    const LText('关联凭据（可多选）'),
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
                  ]))),
          actions: [
            TextButton(
                onPressed: busy ? null : () => Navigator.pop(context),
                child: const LText('取消')),
            FilledButton(
                onPressed: busy ? null : save, child: const LText('保存'))
          ]);
}

class VaultToolsPanel extends StatefulWidget {
  const VaultToolsPanel({super.key});
  @override
  State<VaultToolsPanel> createState() => _VaultToolsPanelState();
}

class _VaultToolsPanelState extends State<VaultToolsPanel> {
  String mode = 'items', query = '', message = '';
  bool busy = false, favorites = false;
  List<Map<String, dynamic>> items = [];
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) load();
    });
  }

  Future<void> load() async {
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
      if (mounted)
        setState(() {
          items = (result['items'] as List? ?? [])
              .map((v) => Map<String, dynamic>.from(v as Map))
              .toList();
          message =
              mode == 'security' ? result['weak_rule']?.toString() ?? '' : '';
        });
    } catch (e) {
      vaultMessage(context, e);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> note() async {
    final title = TextEditingController();
    final text = TextEditingController();
    final ok = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
                title: const LText('新建安全笔记'),
                content: SizedBox(
                    width: 440,
                    child: Column(mainAxisSize: MainAxisSize.min, children: [
                      TextField(
                          controller: title,
                          decoration: InputDecoration(labelText: tr('标题'))),
                      TextField(
                          controller: text,
                          minLines: 4,
                          maxLines: 8,
                          decoration: InputDecoration(labelText: tr('内容')))
                    ])),
                actions: [
                  TextButton(
                      onPressed: () => Navigator.pop(ctx, false),
                      child: const LText('取消')),
                  FilledButton(
                      onPressed: () => Navigator.pop(ctx, true),
                      child: const LText('创建'))
                ]));
    if (ok == true && mounted) {
      try {
        await vaultAction(context,
            {'action': 'note_create', 'title': title.text, 'text': text.text});
        await load();
      } catch (e) {
        vaultMessage(context, e);
      }
    }
    title.dispose();
    text.dispose();
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
          OutlinedButton.icon(
              onPressed: busy ? null : load,
              icon: const Icon(Icons.refresh),
              label: const LText('加载 / 刷新')),
          FilledButton.icon(
              onPressed: busy ? null : note,
              icon: const Icon(Icons.note_add_outlined),
              label: const LText('新建安全笔记'))
        ]),
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
                            await editItemDetails(context, row);
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
                  width: 460,
                  child: Column(mainAxisSize: MainAxisSize.min, children: [
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
                  ])),
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
                    width: 460,
                    child: Column(mainAxisSize: MainAxisSize.min, children: [
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
                    ])),
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
  final issuer = TextEditingController(text: row['issuer']?.toString() ?? ''),
      account = TextEditingController(text: row['account']?.toString() ?? ''),
      secret = TextEditingController();
  try {
    if (!await requireTouchId(context, reason: '编辑 MFA')) return;
    final reveal = await AgentBridge.totpReveal(row['id'].toString());
    secret.text = reveal['otpauth_uri']?.toString() ?? '';
    if (!context.mounted) return;
    final ok = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
                title: const LText('编辑 MFA / TOTP'),
                content: SizedBox(
                    width: 540,
                    child: Column(mainAxisSize: MainAxisSize.min, children: [
                      TextField(
                          controller: issuer,
                          decoration: InputDecoration(labelText: tr('发行方'))),
                      TextField(
                          controller: account,
                          decoration: InputDecoration(labelText: tr('账号'))),
                      TextField(
                          controller: secret,
                          obscureText: true,
                          decoration: InputDecoration(
                              labelText: 'otpauth URI / Base32',
                              helperText: tr(
                                  '完整 URI 可指定 algorithm、digits、period；Base32 默认 SHA1 / 6 / 30s')))
                    ])),
                actions: [
                  TextButton(
                      onPressed: () => Navigator.pop(ctx, false),
                      child: const LText('取消')),
                  FilledButton(
                      onPressed: () => Navigator.pop(ctx, true),
                      child: const LText('确认保存'))
                ]));
    if (ok == true && context.mounted)
      await vaultAction(
          context,
          {
            'action': 'totp_update',
            'id': row['id'],
            'expected_revision': row['current_revision'],
            'issuer': issuer.text,
            'account': account.text,
            'secret': secret.text
          },
          confirmed: true);
  } catch (e) {
    vaultMessage(context, e);
  } finally {
    issuer.dispose();
    account.dispose();
    secret.dispose();
  }
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
              width: 480,
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
