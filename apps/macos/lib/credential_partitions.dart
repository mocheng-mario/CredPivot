import 'package:flutter/material.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';
import 'touch_id_gate.dart';

class CredentialPartitions extends ChangeNotifier {
  static final instance = CredentialPartitions();
  List<Map<String, dynamic>> items = [];
  bool _unlocked = false, _started = false;
  int _generation = 0;
  String error = '';
  String get activeName {
    for (final row in items) { if (row['id'] == AgentBridge.activePartitionId) return row['name'].toString(); }
    return tr('partitions.personal');
  }

  void start() {
    if (_started) return;
    _started = true;
    AgentBridge.vaultChanges.addListener(refresh);
  }
  void stop() {
    AgentBridge.vaultChanges.removeListener(refresh);
    _started = false;
    setUnlocked(false);
  }
  void setUnlocked(bool value) {
    if (_unlocked == value) return;
    _unlocked = value; _generation++;
    if (value) { refresh(); } else {
      items = []; error = ''; AgentBridge.activePartitionId = AgentBridge.personalPartitionId;
    }
  }
  Future<void> refresh() async {
    if (!_unlocked) return;
    final generation = ++_generation;
    try {
      final result = await AgentBridge.manage({'action': 'partition_list'});
      if (!_unlocked || generation != _generation) return;
      items = (result['partitions'] as List).map((v) => Map<String, dynamic>.from(v as Map)).toList();
      if (!items.any((p) => p['id'] == AgentBridge.activePartitionId)) AgentBridge.activePartitionId = AgentBridge.personalPartitionId;
      error = '';
    } catch (e) {
      if (generation != _generation) return;
      error = e is AgentException ? e.message : 'common.operationFailed';
    }
    notifyListeners();
  }
}

Future<void> _failure(BuildContext context, Object error) async {
  if (!context.mounted || !CredentialPartitions.instance._unlocked ||
      (error is AgentException && error.code == 'locked')) return;
  final message = error is AgentException ? error.message : 'common.operationFailed';
  await showDialog<void>(context: context, builder: (ctx) => AlertDialog(
    title: const LText('common.operationFailed'), content: LText(message),
    actions: [TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.close'))],
  ));
}

class PartitionManagementPage extends StatefulWidget {
  const PartitionManagementPage({super.key});
  @override
  State<PartitionManagementPage> createState() => _PartitionManagementPageState();
}

class _PartitionManagementPageState extends State<PartitionManagementPage> {
  final store = CredentialPartitions.instance;
  bool busy = false;

  Future<void> edit([Map<String, dynamic>? row]) async {
    final controller = TextEditingController(text: row?['name']?.toString() ?? '');
    var saving = false;
    var error = '';
    try {
      await showDraftDialog<void>(context: context,
        hasChanges: () => controller.text != (row?['name']?.toString() ?? ''), isBusy: () => saving,
        builder: (ctx) => StatefulBuilder(builder: (ctx, update) => AppEditDialog(
          title: LText(row == null ? 'partitions.create' : 'partitions.rename'),
          content: SizedBox(width: appEditDialogWidth(ctx), child: Column(mainAxisSize: MainAxisSize.min, children: [
            AppFieldRow(label: tr('common.name'), child: TextField(controller: controller, autofocus: true, enabled: !saving,
                maxLength: 80, decoration: InputDecoration())),
            if (error.isNotEmpty) LText(error, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
          ])),
          actions: [
            TextButton(onPressed: saving ? null : () => Navigator.maybePop(ctx), child: const LText('common.cancel')),
            FilledButton(onPressed: saving ? null : () async {
              update(() { saving = true; error = ''; });
              try {
                await AgentBridge.manage(row == null
                    ? {'action': 'partition_create', 'name': controller.text.trim()}
                    : {'action': 'partition_rename', 'id': row['id'], 'expected_revision': row['current_revision'], 'name': controller.text.trim()});
                AgentBridge.notifyVaultChanged();
                if (ctx.mounted) Navigator.pop(ctx);
              } catch (e) {
                if (ctx.mounted) update(() { saving = false; error = e is AgentException ? e.message : 'common.operationFailed'; });
              }
            }, child: const LText('common.save')),
          ],
        )));
    } finally { controller.dispose(); }
  }

  Future<void> reorder(int index, int offset) async {
    if (busy) return;
    setState(() => busy = true);
    try {
      final rows = [...store.items];
      final value = rows.removeAt(index); rows.insert(index + offset, value);
      await AgentBridge.manage({'action': 'partition_reorder', 'ids': rows.map((p) => p['id']).toList(),
        'expected': {for (final row in rows) row['id'].toString(): row['current_revision']}});
      AgentBridge.notifyVaultChanged();
    } catch (e) { if (mounted) await _failure(context, e); }
    finally { if (mounted) setState(() => busy = false); }
  }

  Future<void> delete(Map<String, dynamic> row) async {
    if (busy || !await confirmCredentialDanger(context, title: tr('partitions.delete'),
        message: tr('partitions.deleteHelp', args: {'name': row['name']}))) return;
    if (!mounted || !await requireTouchId(context, reason: 'partitions.delete', confirmed: true)) return;
    if (!mounted) return;
    setState(() => busy = true);
    try {
      await AgentBridge.manage({'action': 'partition_delete', 'id': row['id'], 'expected_revision': row['current_revision']});
      AgentBridge.notifyVaultChanged();
    } catch (e) { if (mounted) await _failure(context, e); }
    finally { if (mounted) setState(() => busy = false); }
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(listenable: store, builder: (context, _) => ListView(
    padding: const EdgeInsets.all(24), children: [
      AppSectionHeader(title: tr('partitions.manage'), subtitle: tr('partitions.description'),
        action: FilledButton.icon(onPressed: busy ? null : () => edit(), icon: const Icon(Icons.add), label: const LText('partitions.create'))),
      if (store.error.isNotEmpty) AppNotice(tr(store.error)),
      for (var index = 0; index < store.items.length; index++) ...[
        Card(child: Padding(padding: const EdgeInsets.all(16), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text(store.items[index]['name'].toString(), style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          LText('partitions.counts', args: {'count': store.items[index]['item_count'], 'trash': store.items[index]['trashed_count']}),
          const SizedBox(height: 12),
          Wrap(spacing: 8, runSpacing: 8, children: [
            TextButton(onPressed: busy ? null : () => edit(store.items[index]), child: const LText('partitions.rename')),
            TextButton(onPressed: busy ? null : () => showPartitionMigration(context, store.items[index]['id'].toString()), child: const LText('partitions.move')),
            IconButton(tooltip: tr('partitions.up'), onPressed: busy || index == 0 ? null : () => reorder(index, -1), icon: const Icon(Icons.arrow_upward)),
            IconButton(tooltip: tr('partitions.down'), onPressed: busy || index == store.items.length - 1 ? null : () => reorder(index, 1), icon: const Icon(Icons.arrow_downward)),
            if (store.items[index]['id'] != AgentBridge.personalPartitionId)
              TextButton(onPressed: busy || store.items[index]['item_count'] != 0 || store.items[index]['trashed_count'] != 0
                  ? null : () => delete(store.items[index]), child: const LText('partitions.delete')),
          ]),
        ]))),
      ],
      const SizedBox(height: 12), const LText('partitions.emptyDeleteOnly'),
    ],
  ));
}

Future<void> showPartitionMigration(BuildContext context, String source, {Set<String>? initialSelection}) async {
  try {
    await CredentialPartitions.instance.refresh();
    final destinations = CredentialPartitions.instance.items.where((p) => p['id'] != source).toList();
    if (destinations.isEmpty) throw AgentException('partition', 'partitions.errors.noTarget');
    final results = await Future.wait([
      AgentBridge.manage({'action': 'item_search', 'query': ''}, partitionId: source),
      AgentBridge.manage({'action': 'trash_list'}, partitionId: source),
    ]);
    final groupLists = await Future.wait([for (final destination in destinations)
      AgentBridge.listCredentialGroups('shared', partitionId: destination['id'].toString())]);
    final targetGroups = {for (var i = 0; i < destinations.length; i++) destinations[i]['id'].toString(): groupLists[i]};
    if (!context.mounted) return;
    final items = [for (final result in results) ...(result['items'] as List).map((v) => Map<String, dynamic>.from(v as Map))];
    if (items.isEmpty) throw AgentException('partition', 'partitions.errors.selection');
    var target = destinations.first['id'].toString(), query = '';
    var groupChoice = '', newGroupName = '';
    final selected = (initialSelection ?? <String>{}).intersection(items.map((r) => r['id'].toString()).toSet());
    final proceed = await showDialog<bool>(context: context, builder: (ctx) => StatefulBuilder(builder: (ctx, update) {
      final visible = items.where((r) => '${r['title']} ${r['account'] ?? ''}'.toLowerCase().contains(query.toLowerCase())).toList();
      final visibleIds = visible.map((item) => item['id'].toString()).toSet();
      final selectedVisible = visibleIds.where(selected.contains).length;
      final allVisibleSelected = visibleIds.isNotEmpty && selectedVisible == visibleIds.length;
      return AlertDialog(title: const LText('partitions.move'),
        content: SizedBox(width: appEditDialogWidth(ctx), height: MediaQuery.sizeOf(ctx).height * .55,
          child: CustomScrollView(slivers: [
            SliverToBoxAdapter(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            AppFieldRow(label: tr('partitions.target'), child: DropdownButtonFormField<String>(initialValue: target, isExpanded: true,
              decoration: InputDecoration(),
              items: destinations.map((p) => DropdownMenuItem(value: p['id'].toString(), child: Text(p['name'].toString()))).toList(),
              onChanged: (value) { if (value != null) update(() { target = value; groupChoice = ''; newGroupName = ''; }); })),
            const SizedBox(height: 12),
            AppFieldRow(label: tr('partitions.targetGroup'), help: tr('partitions.targetGroupHelp'),
              child: DropdownButtonFormField<String>(key: ValueKey(target), initialValue: groupChoice, isExpanded: true,
                items: [
                  const DropdownMenuItem(value: '', child: LText('partitions.keepGroups')),
                  for (final group in targetGroups[target]!) DropdownMenuItem(value: group['id'].toString(), child: Text(group['name'].toString())),
                  const DropdownMenuItem(value: '__new__', child: LText('partitions.newSharedGroup')),
                ], onChanged: (value) { if (value != null) update(() { groupChoice = value; newGroupName = ''; }); })),
            if (groupChoice == '__new__') Padding(padding: const EdgeInsets.only(top: 12), child: AppFieldRow(label: tr('partitions.groupName'),
              child: TextField(maxLength: 80, onChanged: (value) => update(() => newGroupName = value),
                decoration: InputDecoration(hintText: tr('partitions.groupNameHint'))))),
            const SizedBox(height: 12),
            AppFieldRow(label: tr('partitions.search'), child: TextField(decoration: InputDecoration(), onChanged: (value) => update(() => query = value))),
            Wrap(spacing: 12, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
              OutlinedButton.icon(
                onPressed: visibleIds.isEmpty ? null : () => update(() {
                  // 仅切换当前搜索结果，保留其他搜索中已经选择的凭据。
                  if (allVisibleSelected) { selected.removeAll(visibleIds); }
                  else { selected.addAll(visibleIds); }
                }),
                icon: Icon(allVisibleSelected ? Icons.deselect : Icons.select_all),
                label: LText(allVisibleSelected ? 'partitions.deselectResults' : 'partitions.selectResults'),
              ),
              LText('partitions.selectionCount', args: {'count': visible.length, 'selected': selected.length}),
            ]),
            if (selected.length > selectedVisible) Padding(
              padding: const EdgeInsets.only(top: 8),
              child: LText('partitions.selectedOutside', args: {'count': selected.length - selectedVisible},
                  style: Theme.of(ctx).textTheme.bodySmall)),
            const Divider(),
            ])),
            if (visible.isEmpty) const SliverToBoxAdapter(
              child: Padding(padding: EdgeInsets.symmetric(vertical: 24),
                  child: Center(child: LText('partitions.noSearchResults')))),
            SliverList(delegate: SliverChildBuilderDelegate((_, index) {
              final item = visible[index];
              final id = item['id'].toString();
              return CheckboxListTile(value: selected.contains(id), title: Text(item['title']?.toString() ?? ''),
                subtitle: Text('${item['kind']}${item['trashed_at_ms'] != null ? ' · ${tr('partitions.trashed')}' : ''}'),
                onChanged: (value) => update(() { if (value == true) { selected.add(id); } else { selected.remove(id); } }));
            }, childCount: visible.length)),
          ])),
        actions: [TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('common.cancel')),
          FilledButton(onPressed: selected.isEmpty || (groupChoice == '__new__' && newGroupName.trim().isEmpty)
            ? null : () => Navigator.pop(ctx, true), child: const LText('partitions.preview'))],
      );
    }));
    if (proceed != true || !context.mounted) return;
    final ids = selected.toList()..sort();
    final selectedGroup = groupChoice.isEmpty || groupChoice == '__new__' ? null
      : targetGroups[target]!.firstWhere((group) => group['id'].toString() == groupChoice);
    final String? targetGroupName = groupChoice == '__new__' ? newGroupName.trim() : selectedGroup?['name']?.toString();
    final String? targetGroupId = selectedGroup?['id']?.toString();
    final preview = await AgentBridge.manage({'action': 'partition_move_preview', 'item_ids': ids, 'target_partition_id': target,
      'target_group_name': targetGroupId == null ? targetGroupName : null, 'target_group_id': targetGroupId});
    if (!context.mounted) return;
    final affected = (preview['items'] as List).cast<Map>();
    final confirmed = await showDialog<bool>(context: context, builder: (ctx) => AlertDialog(
      title: const LText('partitions.confirmMove'),
      content: SizedBox(width: appEditDialogWidth(ctx), height: MediaQuery.sizeOf(ctx).height * .55,
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          LText('partitions.moveHelp', args: {'selected': ids.length, 'count': affected.length,
            'name': destinations.firstWhere((p) => p['id'] == target)['name']}),
          LText(targetGroupName == null ? 'partitions.confirmKeepGroups' : 'partitions.confirmTargetGroup', args: {'name': targetGroupName}),
          const SizedBox(height: 12),
          Expanded(child: ListView.builder(itemCount: affected.length, itemBuilder: (_, index) {
            final item = affected[index];
            return ListTile(title: Text(item['title']?.toString() ?? ''),
              subtitle: Text([item['kind'], item['account'], item['partition_name'], item['group_name'],
                if (item['trashed'] == 1) tr('partitions.trashed')].where((v) => v != null && v.toString().isNotEmpty).join(' · ')),
              trailing: selected.contains(item['id']) ? null : const LText('partitions.linked'));
          })),
        ])),
      actions: [TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('common.cancel')),
        FilledButton(onPressed: affected.isEmpty ? null : () => Navigator.pop(ctx, true), child: const LText('partitions.confirmMove'))],
    ));
    if (confirmed != true || !context.mounted || !await requireTouchId(context, reason: 'partitions.confirmMove', confirmed: true)) return;
    await AgentBridge.manage({'action': 'partition_move_apply', 'item_ids': ids, 'target_partition_id': target,
      'target_group_name': targetGroupId == null ? targetGroupName : null, 'target_group_id': targetGroupId,
      'fingerprint': preview['fingerprint']});
    AgentBridge.notifyVaultChanged();
    if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: LText('partitions.moved', args: {'count': affected.length})));
  } catch (e) { if (context.mounted) await _failure(context, e); }
}
