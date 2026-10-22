import 'package:flutter/material.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';
import 'linked_refs.dart';
import 'credential_confirm.dart';

/// 凭据子模块 scope：login | totp | ssh | server
Future<List<Map<String, dynamic>>> loadCredentialGroups(String scope) async {
  return AgentBridge.listCredentialGroups(scope);
}

Future<void> showManageGroupsDialog(BuildContext context, String scope) async {
  var groups = await loadCredentialGroups(scope);
  if (!context.mounted) return;
  await showDialog<void>(
    context: context,
    builder: (ctx) => StatefulBuilder(
      builder: (ctx, setLocal) => AlertDialog(
        title: const LText('管理分组'),
        content: SizedBox(
          width: appEditDialogWidth(ctx),
          child: groups.isEmpty
              ? const LText('暂无分组，可点击下方新建。')
              : ListView.builder(
                  shrinkWrap: true,
                  itemCount: groups.length,
                  itemBuilder: (_, i) {
                    final g = groups[i];
                    return ListTile(
                      title: Text(g['name']?.toString() ?? ''),
                      trailing: IconButton(
                        icon: const Icon(Icons.delete_outline),
                        onPressed: () async {
                          if (!await confirmCredentialDanger(ctx, title: '删除分组',
                              message: '删除「${g['name']}」？凭据不会删除，将移到未分组。', confirmLabel: '删除分组')) return;
                          if (!ctx.mounted) return;
                          try {
                            await AgentBridge.deleteCredentialGroup(g['id'] as String);
                            groups = await loadCredentialGroups(scope);
                            if (ctx.mounted) setLocal(() {});
                          } on AgentException catch (e) {
                            if (ctx.mounted) ScaffoldMessenger.of(ctx).showSnackBar(SnackBar(content: LText(e.message)));
                          }
                        },
                      ),
                    );
                  },
                ),
        ),
        actions: [
          TextButton(
            onPressed: () async {
              final nameCtl = TextEditingController();
              var busy = false;
              var error = '';
              try {
                final created = await showDraftDialog<bool>(context: ctx,
                  hasChanges: () => nameCtl.text.isNotEmpty, isBusy: () => busy,
                  builder: (d) => StatefulBuilder(builder: (d, update) => AlertDialog(
                    title: const LText('新建分组'),
                    content: SizedBox(width: appEditDialogWidth(d), child: Column(mainAxisSize: MainAxisSize.min, children: [
                      TextField(controller: nameCtl, enabled: !busy, decoration: InputDecoration(labelText: tr('分组名称'))),
                      if (error.isNotEmpty) LText(error),
                    ])),
                    actions: [
                      TextButton(onPressed: busy ? null : () => Navigator.maybePop(d), child: const LText('取消')),
                      FilledButton(onPressed: busy ? null : () async {
                        if (nameCtl.text.trim().isEmpty) { update(() => error = '请输入分组名称'); return; }
                        update(() => busy = true);
                        try {
                          await AgentBridge.createCredentialGroup(scope, nameCtl.text.trim());
                          if (d.mounted) Navigator.pop(d, true);
                        } on AgentException catch (e) { if (d.mounted) update(() { error = e.message; busy = false; }); }
                      }, child: const LText('创建')),
                    ],
                  )));
                if (created == true && ctx.mounted) {
                  groups = await loadCredentialGroups(scope);
                  if (ctx.mounted) setLocal(() {});
                }
              } finally { nameCtl.dispose(); }
            },
            child: const LText('新建分组'),
          ),
          FilledButton(onPressed: () => Navigator.pop(ctx), child: const LText('完成')),
        ],
      ),
    ),
  );
}

/// 将已有凭据（items.item_id）移入/移出分组。
Future<void> showMoveItemToGroupDialog(
  BuildContext context, {
  required String scope,
  required String itemId,
  String? currentGroupId,
}) async {
  final groups = await loadCredentialGroups(scope);
  if (!context.mounted) return;
  String? selected = dropdownValueIfPresent(currentGroupId, groups);
  final initial = selected;
  var busy = false;
  var error = '';
  await showDraftDialog<void>(context: context, hasChanges: () => selected != initial, isBusy: () => busy,
    builder: (ctx) => StatefulBuilder(builder: (ctx, update) => AlertDialog(
      title: const LText('移到分组'),
      content: SizedBox(width: appEditDialogWidth(ctx), child: Column(mainAxisSize: MainAxisSize.min, children: [
        DropdownButtonFormField<String?>(isExpanded: true, value: selected,
          decoration: InputDecoration(labelText: tr('目标分组')),
          items: [const DropdownMenuItem(value: null, child: LText('（未分组）')),
            for (final group in groups) DropdownMenuItem(value: group['id'] as String, child: Text(group['name'].toString()))],
          onChanged: busy ? null : (value) => update(() => selected = value)),
        if (error.isNotEmpty) LText(error),
      ])),
      actions: [
        TextButton(onPressed: busy ? null : () => Navigator.maybePop(ctx), child: const LText('取消')),
        FilledButton(onPressed: busy ? null : () async {
          update(() => busy = true);
          try {
            await AgentBridge.setItemGroup(itemId, selected);
            if (ctx.mounted) Navigator.pop(ctx);
          } on AgentException catch (e) { if (ctx.mounted) update(() { error = e.message; busy = false; }); }
        }, child: const LText('保存')),
      ],
    )));
}


Widget buildGroupFilterBar({
  required List<Map<String, dynamic>> groups,
  required String? selectedGroupId,
  required ValueChanged<String?> onChanged,
  required VoidCallback onManage,
}) {
  return Padding(
    padding: const EdgeInsets.symmetric(vertical: 12),
    child: Row(
      children: [
        Expanded(
          child: DropdownButtonFormField<String?>(
            value: dropdownValueIfPresent(selectedGroupId, groups),
            isExpanded: true,
            decoration: InputDecoration(
                labelText: tr('分组'), prefixIcon: Icon(Icons.folder_outlined)),
            items: [
              const DropdownMenuItem(value: null, child: LText('全部')),
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
            onChanged: onChanged,
          ),
        ),
        const SizedBox(width: 8),
        IconButton(
            onPressed: onManage,
            icon: const Icon(Icons.folder_outlined),
            tooltip: tr('管理分组')),
      ],
    ),
  );
}

List<Widget> buildGroupedListTiles({
  required List<Map<String, dynamic>> groups,
  required List<Map<String, dynamic>> items,
  required Widget Function(Map<String, dynamic> row) tileBuilder,
  String groupIdKey = 'group_id',
}) {
  final groupName = <String, String>{};
  for (final g in groups) {
    groupName[g['id'] as String] = g['name']?.toString() ?? '';
  }
  final buckets = <String?, List<Map<String, dynamic>>>{};
  for (final row in items) {
    final gid = row[groupIdKey] as String?;
    final key = (gid == null || gid.isEmpty) ? null : gid;
    buckets.putIfAbsent(key, () => []).add(row);
  }
  final keys = buckets.keys.toList()
    ..sort((a, b) {
      if (a == null) return 1;
      if (b == null) return -1;
      return (groupName[a] ?? '').compareTo(groupName[b] ?? '');
    });
  final out = <Widget>[];
  for (final key in keys) {
    final title = key == null ? '未分组' : (groupName[key] ?? '分组');
    out.add(Padding(
      padding: const EdgeInsets.only(left: 4, top: 8, bottom: 10),
      child: LText('$title  ·  ${buckets[key]!.length}',
          style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: AppColors.muted)),
    ));
    for (final row in buckets[key]!) {
      out.add(tileBuilder(row));
    }
  }
  return out;
}
