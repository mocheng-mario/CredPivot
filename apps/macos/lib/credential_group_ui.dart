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
        title: const LText('groups.showManageGroupsDialog.text'),
        content: SizedBox(
          width: appEditDialogWidth(ctx),
          child: groups.isEmpty
              ? const LText('groups.showManageGroupsDialog.text.item2')
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
                          if (!await confirmCredentialDanger(ctx, title: tr('groups.showManageGroupsDialog.title'),
                              message: tr('groups.delete.confirmation', args: {'name': g['name']}), confirmLabel: tr('groups.showManageGroupsDialog.title'))) return;
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
                    title: const LText('groups.showManageGroupsDialog.text.item3'),
                    content: SizedBox(width: appEditDialogWidth(d), child: Column(mainAxisSize: MainAxisSize.min, children: [
                      TextField(controller: nameCtl, enabled: !busy, decoration: InputDecoration(labelText: tr('groups.showManageGroupsDialog.text.item4'))),
                      if (error.isNotEmpty) LText(error),
                    ])),
                    actions: [
                      TextButton(onPressed: busy ? null : () => Navigator.maybePop(d), child: const LText('common.cancel')),
                      FilledButton(onPressed: busy ? null : () async {
                        if (nameCtl.text.trim().isEmpty) { update(() => error = tr('groups.showManageGroupsDialog.text.item5')); return; }
                        update(() => busy = true);
                        try {
                          await AgentBridge.createCredentialGroup(scope, nameCtl.text.trim());
                          if (d.mounted) Navigator.pop(d, true);
                        } on AgentException catch (e) { if (d.mounted) update(() { error = e.message; busy = false; }); }
                      }, child: const LText('groups.showManageGroupsDialog.text.item6')),
                    ],
                  )));
                if (created == true && ctx.mounted) {
                  groups = await loadCredentialGroups(scope);
                  if (ctx.mounted) setLocal(() {});
                }
              } finally { nameCtl.dispose(); }
            },
            child: const LText('groups.showManageGroupsDialog.text.item3'),
          ),
          FilledButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.done')),
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
      title: const LText('credentials.build.text.item20'),
      content: SizedBox(width: appEditDialogWidth(ctx), child: Column(mainAxisSize: MainAxisSize.min, children: [
        DropdownButtonFormField<String?>(isExpanded: true, value: selected,
          decoration: InputDecoration(labelText: tr('groups.showMoveItemToGroupDialog.text')),
          items: [const DropdownMenuItem(value: null, child: LText('common.ungroupedOption')),
            for (final group in groups) DropdownMenuItem(value: group['id'] as String, child: Text(group['name'].toString()))],
          onChanged: busy ? null : (value) => update(() => selected = value)),
        if (error.isNotEmpty) LText(error),
      ])),
      actions: [
        TextButton(onPressed: busy ? null : () => Navigator.maybePop(ctx), child: const LText('common.cancel')),
        FilledButton(onPressed: busy ? null : () async {
          update(() => busy = true);
          try {
            await AgentBridge.setItemGroup(itemId, selected);
            if (ctx.mounted) Navigator.pop(ctx);
          } on AgentException catch (e) { if (ctx.mounted) update(() { error = e.message; busy = false; }); }
        }, child: const LText('common.save')),
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
                labelText: tr('common.group'), prefixIcon: Icon(Icons.folder_outlined)),
            items: [
              const DropdownMenuItem(value: null, child: LText('common.all')),
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
            tooltip: tr('groups.showManageGroupsDialog.text')),
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
    final title = key == null ? tr('common.ungrouped') : (groupName[key] ?? tr('common.group'));
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
