import 'package:flutter/material.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';
import 'linked_refs.dart';

/// 凭据子模块 scope：login | totp | ssh | server
Future<List<Map<String, dynamic>>> loadCredentialGroups(String scope) async {
  return AgentBridge.listCredentialGroups(scope);
}

Future<void> showManageGroupsDialog(BuildContext context, String scope) async {
  var groups = await loadCredentialGroups(scope);
  await showDialog<void>(
    context: context,
    builder: (ctx) => StatefulBuilder(
      builder: (ctx, setLocal) => AlertDialog(
        title: const Text('管理分组'),
        content: SizedBox(
          width: 360,
          child: groups.isEmpty
              ? const Text('暂无分组，可点击下方新建。')
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
                          try {
                            await AgentBridge.deleteCredentialGroup(g['id'] as String);
                            groups = await loadCredentialGroups(scope);
                            setLocal(() {});
                          } on AgentException catch (e) {
                            ScaffoldMessenger.of(ctx).showSnackBar(SnackBar(content: Text(e.message)));
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
              final ok = await showDialog<bool>(
                context: ctx,
                builder: (d) => AlertDialog(
                  title: const Text('新建分组'),
                  content: TextField(controller: nameCtl, decoration: const InputDecoration(labelText: '分组名称')),
                  actions: [
                    TextButton(onPressed: () => Navigator.pop(d, false), child: const Text('取消')),
                    FilledButton(onPressed: () => Navigator.pop(d, true), child: const Text('创建')),
                  ],
                ),
              );
              if (ok != true) return;
              try {
                await AgentBridge.createCredentialGroup(scope, nameCtl.text.trim());
                groups = await loadCredentialGroups(scope);
                setLocal(() {});
              } on AgentException catch (e) {
                ScaffoldMessenger.of(ctx).showSnackBar(SnackBar(content: Text(e.message)));
              }
            },
            child: const Text('新建分组'),
          ),
          FilledButton(onPressed: () => Navigator.pop(ctx), child: const Text('完成')),
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
  var groups = await loadCredentialGroups(scope);
  String? selected = dropdownValueIfPresent(currentGroupId, groups);
  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => StatefulBuilder(
      builder: (ctx, setLocal) => AlertDialog(
        title: const Text('移到分组'),
        content: DropdownButtonFormField<String?>(
          isExpanded: true,
          value: selected,
          decoration: const InputDecoration(labelText: '目标分组'),
          items: [
            const DropdownMenuItem(value: null, child: Text('（未分组）')),
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
          onChanged: (v) => setLocal(() => selected = v),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('取消')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('保存')),
        ],
      ),
    ),
  );
  if (ok != true) return;
  try {
    await AgentBridge.setItemGroup(itemId, selected);
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('分组已更新')));
    }
  } on AgentException catch (e) {
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    }
  }
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
            decoration: const InputDecoration(
                labelText: '分组', prefixIcon: Icon(Icons.folder_outlined)),
            items: [
              const DropdownMenuItem(value: null, child: Text('全部')),
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
            tooltip: '管理分组'),
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
      child: Text('$title  ·  ${buckets[key]!.length}',
          style: const TextStyle(
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
