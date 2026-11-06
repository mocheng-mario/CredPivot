import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';
import 'linked_refs.dart';
import 'credential_confirm.dart';

/// shared 在同一分区内跨子模块复用；其余 scope 仍属于指定类型。
Future<List<Map<String, dynamic>>> loadCredentialGroups(String scope, {String? partitionId}) async {
  return AgentBridge.listCredentialGroups(scope, partitionId: partitionId);
}

String credentialGroupLabel(Map group) => tr('groups.optionLabel', args: {
  'name': group['name']?.toString() ?? '',
  'type': tr(group['scope'] == 'shared' ? 'groups.type.shared' : 'groups.type.exclusive'),
});

String credentialGroupScope(String kind) => const {'ssh_key': 'ssh', 'server_login': 'server'}[kind] ?? kind;

String credentialGroupUsage(Map group) {
  const kinds = {'login': 'credentials.login.title', 'totp': 'groups.kind.totp', 'ssh_key': 'credentials.ssh.title',
    'server_login': 'credentials.server.title', 'passkey': 'credentials.passkey.title',
    'recovery_codes': 'credentials.recovery.title', 'secure_note': 'credentials.notes.title'};
  final counts = group['usage_counts'] as Map? ?? {};
  if (counts.isEmpty) return tr('groups.usage.empty');
  return tr('groups.usage.summary', args: {'items': counts.entries.map((entry) =>
    '${tr(kinds[entry.key] ?? 'credentials.trash.other')} ${entry.value}').join(' · ')});
}

Future<void> _groupFailure(BuildContext context, Object error) async {
  if (!context.mounted) return;
  await showDialog<void>(context: context, builder: (ctx) => AlertDialog(
    title: const LText('common.operationFailed'), content: LText(error is AgentException ? error.message : 'common.operationFailed'),
    actions: [TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.close'))]));
}

Future<bool> _editGroup(BuildContext context, String scope, String partition, {Map<String, dynamic>? group}) async {
  final controller = TextEditingController(text: group?['name']?.toString() ?? '');
  final originalScope = group?['scope']?.toString() ?? 'shared';
  var selectedScope = originalScope;
  var busy = false;
  var error = '';
  try {
    return await showDraftDialog<bool>(context: context,
      hasChanges: () => controller.text != (group?['name'] ?? '') || selectedScope != originalScope, isBusy: () => busy,
      builder: (ctx) => StatefulBuilder(builder: (ctx, update) => AppEditDialog(
        title: LText(group == null ? 'groups.showManageGroupsDialog.text.item3' : 'groups.edit'),
        content: SizedBox(width: appEditDialogWidth(ctx), child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch, children: appFormFields([
          AppFieldRow(label: tr('common.name'), child: TextField(controller: controller, autofocus: true, enabled: !busy, maxLength: 80)),
          AppFieldRow(label: tr('groups.type.label'), help: tr(selectedScope == 'shared' ? 'groups.type.sharedHelp' : 'groups.type.exclusiveHelp'),
            child: DropdownButtonFormField<String>(value: selectedScope, isExpanded: true,
              items: [const DropdownMenuItem(value: 'shared', child: LText('groups.type.shared')),
                if (scope != 'shared') DropdownMenuItem(value: scope, child: const LText('groups.type.exclusive'))],
              onChanged: busy ? null : (value) { if (value != null) update(() => selectedScope = value); })),
          if (group != null) Text(credentialGroupUsage(group)),
          if (originalScope == 'shared' && group != null) const LText('groups.edit.sharedHelp'),
          if (error.isNotEmpty) LText(error, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
        ])))),
        actions: [
          TextButton(onPressed: busy ? null : () => Navigator.maybePop(ctx), child: const LText('common.cancel')),
          FilledButton(onPressed: busy ? null : () async {
            if (controller.text.trim().isEmpty) { update(() => error = 'groups.showManageGroupsDialog.text.item5'); return; }
            update(() { busy = true; error = ''; });
            try {
              if (group == null) {
                await AgentBridge.createCredentialGroup(selectedScope, controller.text.trim(), partitionId: partition);
              } else {
                await AgentBridge.manage({'action': 'group_rename', 'id': group['id'], 'scope': selectedScope,
                  'expected_updated_at_ms': group['updated_at_ms'], 'name': controller.text.trim()});
                AgentBridge.notifyVaultChanged();
              }
              if (ctx.mounted) Navigator.pop(ctx, true);
            } catch (e) {
              if (ctx.mounted) update(() { busy = false; error = e is AgentException ? e.message : 'common.operationFailed'; });
            }
          }, child: const LText('common.save')),
        ],
      ))) == true;
  } finally { controller.dispose(); }
}

Future<void> showManageGroupsDialog(BuildContext context, String scope) async {
  final partition = AgentBridge.activePartitionId;
  var groups = await loadCredentialGroups(scope, partitionId: partition);
  var busy = false;
  if (!context.mounted) return;
  await showDialog<void>(context: context, barrierDismissible: false,
    builder: (ctx) => StatefulBuilder(builder: (ctx, update) => PopScope(canPop: !busy, child: AlertDialog(
      title: const LText('groups.showManageGroupsDialog.text'),
      content: SizedBox(width: appEditDialogWidth(ctx), child: Column(mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        const LText('groups.manage.help'), const SizedBox(height: 12),
        if (busy) const LinearProgressIndicator(),
        Flexible(child: groups.isEmpty ? const LText('groups.showManageGroupsDialog.text.item2') : ListView.builder(
          shrinkWrap: true, itemCount: groups.length, itemBuilder: (_, i) {
            final group = groups[i];
            return ListTile(title: Text(credentialGroupLabel(group)), subtitle: Text(credentialGroupUsage(group)),
              trailing: Wrap(children: [
                IconButton(icon: const Icon(Icons.edit_outlined), tooltip: tr('groups.edit'), onPressed: busy ? null : () async {
                  update(() => busy = true);
                  try {
                    if (await _editGroup(ctx, scope, partition, group: group)) groups = await loadCredentialGroups(scope, partitionId: partition);
                  } catch (e) { await _groupFailure(ctx, e);
                  } finally { if (ctx.mounted) update(() => busy = false); }
                }),
                IconButton(icon: const Icon(Icons.delete_outline), tooltip: tr('groups.showManageGroupsDialog.title'), onPressed: busy ? null : () async {
                  update(() => busy = true);
                  try {
                    // 重新读取跨模块用量，不能用当前页面的旧数量做删除确认。
                    groups = await loadCredentialGroups(scope, partitionId: partition);
                    final matches = groups.where((value) => value['id'] == group['id']);
                    if (matches.isEmpty || !ctx.mounted) return;
                    final current = matches.first;
                    if (!await confirmCredentialDanger(ctx, title: tr('groups.showManageGroupsDialog.title'),
                      message: tr(current['scope'] == 'shared' ? 'groups.delete.sharedConfirmation' : 'groups.delete.confirmation',
                        args: {'name': current['name'], 'usage': credentialGroupUsage(current)}), confirmLabel: tr('groups.showManageGroupsDialog.title'))) return;
                    await AgentBridge.deleteCredentialGroup(current['id'] as String);
                    groups = await loadCredentialGroups(scope, partitionId: partition);
                  } catch (e) {
                    await _groupFailure(ctx, e);
                  } finally { if (ctx.mounted) update(() => busy = false); }
                }),
              ]));
          })),
      ])),
      actions: [
        TextButton(onPressed: busy ? null : () async {
          update(() => busy = true);
          try {
            if (await _editGroup(ctx, scope, partition)) groups = await loadCredentialGroups(scope, partitionId: partition);
          } catch (e) { await _groupFailure(ctx, e);
          } finally { if (ctx.mounted) update(() => busy = false); }
        }, child: const LText('groups.showManageGroupsDialog.text.item3')),
        FilledButton(onPressed: busy ? null : () => Navigator.pop(ctx), child: const LText('common.done')),
      ],
    ))),
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
    builder: (ctx) => StatefulBuilder(builder: (ctx, update) => AppEditDialog(
      title: const LText('credentials.build.text.item20'),
      content: SizedBox(width: appEditDialogWidth(ctx), child: Column(mainAxisSize: MainAxisSize.min, children: [
        AppFieldRow(label: tr('groups.showMoveItemToGroupDialog.text'), child: DropdownButtonFormField<String?>(isExpanded: true, value: selected,
          decoration: InputDecoration(),
          items: [const DropdownMenuItem(value: null, child: LText('common.ungroupedOption')),
            for (final group in groups) DropdownMenuItem(value: group['id'] as String, child: Text(credentialGroupLabel(group), overflow: TextOverflow.ellipsis))],
          onChanged: busy ? null : (value) => update(() => selected = value))),
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
  final mobile = defaultTargetPlatform == TargetPlatform.android;
  final dropdown = DropdownButtonFormField<String?>(
    value: dropdownValueIfPresent(selectedGroupId, groups),
    isExpanded: true,
    decoration: InputDecoration(
      prefixIcon: const Icon(Icons.folder_outlined),
      labelText: mobile ? tr('common.group') : null,
      isDense: mobile,
    ),
    items: [
      const DropdownMenuItem(value: null, child: LText('common.all')),
      ...groups.map((g) => DropdownMenuItem(
        value: g['id'] as String,
        child: Text(credentialGroupLabel(g), maxLines: 1, overflow: TextOverflow.ellipsis),
      )),
    ],
    onChanged: onChanged,
  );
  return Padding(
    padding: EdgeInsets.symmetric(vertical: mobile ? 8 : 12),
    child: Row(children: [
      Expanded(child: mobile ? dropdown : AppFieldRow(label: tr('common.group'), child: dropdown)),
      const SizedBox(width: 8),
      IconButton(
        onPressed: onManage,
        icon: const Icon(Icons.folder_outlined),
        tooltip: tr('groups.showManageGroupsDialog.text')),
    ]),
  );
}

List<Widget> buildGroupedListTiles({
  required String scope,
  required List<Map<String, dynamic>> groups,
  required List<Map<String, dynamic>> items,
  required Widget Function(Map<String, dynamic> row) tileBuilder,
  String groupIdKey = 'group_id',
}) {
  final groupName = <String, String>{};
  for (final g in groups) {
    groupName[g['id'] as String] = credentialGroupLabel(g);
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
    out.add(ExpansionTile(
      // 未分组也需要独立状态；分区和子模块参与 key，避免切换页面后互相继承折叠状态。
      key: PageStorageKey<String>('credential-group:${AgentBridge.activePartitionId}:$scope:${key ?? 'ungrouped'}'),
      initiallyExpanded: true,
      tilePadding: const EdgeInsets.symmetric(horizontal: 4),
      childrenPadding: const EdgeInsets.only(bottom: 8),
      shape: const Border(),
      collapsedShape: const Border(),
      title: Text('$title  ·  ${buckets[key]!.length}',
          style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: AppColors.muted)),
      children: [for (final row in buckets[key]!) tileBuilder(row)],
    ));
  }
  return out;
}
