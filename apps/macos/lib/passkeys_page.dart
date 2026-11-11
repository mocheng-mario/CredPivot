import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';
import 'credential_group_ui.dart';
import 'credential_list_tile.dart';
import 'linked_refs.dart';
import 'touch_id_gate.dart';
import 'vault_tools.dart';

class PasskeysPanel extends StatefulWidget {
  const PasskeysPanel({super.key, this.initialSelection});
  final Map<String, dynamic>? initialSelection;
  @override
  State<PasskeysPanel> createState() => _PasskeysPanelState();
}

class _PasskeysPanelState extends State<PasskeysPanel> {
  List<Map<String, dynamic>> _items = [];
  List<Map<String, dynamic>> _groups = [];
  String? _filterGroupId;
  Map<String, dynamic>? _selected;
  String _query = '';
  String _error = '';
  bool _busy = false;
  int _generation = 0;

  @override
  void initState() {
    super.initState();
    _selected = widget.initialSelection;
    AgentBridge.vaultChanges.addListener(_changed);
    _refresh();
  }

  void _changed() {
    if (mounted) _refresh();
  }

  @override
  void dispose() {
    AgentBridge.vaultChanges.removeListener(_changed);
    super.dispose();
  }

  Future<void> _refresh() async {
    final generation = ++_generation;
    setState(() {
      _busy = true;
      _error = '';
    });
    try {
      final partition = AgentBridge.activePartitionId;
      final response = AgentBridge.payloadOf(
          await AgentBridge.request({'type': 'passkey_list'}, partitionId: partition));
      final groups = await loadCredentialGroups('passkey', partitionId: partition);
      if (!mounted || generation != _generation) return;
      final items = (response['items'] as List? ?? [])
          .map((v) => Map<String, dynamic>.from(v as Map))
          .toList();
      final id = _selected?['credential_id'];
      _items = items;
      _groups = groups;
      _filterGroupId = dropdownValueIfPresent(_filterGroupId, groups);
      _selected = null;
      for (final row in items) {
        if (row['credential_id'] == id &&
            (_filterGroupId == null || row['group_id'] == _filterGroupId)) {
          _selected = row;
          break;
        }
      }
    } catch (e) {
      if (mounted && generation == _generation)
        _error =
            e is AgentException ? AgentBridge.friendlyMessage(e) : tr('passkey.refresh.text');
    } finally {
      if (mounted && generation == _generation) setState(() => _busy = false);
    }
  }

  Future<void> _delete() async {
    final selected = _selected;
    if (_busy || selected == null) return;
    setState(() => _busy = true);
    try {
      if (!await confirmCredentialDanger(context,
          title: tr('passkey.delete.title'),
          message:
              tr('passkey.delete.confirmation', args: {'rpId': selected['rp_id'], 'username': selected['username']})))
        return;
      if (!mounted ||
          !await requireTouchId(context, reason: tr('passkey.delete.title'), confirmed: true))
        return;
      await AgentBridge.trashCredential(selected['item_id'] as String);
      if (mounted) {
        _selected = null;
        await _refresh();
        if (mounted && widget.initialSelection != null && ModalRoute.of(context)?.isCurrent == true) Navigator.pop(context);
      }
    } catch (e) {
      if (mounted)
        setState(() => _error =
            e is AgentException ? AgentBridge.friendlyMessage(e) : tr('passkey.delete.text'));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _select(Map<String, dynamic> row) async {
    if (defaultTargetPlatform == TargetPlatform.android) {
      await showCredentialDetailSheet(context, PasskeysPanel(initialSelection: row));
      if (mounted) await _refresh();
      return;
    }
    setState(() => _selected = row);
  }

  @override
  Widget build(BuildContext context) {
    final query = _query.trim().toLowerCase();
    final visible = _items
        .where((row) => (_filterGroupId == null || row['group_id'] == _filterGroupId) &&
            [row['rp_id'], row['username'], row['display_name']]
                .any((value) => value.toString().toLowerCase().contains(query)))
        .toList();
    final selected = _selected;
    return CredentialPanel(
      detailsOnly: widget.initialSelection != null,
      detailNotice: _error.isEmpty ? null : AppNotice(_error),
      header: [
        AppSectionHeader(
            compact: defaultTargetPlatform == TargetPlatform.android,
            title: tr('credentials.passkey.title'),
            subtitle: tr('passkey.list.count', args: {'count': visible.length}),
            action: Row(mainAxisSize: MainAxisSize.min, children: [
              if (defaultTargetPlatform == TargetPlatform.android) IconButton(
                tooltip: tr('android.passkey.title'),
                icon: const Icon(Icons.info_outline),
                onPressed: () => showDialog<void>(context: context, builder: (ctx) => AlertDialog(
                  title: const LText('android.passkey.title'),
                  content: const LText('android.passkey.listHelp'),
                  actions: [TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.close'))],
                ))),
              IconButton(
                onPressed: _busy ? null : _refresh,
                tooltip: tr('passkey.build.text'),
                icon: const Icon(Icons.refresh_rounded)),
            ])),
        if (defaultTargetPlatform != TargetPlatform.android) ...[
          AppNotice(tr('passkey.build.text.item2')),
          const SizedBox(height: 12),
        ],
        TextField(
            onChanged: (value) => setState(() => _query = value),
            decoration: InputDecoration(
                isDense: defaultTargetPlatform == TargetPlatform.android,
                hintText: tr('passkey.build.text.item3'),
                prefixIcon: const Icon(Icons.search_rounded))),
        if (_error.isNotEmpty) AppNotice(_error),
        buildGroupFilterBar(
          groups: _groups,
          selectedGroupId: _filterGroupId,
          onChanged: (value) => setState(() {
            _filterGroupId = value;
            _selected = null;
          }),
          onManage: () => showManageGroupsDialog(context, 'passkey').then((_) => _refresh()),
        ),
      ],
      body: CredentialWorkspace(
          detailsOnly: widget.initialSelection != null,
          list: visible.isEmpty
              ? AppEmptyState(
                  icon: Icons.fingerprint_rounded,
                  title: tr('passkey.build.title'),
                  message: tr('passkey.build.message'))
              : ListView(
                  children: buildGroupedListTiles(
                      scope: 'passkey',
                      groups: _groups,
                      items: visible,
                      tileBuilder: (row) => selectableCredentialTile(
                            context: context,
                            selected: selected?['credential_id'] ==
                                row['credential_id'],
                            icon: Icons.fingerprint_rounded,
                            title: Text(row['rp_id']?.toString() ?? ''),
                            subtitle: Text(row['username']?.toString() ?? ''),
                            onTap: _busy
                                ? null
                                : () => _select(row),
                          ))),
          detail: selected == null
              ? null
              : CredentialDetails(
                  title: selected['rp_id'].toString(),
                  icon: Icons.fingerprint_rounded,
                  fields: {
                      tr('passkey.build.text.item4'): selected['rp_id'].toString(),
                      tr('common.account'): selected['username'].toString(),
                      tr('passkey.links.accounts'): (selected['linked_logins'] as List? ?? []).isEmpty
                          ? tr('common.notLinked')
                          : (selected['linked_logins'] as List).map((login) => '${login['title']} · ${login['username']}').join('\n'),
                      tr('passkey.build.text.item5'): selected['display_name'].toString(),
                      tr('passkey.build.text.item6'): vaultDate(selected['created_at_ms']),
                      tr('passkey.build.text.item7'): vaultDate(selected['last_used_at_ms']),
                      tr('passkey.build.text.item8'): tr('passkey.build.text.item9')
                    }),
          actions: selected == null
              ? null
              : Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  CredentialActionSection(
                    title: tr('server.build.title.item4'),
                    children: [
                      OutlinedButton(
                          onPressed: _busy ? null : () async {
                            await editItemDetails(context, selected);
                            if (mounted) await _refresh();
                          },
                          child: const LText('passkey.links.edit')),
                      OutlinedButton(
                          onPressed: _busy ? null : () async {
                            await showMoveItemToGroupDialog(context, scope: 'passkey',
                                itemId: selected['item_id'] as String,
                                currentGroupId: selected['group_id'] as String?);
                            if (mounted) await _refresh();
                          },
                          child: const LText('credentials.build.text.item20')),
                    ],
                  ),
                  CredentialActionSection(
                    title: tr('server.build.title.item5'),
                    dangerous: true,
                    children: [
                      OutlinedButton(
                          onPressed: _busy ? null : _delete,
                          child: const LText('passkey.delete.title'))
                    ]),
                ]),
      ),
    );
  }
}
