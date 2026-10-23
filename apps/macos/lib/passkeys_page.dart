import 'package:flutter/material.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';
import 'credential_list_tile.dart';
import 'touch_id_gate.dart';
import 'vault_tools.dart';

class PasskeysPanel extends StatefulWidget {
  const PasskeysPanel({super.key});
  @override
  State<PasskeysPanel> createState() => _PasskeysPanelState();
}

class _PasskeysPanelState extends State<PasskeysPanel> {
  List<Map<String, dynamic>> _items = [];
  Map<String, dynamic>? _selected;
  String _query = '';
  String _error = '';
  bool _busy = false;
  int _generation = 0;

  @override
  void initState() {
    super.initState();
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
      final response = AgentBridge.payloadOf(
          await AgentBridge.request({'type': 'passkey_list'}));
      if (!mounted || generation != _generation) return;
      final items = (response['items'] as List? ?? [])
          .map((v) => Map<String, dynamic>.from(v as Map))
          .toList();
      final id = _selected?['credential_id'];
      _items = items;
      _selected = null;
      for (final row in items) {
        if (row['credential_id'] == id) {
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
      }
    } catch (e) {
      if (mounted)
        setState(() => _error =
            e is AgentException ? AgentBridge.friendlyMessage(e) : tr('passkey.delete.text'));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final query = _query.trim().toLowerCase();
    final visible = _items
        .where((row) => [row['rp_id'], row['username'], row['display_name']]
            .any((value) => value.toString().toLowerCase().contains(query)))
        .toList();
    final selected = _selected;
    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 12, 24, 20),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        AppSectionHeader(
            title: tr('credentials.passkey.title'),
            subtitle: tr('passkey.list.count', args: {'count': visible.length}),
            action: IconButton(
                onPressed: _busy ? null : _refresh,
                tooltip: tr('passkey.build.text'),
                icon: const Icon(Icons.refresh_rounded))),
        AppNotice(
            tr('passkey.build.text.item2')),
        const SizedBox(height: 12),
        TextField(
            onChanged: (value) => setState(() => _query = value),
            decoration: InputDecoration(
                hintText: tr('passkey.build.text.item3'),
                prefixIcon: const Icon(Icons.search_rounded))),
        if (_error.isNotEmpty) AppNotice(_error),
        const SizedBox(height: 12),
        Expanded(
            child: CredentialWorkspace(
          list: visible.isEmpty
              ? AppEmptyState(
                  icon: Icons.fingerprint_rounded,
                  title: tr('passkey.build.title'),
                  message: tr('passkey.build.message'))
              : ListView(
                  children: visible
                      .map((row) => selectableCredentialTile(
                            context: context,
                            selected: selected?['credential_id'] ==
                                row['credential_id'],
                            icon: Icons.fingerprint_rounded,
                            title: Text(row['rp_id']?.toString() ?? ''),
                            subtitle: Text(row['username']?.toString() ?? ''),
                            onTap: _busy
                                ? null
                                : () => setState(() => _selected = row),
                          ))
                      .toList()),
          detail: selected == null
              ? null
              : CredentialDetails(
                  title: selected['rp_id'].toString(),
                  icon: Icons.fingerprint_rounded,
                  fields: {
                      tr('passkey.build.text.item4'): selected['rp_id'].toString(),
                      tr('common.account'): selected['username'].toString(),
                      tr('passkey.build.text.item5'): selected['display_name'].toString(),
                      tr('passkey.build.text.item6'): vaultDate(selected['created_at_ms']),
                      tr('passkey.build.text.item7'): vaultDate(selected['last_used_at_ms']),
                      tr('passkey.build.text.item8'): tr('passkey.build.text.item9')
                    }),
          actions: selected == null
              ? null
              : CredentialActionSection(
                  title: tr('server.build.title.item5'),
                  dangerous: true,
                  children: [
                      OutlinedButton(
                          onPressed: _busy ? null : _delete,
                          child: const LText('passkey.delete.title'))
                    ]),
        )),
      ]),
    );
  }
}
