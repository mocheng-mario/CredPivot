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
            e is AgentException ? AgentBridge.friendlyMessage(e) : '读取通行密钥失败';
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
          title: '删除通行密钥',
          message:
              '确定删除「${selected['rp_id']} · ${selected['username']}」？此操作只移入本机回收站，不会撤销网站上的注册。请先确认网站还有其他登录方式。'))
        return;
      if (!mounted ||
          !await requireTouchId(context, reason: '删除通行密钥', confirmed: true))
        return;
      await AgentBridge.trashCredential(selected['item_id'] as String);
      if (mounted) {
        _selected = null;
        await _refresh();
      }
    } catch (e) {
      if (mounted)
        setState(() => _error =
            e is AgentException ? AgentBridge.friendlyMessage(e) : '删除失败，请重试');
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
            title: '通行密钥',
            subtitle: '${visible.length} 条通行密钥 · Chrome 预览版',
            action: IconButton(
                onPressed: _busy ? null : _refresh,
                tooltip: tr('刷新列表'),
                icon: const Icon(Icons.refresh_rounded))),
        const AppNotice(
            '先在 Chrome 插件中为网站启用通行密钥，再到网站的安全设置中新建。私钥不会展示或复制，随 CredPivot 加密备份迁移、恢复。'),
        const SizedBox(height: 12),
        TextField(
            onChanged: (value) => setState(() => _query = value),
            decoration: InputDecoration(
                hintText: tr('搜索网站或账号'),
                prefixIcon: const Icon(Icons.search_rounded))),
        if (_error.isNotEmpty) AppNotice(_error),
        const SizedBox(height: 12),
        Expanded(
            child: CredentialWorkspace(
          list: visible.isEmpty
              ? const AppEmptyState(
                  icon: Icons.fingerprint_rounded,
                  title: '暂无通行密钥',
                  message: '在网站新建并选择保存到 CredPivot 后，将显示在这里。')
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
                      '网站 RP ID': selected['rp_id'].toString(),
                      '账号': selected['username'].toString(),
                      '显示名称': selected['display_name'].toString(),
                      '创建时间': vaultDate(selected['created_at_ms']),
                      '最近使用': vaultDate(selected['last_used_at_ms']),
                      '备份方式': '随 CredPivot 加密备份保存'
                    }),
          actions: selected == null
              ? null
              : CredentialActionSection(
                  title: '危险操作',
                  dangerous: true,
                  children: [
                      OutlinedButton(
                          onPressed: _busy ? null : _delete,
                          child: const LText('删除通行密钥'))
                    ]),
        )),
      ]),
    );
  }
}
