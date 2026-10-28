import 'package:flutter/material.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';
import 'touch_id_gate.dart';

class ShortcutsPage extends StatefulWidget {
  const ShortcutsPage({super.key, required this.active, this.busy = false});
  final bool active;
  final bool busy;

  @override
  State<ShortcutsPage> createState() => _ShortcutsPageState();
}

class _ShortcutsPageState extends State<ShortcutsPage> {
  static const _labels = {'search': 'shortcuts.actions.search', 'lock': 'vault.actions.lock', 'new': 'credentials.actions.new'};
  Map<String, String> _saved = {}, _bindings = {}, _defaults = {};
  String _message = '', _warning = '', _backupPath = '';
  bool _loading = false, _saving = false, _recording = false;
  bool get _busy => widget.busy || _loading || _saving || _recording;
  bool get _dirty => _labels.keys.any((key) => _bindings[key] != _saved[key]);

  static String _normalized(String value) => (value.split('+')..sort()).join('+');

  Map<String, String> _read(Map settings) => {
    for (final key in _labels.keys) key: settings['shortcut_$key']?.toString() ?? '',
  };

  String _display(String value) {
    if (value.isEmpty) return tr('common.disabled');
    final parts = value.split('+');
    return '${parts.contains('control') ? '⌃' : ''}'
        '${parts.contains('option') ? '⌥' : ''}'
        '${parts.contains('shift') ? '⇧' : ''}'
        '${parts.contains('command') ? '⌘' : ''}'
        '${parts.last == 'space' ? 'Space' : parts.last.toUpperCase()}';
  }

  String? _validation(Map<String, String> bindings) {
    final seen = <String, String>{};
    for (final entry in bindings.entries) {
      if (entry.value.isEmpty) continue;
      final normalized = _normalized(entry.value);
      final other = seen[normalized];
      if (other != null) return tr('shortcuts.errors.duplicate', args: {'action': tr(_labels[entry.key]!), 'otherAction': tr(_labels[other]!)});
      seen[normalized] = entry.key;
    }
    return null;
  }

  @override
  void initState() { super.initState(); _load(); }

  @override
  void didUpdateWidget(covariant ShortcutsPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.active && !oldWidget.active && !_busy && !_dirty) _load();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final result = await AgentBridge.fetchAppSettings();
      if (!mounted) return;
      setState(() {
        _saved = _read(result['settings'] as Map);
        _bindings = Map<String, String>.from(_saved);
        _defaults = _read(result['defaults'] as Map);
        _warning = result['warning']?.toString() ?? '';
      });
    } catch (_) {
      if (mounted) setState(() => _message = tr('shortcuts.load.status'));
    } finally { if (mounted) setState(() => _loading = false); }
  }

  Future<void> _reload() async {
    if (_busy) return;
    if (_dirty && !await confirmDiscardChanges(context)) return;
    if (mounted) await _load();
  }

  Future<void> _record(String name) async {
    if (_busy) return;
    setState(() => _recording = true);
    try {
      final value = await AgentBridge.recordShortcut(name, _bindings);
      if (!mounted || value == null) return;
      final next = {..._bindings, name: value};
      final error = _validation(next);
      setState(() {
        if (error == null) _bindings = next;
        _message = error ?? tr('shortcuts.record.text');
      });
    } catch (_) {
      if (mounted) setState(() => _message = tr('shortcuts.record.status'));
    } finally { if (mounted) setState(() => _recording = false); }
  }

  Future<void> _restoreDefaults() async {
    if (_busy) return;
    setState(() => _loading = true);
    try {
      final path = await AgentBridge.backupAppSettings();
      if (!mounted) return;
      setState(() {
        _bindings = Map<String, String>.from(_defaults);
        _backupPath = path ?? '';
        _message = tr('shortcuts.restoreDefaults.status');
      });
    } catch (_) {
      if (mounted) setState(() => _message = tr('shortcuts.restoreDefaults.status.item2'));
    } finally { if (mounted) setState(() => _loading = false); }
  }

  Future<void> _save() async {
    if (_busy || !_dirty || _warning.isNotEmpty) return;
    final error = _validation(_bindings);
    if (error != null) { setState(() => _message = error); return; }
    setState(() => _saving = true);
    try {
      final result = await AgentBridge.fetchAppSettings();
      if (!mounted) return;
      final current = Map<String, dynamic>.from(result['settings'] as Map);
      final latest = _read(current);
      if (_labels.keys.any((key) => latest[key] != _saved[key])) {
        setState(() => _message = tr('shortcuts.save.status'));
        return;
      }
      if ((result['warning']?.toString() ?? '').isNotEmpty) {
        setState(() => _message = tr('shortcuts.save.status.item2'));
        return;
      }
      if (result['vault_exists'] == true && !await requireTouchId(context, reason: tr('shortcuts.save.reason'))) return;
      if (!mounted) return;
      // 合并最新配置，只写入本页字段，避免覆盖其他设置页已经保存的修改。
      for (final entry in _bindings.entries) { current['shortcut_${entry.key}'] = entry.value; }
      await AgentBridge.saveAppSettings(current);
      if (!mounted) return;
      setState(() {
        _saved = Map<String, String>.from(_bindings);
        _message = tr('shortcuts.save.status.item3');
      });
    } on AgentException catch (e) {
      if (mounted) setState(() => _message = AgentBridge.friendlyMessage(e));
    } catch (_) {
      if (mounted) setState(() => _message = tr('shortcuts.save.status.item4'));
    } finally { if (mounted) setState(() => _saving = false); }
  }

  @override
  Widget build(BuildContext context) {
    if (_saved.isEmpty) return Center(child: _loading ? const CircularProgressIndicator() :
      Column(mainAxisSize: MainAxisSize.min, children: [
        LText(_message.isEmpty ? tr('shortcuts.build.text') : _message),
        TextButton(onPressed: _load, child: const LText('common.retry')),
      ]));
    return AbsorbPointer(absorbing: _busy, child: ListView(
      padding: const EdgeInsets.fromLTRB(24, 6, 24, 24),
      children: [
        AppSectionHeader(title: tr('shortcuts.build.title'), subtitle: tr('shortcuts.build.description'),
          action: Wrap(spacing: 8, runSpacing: 8, children: [
            TextButton(onPressed: _reload, child: const LText('common.reload')),
            TextButton(onPressed: _restoreDefaults, child: const LText('common.restoreDefaults')),
            FilledButton.icon(onPressed: _dirty && _warning.isEmpty ? _save : null,
              icon: const Icon(Icons.check_rounded), label: LText(_saving ? tr('common.saving') : tr('shortcuts.build.text.item2'))),
          ])),
        if (_busy) const LinearProgressIndicator(),
        if (_warning.isNotEmpty) AppNotice(_warning),
        if (_message.isNotEmpty) AppNotice(_message, onDismiss: () => setState(() => _message = '')),
        if (_backupPath.isNotEmpty) AppPanel(title: tr('settings.build.title'), child: SelectableText(_backupPath)),
        const SizedBox(height: 16),
        AppPanel(icon: Icons.keyboard_outlined, title: _dirty ? tr('settings.build.text.item3') : tr('shortcuts.build.text.item3'),
          subtitle: tr('shortcuts.build.description.item2'),
          child: appFieldRows([
            for (final entry in _labels.entries)
              AppFieldRow(label: tr(entry.value), child: Row(children: [
                OutlinedButton.icon(onPressed: () => _record(entry.key), icon: const Icon(Icons.keyboard, size: 18),
                  label: Text(_display(_bindings[entry.key] ?? ''), style: const TextStyle(fontSize: 16))),
                const SizedBox(width: 8),
                IconButton(tooltip: tr('shortcuts.build.text.item4'), onPressed: (_bindings[entry.key] ?? '').isEmpty ? null :
                  () => setState(() => _bindings[entry.key] = ''), icon: const Icon(Icons.close_rounded)),
              ])),
          ])),
        const SizedBox(height: 16),
        AppNotice(tr('shortcuts.build.text.item5')),
      ],
    ));
  }
}
