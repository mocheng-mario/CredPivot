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
  static const _labels = {'search': '搜索凭据', 'lock': '锁定保险库', 'new': '新建记录'};
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
    if (value.isEmpty) return tr('已停用');
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
      if (other != null) return '「${_labels[entry.key]}」与「${_labels[other]}」的快捷键重复';
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
      if (mounted) setState(() => _message = '快捷键配置读取失败，请重试');
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
        _message = error ?? '已设置，点击「保存快捷键」后生效';
      });
    } catch (_) {
      if (mounted) setState(() => _message = '快捷键录入未完成，请重试');
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
        _message = '已载入默认快捷键，点击「保存快捷键」后生效';
      });
    } catch (_) {
      if (mounted) setState(() => _message = '配置备份失败，未恢复默认值');
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
        setState(() => _message = '快捷键已在其他位置更新，请重新加载后再保存');
        return;
      }
      if ((result['warning']?.toString() ?? '').isNotEmpty) {
        setState(() => _message = '配置文件无效，请先在「设置」修复配置');
        return;
      }
      if (result['vault_exists'] == true && !await requireTouchId(context, reason: '保存快捷键配置')) return;
      if (!mounted) return;
      // 合并最新配置，只写入本页字段，避免覆盖其他设置页已经保存的修改。
      for (final entry in _bindings.entries) { current['shortcut_${entry.key}'] = entry.value; }
      await AgentBridge.saveAppSettings(current);
      if (!mounted) return;
      setState(() {
        _saved = Map<String, String>.from(_bindings);
        _message = '快捷键已保存并生效';
      });
    } on AgentException catch (e) {
      if (mounted) setState(() => _message = AgentBridge.friendlyMessage(e));
    } catch (_) {
      if (mounted) setState(() => _message = '保存未完成，修改已保留，请重新加载确认当前状态');
    } finally { if (mounted) setState(() => _saving = false); }
  }

  @override
  Widget build(BuildContext context) {
    if (_saved.isEmpty) return Center(child: _loading ? const CircularProgressIndicator() :
      Column(mainAxisSize: MainAxisSize.min, children: [
        LText(_message.isEmpty ? '快捷键尚未加载' : _message),
        TextButton(onPressed: _load, child: const LText('重试')),
      ]));
    return AbsorbPointer(absorbing: _busy, child: ListView(
      padding: const EdgeInsets.fromLTRB(24, 6, 24, 24),
      children: [
        AppSectionHeader(title: '快捷键管理', subtitle: '仅在 CredPivot 前台生效，点击组合键即可重新录入',
          action: Wrap(spacing: 8, runSpacing: 8, children: [
            TextButton(onPressed: _reload, child: const LText('重新加载')),
            TextButton(onPressed: _restoreDefaults, child: const LText('恢复默认')),
            FilledButton.icon(onPressed: _dirty && _warning.isEmpty ? _save : null,
              icon: const Icon(Icons.check_rounded), label: LText(_saving ? '保存中…' : '保存快捷键')),
          ])),
        if (_busy) const LinearProgressIndicator(),
        if (_warning.isNotEmpty) AppNotice(_warning),
        if (_message.isNotEmpty) AppNotice(_message, onDismiss: () => setState(() => _message = '')),
        if (_backupPath.isNotEmpty) AppPanel(title: '恢复默认前的配置备份', child: SelectableText(_backupPath)),
        const SizedBox(height: 16),
        AppPanel(icon: Icons.keyboard_outlined, title: _dirty ? '有未保存的修改' : '应用快捷键',
          subtitle: '录入时会检查重复组合；系统复制、粘贴和窗口快捷键保持原有行为。',
          child: Column(children: [
            for (final entry in _labels.entries) ...[
              if (entry.key != _labels.keys.first) const Divider(height: 32),
              Row(children: [
                Expanded(child: LText(entry.value, style: Theme.of(context).textTheme.titleMedium)),
                OutlinedButton.icon(onPressed: () => _record(entry.key), icon: const Icon(Icons.keyboard, size: 18),
                  label: Text(_display(_bindings[entry.key] ?? ''), style: const TextStyle(fontSize: 16))),
                const SizedBox(width: 8),
                IconButton(tooltip: tr('停用此快捷键'), onPressed: (_bindings[entry.key] ?? '').isEmpty ? null :
                  () => setState(() => _bindings[entry.key] = ''), icon: const Icon(Icons.close_rounded)),
              ]),
            ],
          ])),
        const SizedBox(height: 16),
        const AppNotice('⌘W 关闭主窗口并保持后台运行。关闭窗口不会退出 App，也不会替代保险库的空闲锁定。'),
      ],
    ));
  }
}
