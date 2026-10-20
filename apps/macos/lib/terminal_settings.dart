import 'package:flutter/material.dart';

import 'agent_bridge.dart';

Future<Map<String, String>> loadTerminalApplication() async {
  final raw = await AgentBridge.getTerminalApplication();
  return {
    'path': raw['path']?.toString() ?? '',
    'name': raw['name']?.toString() ?? '',
  };
}

/// 未配置时弹出选择；返回是否已有可用终端。
Future<bool> ensureTerminalConfigured(BuildContext context) async {
  final cur = await loadTerminalApplication();
  if (cur['path']?.isNotEmpty == true) return true;
  return showTerminalPickerDialog(context);
}

Future<bool> showTerminalPickerDialog(BuildContext context) async {
  final initial = await loadTerminalApplication();
  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => _TerminalSettingsDialog(initial: initial),
  );
  return ok == true || (await loadTerminalApplication())['path']?.isNotEmpty == true;
}

String terminalDisplayName(Map<String, String> pref) {
  final name = pref['name'] ?? '';
  if (name.isNotEmpty) return name;
  final path = pref['path'] ?? '';
  if (path.isEmpty) return '未选择';
  final parts = path.split('/');
  return parts.isNotEmpty ? parts.last : path;
}

class _TerminalSettingsDialog extends StatefulWidget {
  const _TerminalSettingsDialog({required this.initial});

  final Map<String, String> initial;

  @override
  State<_TerminalSettingsDialog> createState() => _TerminalSettingsDialogState();
}

class _TerminalSettingsDialogState extends State<_TerminalSettingsDialog> {
  late TextEditingController _appPath;
  late TextEditingController _appName;
  String _status = '';

  @override
  void initState() {
    super.initState();
    _appPath = TextEditingController(text: widget.initial['path'] ?? '');
    _appName = TextEditingController(text: widget.initial['name'] ?? '');
  }

  @override
  void dispose() {
    _appPath.dispose();
    _appName.dispose();
    super.dispose();
  }

  Future<void> _pickApp() async {
    final picked = await AgentBridge.pickTerminalApplication();
    if (picked == null) return;
    setState(() {
      _appPath.text = picked['path']?.toString() ?? '';
      _appName.text = picked['name']?.toString() ?? '';
      _status = '';
    });
  }

  Future<void> _save() async {
    if (_appPath.text.trim().isEmpty) {
      setState(() => _status = '请先选择终端 .app');
      return;
    }
    await AgentBridge.setTerminalLaunchConfig({'path': _appPath.text.trim()});
    if (mounted) Navigator.pop(context, true);
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('选择终端'),
      content: SizedBox(
        width: 480,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
              '一键 SSH / 自动认证会在所选终端中打开新标签。'
              ' 已内置 Terminal、iTerm、Warp、Tabby 等常见应用的启动方式。',
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 12),
            Text(
              _appName.text.isNotEmpty
                  ? '当前：${_appName.text}\n${_appPath.text}'
                  : '当前：未选择',
              style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
            ),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: _pickApp,
              icon: const Icon(Icons.apps, size: 18),
              label: const Text('选择 .app'),
            ),
            if (_status.isNotEmpty) ...[
              const SizedBox(height: 8),
              Text(
                _status,
                style: TextStyle(color: Theme.of(context).colorScheme.error, fontSize: 12),
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('取消')),
        FilledButton(onPressed: _save, child: const Text('保存')),
      ],
    );
  }
}
