import 'package:flutter/material.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';

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
  if (path.isEmpty) return tr('common.notSelected');
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
  bool _busy = false, _confirming = false;

  Future<void> _cancel() async {
    if (_busy || _confirming) return;
    _confirming = true;
    try {
      final changed = _appPath.text != (widget.initial['path'] ?? '');
      if (changed && !await confirmDiscardChanges(context)) return;
      if (mounted) Navigator.pop(context, false);
    } finally { _confirming = false; }
  }

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
    if (picked == null || !mounted) return;
    setState(() {
      _appPath.text = picked['path']?.toString() ?? '';
      _appName.text = picked['name']?.toString() ?? '';
      _status = '';
    });
  }

  Future<void> _save() async {
    if (_busy) return;
    if (_appPath.text.trim().isEmpty) {
      setState(() => _status = tr('terminal.save.text'));
      return;
    }
    setState(() => _busy = true);
    try {
      await AgentBridge.setTerminalLaunchConfig({'path': _appPath.text.trim()});
      if (mounted) Navigator.pop(context, true);
    } catch (_) {
      if (mounted) setState(() { _busy = false; _status = tr('terminal.save.text.item2'); });
    }
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(canPop: false, onPopInvokedWithResult: (didPop, _) { if (!didPop) _cancel(); }, child: AlertDialog(
      title: const LText('settings.build.text.item47'),
      content: SizedBox(
        width: appEditDialogWidth(context),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisSize: MainAxisSize.min,
          children: [
            const LText(
              'terminal.build.text',
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 12),
            LText(
              _appName.text.isNotEmpty
                  ? tr('terminal.selection.current', args: {'name': _appName.text, 'path': _appPath.text})
                  : tr('terminal.build.text.item3'),
              style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
            ),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: _busy ? null : _pickApp,
              icon: const Icon(Icons.apps, size: 18),
              label: const LText('terminal.build.text.item4'),
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
        TextButton(onPressed: _busy ? null : _cancel, child: const LText('common.cancel')),
        FilledButton(onPressed: _busy ? null : _save, child: const LText('common.save')),
      ],
    ));
  }
}
