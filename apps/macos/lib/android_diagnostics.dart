import 'package:flutter/material.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'touch_id_gate.dart';

class AndroidDiagnosticsPage extends StatefulWidget {
  const AndroidDiagnosticsPage({super.key, this.readOnly = false});
  final bool readOnly;
  @override
  State<AndroidDiagnosticsPage> createState() => _AndroidDiagnosticsPageState();
}

class _AndroidDiagnosticsPageState extends State<AndroidDiagnosticsPage> {
  Map<String, dynamic> data = {};
  String? file;
  String minimum = 'debug', error = '';
  bool busy = false;
  static const levels = ['debug', 'info', 'warn', 'error'];

  @override
  void initState() { super.initState(); load(); }

  Future<void> load() async {
    if (busy) return;
    setState(() { busy = true; error = ''; });
    try {
      final next = await AgentBridge.fetchDiagnosticLog(maxLines: 1000, file: file);
      if (mounted) setState(() { data = next; file = next['file'] as String?; });
    } catch (_) { if (mounted) setState(() => error = tr('android.diagnostics.failed')); }
    finally { if (mounted) setState(() => busy = false); }
  }

  @override
  Widget build(BuildContext context) {
    final files = (data['files'] as List? ?? []).cast<String>();
    final lines = (data['text'] as String? ?? '').split('\n').where((line) {
      final match = RegExp(r'\b(DEBUG|INFO|WARN|ERROR)\b').firstMatch(line);
      return match == null || levels.indexOf(match.group(1)!.toLowerCase()) >= levels.indexOf(minimum);
    }).join('\n');
    return Scaffold(appBar: AppBar(title: const LText('android.diagnostics.title'), actions: [
      IconButton(tooltip: tr('android.autofill.refresh'), onPressed: busy ? null : load, icon: const Icon(Icons.refresh))]),
      body: ListView(padding: const EdgeInsets.all(20), children: [
        if (busy) const LinearProgressIndicator(),
        if (error.isNotEmpty) AppNotice(error),
        AppPanel(title: tr('android.diagnostics.options'), icon: Icons.tune, child: appFieldRows([
          AppFieldRow(label: tr('android.diagnostics.file'), child: DropdownButtonFormField<String>(
            key: ValueKey(file), initialValue: files.contains(file) ? file : null, isExpanded: true,
            items: files.map((name) => DropdownMenuItem(value: name, child: Text(name, overflow: TextOverflow.ellipsis))).toList(),
            onChanged: busy ? null : (value) { file = value; load(); })),
          AppFieldRow(label: tr('android.diagnostics.minimum'), child: DropdownButtonFormField<String>(initialValue: minimum,
            items: levels.map((level) => DropdownMenuItem(value: level, child: Text(level.toUpperCase()))).toList(),
            onChanged: (value) => setState(() => minimum = value ?? 'debug'))),
          if (!widget.readOnly) AppFieldRow(label: tr('android.diagnostics.recording'), child: DropdownButtonFormField<String>(
            key: ValueKey(data['level']), initialValue: levels.contains(data['level']) ? data['level'] as String : 'info',
            items: levels.map((level) => DropdownMenuItem(value: level, child: Text(level.toUpperCase()))).toList(),
            onChanged: busy ? null : (value) async {
              if (value == null || !await requireTouchId(context, reason: tr('android.diagnostics.recording')) || !mounted) return;
              try { await AgentBridge.setDiagnosticLogLevel(value); await load(); }
              catch (_) { if (mounted) setState(() => error = tr('android.diagnostics.failed')); }
            })),
        ])),
        const SizedBox(height: 16),
        AppPanel(title: tr('android.diagnostics.newestFirst'), icon: Icons.receipt_long,
          child: SelectableText(lines.isEmpty ? tr('android.diagnostics.empty') : lines, style: const TextStyle(fontFamily: 'monospace', fontSize: 12))),
      ]));
  }
}
