import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'build_stamp.dart';

class ComponentVersions extends StatefulWidget {
  const ComponentVersions({super.key});
  @override
  State<ComponentVersions> createState() => _ComponentVersionsState();
}

class _ComponentVersionsState extends State<ComponentVersions> {
  Map<String,dynamic> info = {};
  String error = '';
  bool busy = false;
  @override
  void initState() { super.initState(); load(); }
  Future<void> load() async {
    if (busy) return;
    setState(() { busy = true; error = ''; });
    try {
      final result = await AgentBridge.componentVersions();
      if (mounted) setState(() => info = result);
    } catch (e) {
      if (mounted) setState(() => error = e is AgentException ? tr(e.message) : tr('common.operationFailed'));
    } finally { if (mounted) setState(() => busy = false); }
  }

  @override
  Widget build(BuildContext context) => AppPanel(title: tr('components.title'),
    icon: Icons.info_outline,
    trailing: IconButton(onPressed: busy ? null : load, tooltip: tr('common.refresh'), icon: const Icon(Icons.refresh)),
    child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      if (busy) const LinearProgressIndicator(),
      if (error.isNotEmpty) AppNotice(error),
      for (final field in {
        'App': '${info['app_version'] ?? '—'} (${info['app_build'] ?? '—'})',
        tr('components.build'): kCredPivotBuildStamp,
        'Agent': info['agent_version']?.toString() ?? '—',
        tr('components.protocol'): '${info['protocol_version'] ?? '—'} / Schema ${info['schema_user_version'] ?? '—'}',
        if (defaultTargetPlatform != TargetPlatform.android) ...{
          tr('components.extension'): info['expected_extension_version']?.toString() ?? '—',
          'Native Host': tr(info['installed_host_current'] == true && info['manifest_host_matches_installed'] == true
            ? 'components.hostCurrent' : 'components.hostUpdate'),
          'Native Host SHA-256': (info['installed_host_sha256']?.toString().isNotEmpty ?? false)
            ? info['installed_host_sha256'].toString() : '—',
        },
      }.entries) AppFieldRow(label: field.key, child: SelectableText(field.value)),
      if (defaultTargetPlatform != TargetPlatform.android) const LText('components.updateHelp'),
    ]));
}
