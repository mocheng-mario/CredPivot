import 'package:flutter/material.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'theme_color_picker.dart';
import 'android_diagnostics.dart';

class VaultSetupChoices extends StatelessWidget {
  const VaultSetupChoices({super.key, required this.onCreate, required this.onWebDav, required this.onRestore, required this.onSkip, this.busy = false});
  final VoidCallback onCreate, onWebDav, onRestore, onSkip;
  final bool busy;
  @override
  Widget build(BuildContext context) => Center(child: SingleChildScrollView(padding: const EdgeInsets.all(24), child: ConstrainedBox(
    constraints: const BoxConstraints(maxWidth: 580), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Icon(Icons.shield_outlined, size: 60, color: Theme.of(context).colorScheme.primary),
      const SizedBox(height: 24), LText('setup.title', textAlign: TextAlign.center, style: Theme.of(context).textTheme.headlineSmall),
      const SizedBox(height: 12), const LText('setup.description', textAlign: TextAlign.center),
      const SizedBox(height: 28),
      for (final option in [
        (Icons.add_rounded, 'setup.create', 'setup.createHelp', onCreate),
        (Icons.cloud_download_outlined, 'setup.webdav', 'setup.webdavHelp', onWebDav),
        (Icons.restore_rounded, 'setup.restore', 'setup.restoreHelp', onRestore),
      ]) ...[
        Card(child: ListTile(contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
          leading: Icon(option.$1, color: Theme.of(context).colorScheme.primary), title: LText(option.$2),
          subtitle: Padding(padding: const EdgeInsets.only(top: 6), child: LText(option.$3)),
          trailing: const Icon(Icons.chevron_right), onTap: busy ? null : option.$4)),
        const SizedBox(height: 10),
      ],
      TextButton(onPressed: busy ? null : onSkip, child: const LText('setup.skip')),
      if (busy) const LinearProgressIndicator(),
    ]))));
}

class UnconfiguredVaultPage extends StatefulWidget {
  const UnconfiguredVaultPage({super.key, required this.onSetup});
  final VoidCallback onSetup;
  @override
  State<UnconfiguredVaultPage> createState() => _UnconfiguredVaultPageState();
}

class _UnconfiguredVaultPageState extends State<UnconfiguredVaultPage> {
  bool busy = false;
  String error = '';
  Future<void> save(String key, Object value) async {
    if (busy) return;
    setState(() { busy = true; error = ''; });
    try {
      final status = AgentBridge.payloadOf(await AgentBridge.request({'type': 'status'}));
      if (status['vault_exists'] == true) throw AgentException('existing', tr('sync.bootstrap.existing'));
      final current = await AgentBridge.fetchAppSettings();
      final settings = Map<String, dynamic>.from(current['settings'] as Map)..[key] = value;
      final result = await AgentBridge.saveAppSettings(settings);
      AppPresentation.instance.apply(Map<String, dynamic>.from(result['settings'] as Map));
    } catch (problem) {
      if (mounted) setState(() => error = problem is AgentException ? tr(problem.message) : tr('common.operationFailed'));
    } finally { if (mounted) setState(() => busy = false); }
  }
  @override
  Widget build(BuildContext context) => ListView(padding: const EdgeInsets.all(24), children: [
    AppPanel(title: tr('setup.unconfigured'), subtitle: tr('setup.unconfiguredHelp'), icon: Icons.shield_outlined,
      child: FilledButton(onPressed: busy ? null : widget.onSetup, child: const LText('setup.continue'))),
    const SizedBox(height: 20),
    if (error.isNotEmpty) AppNotice(error),
    AppPanel(title: tr('android.settings.appearance'), icon: Icons.palette_outlined, child: appFieldRows([
      AppFieldRow(label: tr('android.settings.theme'), child: DropdownButtonFormField<String>(
        key: ValueKey(AppPresentation.instance.theme), initialValue: AppPresentation.instance.theme,
        items: const [DropdownMenuItem(value: 'system', child: LText('android.theme.system')), DropdownMenuItem(value: 'light', child: LText('android.theme.light')),
          DropdownMenuItem(value: 'dark', child: LText('android.theme.dark'))],
        onChanged: busy ? null : (value) { if (value != null) save('theme', value); })),
      AppFieldRow(label: tr('theme.colors.title'), child: OutlinedButton.icon(icon: const Icon(Icons.colorize_outlined),
        label: const LText('theme.colors.openPicker'), onPressed: busy ? null : () async {
          final color = await showThemeColorPicker(context, AppPresentation.instance.accentColor);
          if (mounted && color != null) await save('accent_color', color);
        })),
      AppFieldRow(label: tr('android.settings.language'), child: DropdownButtonFormField<String>(
        key: ValueKey(AppPresentation.instance.language), initialValue: AppPresentation.instance.names.containsKey(AppPresentation.instance.language) ? AppPresentation.instance.language : 'zh-CN',
        items: AppPresentation.instance.names.entries.map((entry) => DropdownMenuItem(value: entry.key, child: Text(entry.value))).toList(),
        onChanged: busy ? null : (value) { if (value != null) save('language', value); })),
    ])),
    const SizedBox(height: 16), OutlinedButton.icon(icon: const Icon(Icons.receipt_long_outlined), label: const LText('android.diagnostics.title'),
      onPressed: () => Navigator.push(context, MaterialPageRoute<void>(builder: (_) => const AndroidDiagnosticsPage(readOnly: true)))),
  ]);
}

Future<String?> askInitialBackupPassword(BuildContext context) async {
  final input = TextEditingController();
  final form = GlobalKey<FormState>();
  ModalRoute<String>? route;
  try {
    return await showDialog<String>(context: context, builder: (ctx) {
      route = ModalRoute.of<String>(ctx);
      return AlertDialog(title: const LText('setup.backupPassword'), content: Form(key: form, child: TextFormField(controller: input, obscureText: true, autofocus: true,
        autocorrect: false, enableSuggestions: false, enableIMEPersonalizedLearning: false,
        validator: (value) => (value ?? '').isEmpty ? tr('vault.recoverOvb.passwordRequired') : null,
        onSubmitted: (value) { if (form.currentState?.validate() == true) Navigator.pop(ctx, value); })),
        actions: [TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.cancel')),
          FilledButton(onPressed: () { if (form.currentState?.validate() == true) Navigator.pop(ctx, input.text); }, child: const LText('common.continue'))]);
    });
  } finally { await route?.completed; input.dispose(); }
}
