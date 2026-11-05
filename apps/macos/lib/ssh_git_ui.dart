import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';
import 'touch_id_gate.dart';

List<String> sshGitRules(TextEditingController controller) => controller.text.split('\n').map((v) => v.trim()).where((v) => v.isNotEmpty).toList();

class SshGitRulesField extends StatefulWidget {
  const SshGitRulesField({super.key, required this.controller, this.enabled = true});
  final TextEditingController controller;
  final bool enabled;
  @override
  State<SshGitRulesField> createState() => _SshGitRulesFieldState();
}

class _SshGitRulesFieldState extends State<SshGitRulesField> {
  final target = TextEditingController();
  Timer? timer;
  int generation = 0;
  String error = '';
  List<String> normalized = [];
  bool? matches;
  @override
  void initState() { super.initState(); widget.controller.addListener(changed); changed(); }
  void changed() {
    timer?.cancel(); final epoch = ++generation;
    timer = Timer(const Duration(milliseconds: 300), () async {
      try {
        final value = await AgentBridge.manage({'action': 'ssh_git_rules_test', 'rules': sshGitRules(widget.controller), 'target': target.text});
        if (mounted && epoch == generation) setState(() { normalized = (value['rules'] as List).cast<String>(); matches = value['matches'] as bool?; error = ''; });
      } catch (e) { if (mounted && epoch == generation) setState(() { error = e is AgentException ? e.message.replaceFirst('invalid format: ', '') : 'common.operationFailed'; matches = null; normalized = []; }); }
    });
  }
  @override
  void dispose() { ++generation; timer?.cancel(); widget.controller.removeListener(changed); target.dispose(); super.dispose(); }
  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
    AppFieldRow(label: tr('ssh.git.rules'), help: tr('ssh.git.rulesHelp'), child: TextField(controller: widget.controller, enabled: widget.enabled,
      minLines: 2, maxLines: 5, decoration: InputDecoration(hintText: tr('ssh.git.rulesHint')))),
    if (normalized.isNotEmpty) Padding(padding: const EdgeInsets.symmetric(vertical: 8), child: SelectableText(tr('ssh.git.normalized', args: {'rules': normalized.join('\n')}))),
    AppFieldRow(label: tr('ssh.git.testTarget'), child: TextField(controller: target, enabled: widget.enabled,
      decoration: InputDecoration(hintText: tr('ssh.git.testHint')), onChanged: (_) => changed())),
    if (matches != null) LText(matches! ? 'ssh.git.matches' : 'ssh.git.noMatch'),
    if (error.isNotEmpty) LText(error, style: TextStyle(color: Theme.of(context).colorScheme.error)),
  ]);
}

Future<void> showGitSshSettings(BuildContext context) async {
  if (!Platform.isMacOS) return;
  const channel = MethodChannel('credpivot/agent');
  var status = <String, dynamic>{};
  List bindings = [];
  String error = '';
  try {
    status = Map<String, dynamic>.from(await channel.invokeMethod<Map>('gitSshStatus') ?? {});
    bindings = (await AgentBridge.manage({'action': 'ssh_git_bindings'}))['items'] as List? ?? [];
    error = status['error']?.toString() ?? '';
  } catch (e) { error = e is AgentException ? e.message : 'ssh.git.configureFailed'; }
  if (!context.mounted) return;
  var busy = false;
  await showDialog<void>(context: context, barrierDismissible: false, builder: (ctx) => StatefulBuilder(builder: (ctx, update) => PopScope(
    canPop: !busy, child: AlertDialog(title: const LText('ssh.git.settings'), content: SizedBox(width: appEditDialogWidth(ctx),
      height: MediaQuery.sizeOf(ctx).height * .6, child: ListView(children: [
        const LText('ssh.git.integrationHelp'), const SizedBox(height: 12),
        LText(status['enabled'] == true ? 'ssh.git.enabled' : 'ssh.git.disabled'),
        if (status['current'] is String && (status['current'] as String).isNotEmpty) SelectableText(tr('ssh.git.current', args: {'command': status['current']})),
        if (status['backup'] is String && (status['backup'] as String).isNotEmpty) SelectableText(tr('ssh.git.backup', args: {'path': status['backup']})),
        const SizedBox(height: 12), FilledButton(onPressed: busy ? null : () async {
          update(() { busy = true; error = ''; });
          try {
            final enable = status['enabled'] != true;
            if (!await confirmCredentialDanger(ctx, title: tr('ssh.git.settings'), message: tr(enable ? 'ssh.git.enableConfirm' : 'ssh.git.disableConfirm'), confirmLabel: 'common.continue')) return;
            if (!ctx.mounted || !await requireTouchId(ctx, reason: tr('ssh.git.settings'), confirmed: true)) return;
            status = Map<String, dynamic>.from(await channel.invokeMethod<Map>('gitSshConfigure', enable) ?? {});
          } catch (e) { error = e is PlatformException ? e.message ?? 'ssh.git.configureFailed' : e is AgentException ? e.message : 'ssh.git.configureFailed'; }
          finally { if (ctx.mounted) update(() => busy = false); }
        }, child: LText(status['enabled'] == true ? 'ssh.git.disable' : 'ssh.git.enable')),
        const SizedBox(height: 20), const LText('ssh.git.bindings'), const LText('ssh.git.bindingsHelp'),
        for (final raw in bindings) Builder(builder: (_) {
          final binding = Map<String, dynamic>.from(raw as Map);
          return ListTile(contentPadding: EdgeInsets.zero, title: Text(binding['remote']?.toString() ?? ''),
            subtitle: Text([binding['label']?.toString() ?? tr('ssh.git.missingKey'), binding['workspace']?.toString() ?? '',
              if (binding['reselect'] == true) tr('ssh.git.rechoosePending')].where((v) => v.isNotEmpty).join('\n')),
            trailing: PopupMenuButton<String>(enabled: !busy, onSelected: (action) async {
              update(() { busy = true; error = ''; });
              try {
                if (!await confirmCredentialDanger(ctx, title: tr(action == 'ssh_git_rechoose' ? 'ssh.git.rechoose' : 'ssh.git.forget'),
                  message: tr(action == 'ssh_git_rechoose' ? 'ssh.git.rechooseConfirm' : 'ssh.git.forgetConfirm'), confirmLabel: 'common.continue')) return;
                if (!ctx.mounted || !await requireTouchId(ctx, reason: tr(action == 'ssh_git_rechoose' ? 'ssh.git.rechoose' : 'ssh.git.forget'), confirmed: true)) return;
                await AgentBridge.manage({'action': action, 'scope': binding['scope']});
                bindings = (await AgentBridge.manage({'action': 'ssh_git_bindings'}))['items'] as List? ?? [];
              } catch (e) { error = e is AgentException ? e.message : 'common.operationFailed'; }
              finally { if (ctx.mounted) update(() => busy = false); }
            }, itemBuilder: (_) => const [PopupMenuItem(value: 'ssh_git_rechoose', child: LText('ssh.git.rechoose')),
              PopupMenuItem(value: 'ssh_git_forget', child: LText('ssh.git.forget'))]));
        }),
        if (bindings.isEmpty) const LText('ssh.git.noBindings'),
        if (error.isNotEmpty) LText(error, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
        if (busy) const LinearProgressIndicator(),
      ])), actions: [TextButton(onPressed: busy ? null : () => Navigator.pop(ctx), child: const LText('common.close'))],
  ))));
}
