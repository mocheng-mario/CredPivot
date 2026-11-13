import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';
import 'touch_id_gate.dart';

List<String> sshGitRules(TextEditingController controller) => controller.text.split('\n').map((v) => v.trim()).where((v) => v.isNotEmpty).toList();

Future<List<String>> normalizeGitTrustRepositories(List<String> repositories) async {
  final result = await AgentBridge.manage({'action': 'ssh_git_trust_normalize', 'repositories': repositories});
  return (result['repositories'] as List).cast<String>();
}

Future<List<String>?> chooseSshGitTrustRules(BuildContext context, List<String> repositories) async {
  final normalized = await AgentBridge.manage({'action': 'ssh_git_trust_normalize', 'repositories': repositories});
  final existing = (normalized['rules'] as List).cast<String>().toSet();
  final result = await AgentBridge.manage({'action': 'ssh_git_trust_candidates'});
  if (!context.mounted) return null;
  final candidates = (result['items'] as List).map((item) => Map<String, dynamic>.from(item as Map)).toList();
  final selected = <String>{};
  var query = '';
  return showDialog<List<String>>(
    context: context,
    builder: (ctx) => StatefulBuilder(builder: (ctx, update) {
      final visible = candidates.where((item) => '${item['rule']} ${(item['labels'] as List).join(' ')}'.toLowerCase().contains(query)).toList();
      return AlertDialog(
        title: const LText('ssh.git.trust.chooseTitle'),
        content: SizedBox(width: appEditDialogWidth(ctx), height: MediaQuery.sizeOf(ctx).height * .5,
          child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            const LText('ssh.git.trust.chooseHelp'),
            const SizedBox(height: 12),
            TextField(decoration: InputDecoration(hintText: tr('links.search'), prefixIcon: const Icon(Icons.search)),
              onChanged: (value) => update(() => query = value.trim().toLowerCase())),
            const SizedBox(height: 8),
            LText('ssh.git.trust.pendingCount', args: {'count': selected.length}),
            Expanded(child: visible.isEmpty
              ? Center(child: LText(candidates.isEmpty ? 'ssh.git.trust.noOrigins' : 'links.noMatches'))
              : ListView.builder(itemCount: visible.length, itemBuilder: (_, index) {
                  final item = visible[index];
                  final rule = item['rule'] as String;
                  final added = existing.contains(rule);
                  return CheckboxListTile(contentPadding: EdgeInsets.zero,
                    value: added || selected.contains(rule),
                    title: Text(rule),
                    subtitle: Text([if (added) tr('ssh.git.trust.alreadyAdded'), (item['labels'] as List).join('、')].join('\n')),
                    onChanged: added ? null : (checked) => update(() {
                      if (checked == true) { selected.add(rule); } else { selected.remove(rule); }
                    }),
                  );
                })),
          ])),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.cancel')),
          FilledButton(onPressed: selected.isEmpty ? null : () => Navigator.pop(ctx, selected.toList()), child: const LText('ssh.git.trust.addSelected')),
        ],
      );
    }),
  );
}

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
        AppPanel(title: 'ssh.git.integrationSection', subtitle: 'ssh.git.integrationHelp', icon: Icons.settings_ethernet,
          child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
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
        ])),
        const SizedBox(height: 16),
        AppPanel(title: 'ssh.git.bindings', subtitle: 'ssh.git.bindingsHelp', icon: Icons.key_outlined,
          child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        for (final raw in bindings) Builder(builder: (_) {
          final binding = Map<String, dynamic>.from(raw as Map);
          return ListTile(contentPadding: EdgeInsets.zero, title: Text(binding['remote']?.toString() ?? ''),
            subtitle: Text([binding['label']?.toString() ?? tr('ssh.git.missingKey'),
              tr(binding['scope']?.toString().startsWith('git-ssh:local:') == true ? 'ssh.git.source.localMemory' : 'ssh.git.source.remoteMemory'),
              binding['workspace']?.toString() ?? '',
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
        ])),
        if (error.isNotEmpty) LText(error, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
        if (busy) const LinearProgressIndicator(),
      ])), actions: [TextButton(onPressed: busy ? null : () => Navigator.pop(ctx), child: const LText('common.close'))],
  ))));
}
