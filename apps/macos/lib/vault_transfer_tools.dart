import 'package:flutter/material.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';

enum VaultTransferTool {
  exportJson, importJson, verifyRecovery, resetRecovery;
  String get label => 'vaultTools.maintenance.$name';
}

Future<void> showVaultTransferTool(BuildContext context, VaultTransferTool tool, {required ValueChanged<String> onRecoveryKey}) async {
  final password = TextEditingController();
  final repeat = TextEditingController();
  final recovery = TextEditingController();
  final importing = tool == VaultTransferTool.importJson;
  final verifying = tool == VaultTransferTool.verifyRecovery;
  final resetting = tool == VaultTransferTool.resetRecovery;
  var busy = false, saved = false;
  String error = '', result = '', newKey = '';
  ModalRoute<void>? route;
  try {
    await showDialog<void>(context: context, barrierDismissible: false, builder: (ctx) {
      route ??= ModalRoute.of<void>(ctx);
      return StatefulBuilder(builder: (ctx, update) {
        Future<void> submit() async {
          if (busy) return;
          if ((!verifying && password.text.isEmpty) || ((verifying || resetting) && recovery.text.trim().isEmpty)) {
            update(() => error = tr('vaultTools.maintenance.required')); return;
          }
          if (importing && (password.text.characters.length < 8 || password.text != repeat.text)) {
            update(() => error = tr('vaultTools.maintenance.passwordMismatch')); return;
          }
          final secret = password.text;
          final oldKey = recovery.text.trim();
          update(() { busy = true; error = ''; });
          try {
            if (tool == VaultTransferTool.exportJson) {
              final path = await AgentBridge.pickSaveFile('credpivot-plaintext.json');
              if (path == null || !ctx.mounted) return;
              await AgentBridge.request({'type': 'vault_export_json', 'output_path': path, 'password': secret});
              if (ctx.mounted) update(() => result = path);
            } else if (importing) {
              final input = await AgentBridge.pickOpenFile();
              if (input == null || !ctx.mounted) return;
              final target = await AgentBridge.pickDirectory();
              if (target == null || !ctx.mounted) return;
              final response = AgentBridge.payloadOf(await AgentBridge.request({
                'type': 'vault_import_json', 'input_path': input, 'target_dir': target, 'password': secret,
              }));
              onRecoveryKey(response['new_recovery_key'].toString());
              if (ctx.mounted) update(() { newKey = response['new_recovery_key'].toString(); result = target; });
            } else if (verifying) {
              await AgentBridge.verifyRecoveryKey(oldKey);
              AgentBridge.notifyVaultChanged();
              if (ctx.mounted) update(() => result = tr('vaultTools.maintenance.verified'));
            } else {
              final response = AgentBridge.payloadOf(await AgentBridge.request({
                'type': 'vault_reset_recovery_key', 'password': secret, 'recovery_key': oldKey,
              }));
              onRecoveryKey(response['new_recovery_key'].toString());
              AgentBridge.notifyVaultChanged();
              if (ctx.mounted) update(() { newKey = response['new_recovery_key'].toString(); result = tr('vaultTools.maintenance.resetDone'); });
            }
            if (ctx.mounted && result.isNotEmpty) { password.clear(); repeat.clear(); recovery.clear(); }
          } catch (e) {
            if (ctx.mounted) update(() => error = e is AgentException ? AgentBridge.friendlyMessage(e) : tr('common.operationFailed'));
          } finally {
            if (ctx.mounted) update(() => busy = false);
          }
        }
        return PopScope(canPop: !busy && (newKey.isEmpty || saved), child: AlertDialog(
          title: LText(tool.label),
          content: SizedBox(width: 520, child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            LText('vaultTools.maintenance.${tool.name}Help'),
            const SizedBox(height: 16),
            if (result.isEmpty) ...[
              if (!verifying) ...[
                AppFieldRow(label: tr(importing ? 'vaultTools.maintenance.newPassword' : 'vault.vaultOverview.text.item19'), child: TextField(
                  controller: password, obscureText: true, enabled: !busy, decoration: const InputDecoration())),
                const SizedBox(height: 12),
              ],
              if (importing) ...[
                AppFieldRow(label: tr('vaultTools.maintenance.repeatPassword'), child: TextField(
                  controller: repeat, obscureText: true, enabled: !busy, decoration: const InputDecoration())),
                const SizedBox(height: 12),
              ],
              if (verifying || resetting) AppFieldRow(label: tr('vault.fields.recoveryKey'), child: TextField(
                controller: recovery, obscureText: true, enabled: !busy, decoration: const InputDecoration())),
            ] else ...[
              LText('vaultTools.maintenance.completed'), SelectableText(result),
              if (newKey.isNotEmpty) ...[
                const SizedBox(height: 16),
                const LText('vaultTools.maintenance.saveKey'),
                SelectableText(newKey),
                CheckboxListTile(contentPadding: EdgeInsets.zero, value: saved,
                  onChanged: (v) => update(() { saved = v == true; onRecoveryKey(saved ? '' : newKey); }), title: const LText('vaultTools.maintenance.savedKey')),
              ],
            ],
            if (error.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 12), child: Text(error, style: TextStyle(color: Theme.of(ctx).colorScheme.error))),
          ]))),
          actions: [
            TextButton(onPressed: busy || (newKey.isNotEmpty && !saved) ? null : () => Navigator.pop(ctx),
              child: LText(result.isEmpty ? 'common.cancel' : 'common.close')),
            if (result.isEmpty) FilledButton(onPressed: busy ? null : submit,
              child: LText(busy ? 'common.saving' : tool.label)),
          ],
        ));
      });
    });
    await route?.completed;
  } finally { password.dispose(); repeat.dispose(); recovery.dispose(); }
}
