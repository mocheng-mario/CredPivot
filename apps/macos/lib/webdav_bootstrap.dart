import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'android_webdav.dart';
import 'webdav_sync.dart';

enum WebDavBootstrapOutcome { opened, createNew }

Future<WebDavBootstrapOutcome?> openWebDavBootstrap(BuildContext context) async {
  final values = await WebDavSyncPage.configurationDraft(context, bootstrap: true);
  if (values == null) return null;
  try {
    if (!context.mounted) return null;
    return await showDialog<WebDavBootstrapOutcome>(context: context, barrierDismissible: false,
      builder: (_) => _BootstrapDialog(draft: values));
  } finally { values['password'] = ''; }
}

class _BootstrapDialog extends StatefulWidget {
  const _BootstrapDialog({required this.draft});
  final Map<String, dynamic> draft;
  @override
  State<_BootstrapDialog> createState() => _BootstrapDialogState();
}

class _BootstrapDialogState extends State<_BootstrapDialog> {
  static const channel = MethodChannel('credpivot/agent');
  final master = TextEditingController(), host = TextEditingController();
  Map<String, dynamic> remote = {}, preview = {};
  String error = '', warning = '', progress = '';
  bool busy = false, opening = false, opened = false, connected = false, cancelling = false;
  int generation = 0;
  String? restoredPath;
  Map<String, dynamic> get draft => widget.draft;

  Future<Map<String, dynamic>> native(String method, [Map<String, dynamic>? args]) async {
    if (Platform.isAndroid) return AndroidWebDav.instance.invoke(method, args);
    return Map<String, dynamic>.from(await channel.invokeMethod<Map>(method, args) ?? {});
  }
  Future<Map<String, dynamic>> agent(Map<String, dynamic> args) async => AgentBridge.payloadOf(await AgentBridge.request(args));

  String message(Object problem) {
    final reason = problem is AgentException ? tr(problem.message.replaceFirst('invalid format: ', '')) :
      problem is PlatformException ? problem.message ?? tr(problem.code) : tr('sync.errors.operation');
    final details = problem is AgentException ? problem.details : null;
    final record = details?['record'];
    if (record is! Map) return reason;
    final label = [record['title'], record['account']].whereType<String>().where((v) => v.trim().isNotEmpty).join(' · ');
    return tr('sync.bootstrap.recordError', args: {'record': label.isEmpty ? record['id']?.toString() ?? '' : label, 'reason': reason});
  }

  @override
  void initState() { super.initState(); load(); }

  Future<void> load() async {
    if (busy || opened) return;
    final epoch = ++generation;
    setState(() { busy = true; error = ''; preview = {}; remote = {}; progress = 'sync.bootstrap.reading'; });
    try {
      await agent({'type': 'sync_bootstrap_cancel'});
      final value = await native('webdavBootstrapRead', draft);
      if (mounted && epoch == generation) setState(() => remote = value);
    } catch (problem) { if (mounted && epoch == generation) setState(() => error = message(problem)); }
    finally { if (mounted && epoch == generation) setState(() { busy = false; progress = ''; }); }
  }

  Future<void> decrypt() async {
    if (busy || remote['remote_ovb'] is! String || master.text.isEmpty) return;
    final epoch = ++generation;
    setState(() { busy = true; error = ''; progress = 'sync.bootstrap.decrypting'; });
    try {
      final value = await agent({'type': 'sync_bootstrap_prepare', 'head': remote['head'], 'location': remote['location'],
        'remote_ovb': remote['remote_ovb'], 'password': master.text});
      if (mounted && epoch == generation) setState(() { preview = value; remote.remove('remote_ovb'); });
    } catch (problem) { if (mounted && epoch == generation) setState(() => error = message(problem)); }
    finally { if (mounted && epoch == generation) setState(() { busy = false; progress = ''; }); }
  }

  dynamic sorted(dynamic value) {
    if (value is Map) { final keys = value.keys.cast<String>().toList()..sort(); return {for (final key in keys) key: sorted(value[key])}; }
    if (value is List) return value.map(sorted).toList();
    return value;
  }

  Future<void> open() async {
    if (busy || preview['plan_id'] is! String) return;
    final epoch = ++generation;
    final secret = master.text;
    setState(() { busy = true; opening = true; error = ''; warning = ''; progress = 'sync.bootstrap.opening'; });
    try {
      if (restoredPath == null) {
        // 确认前重读入口；无 ETag 的只读服务器也必须比较完整入口，不能凭文件名猜测版本。
        final current = await native('webdavBootstrapRead', {...draft, if (remote['etag'] is String) 'etag': remote['etag']});
        if (!mounted || epoch != generation) return;
        if (current['not_modified'] != true && jsonEncode(sorted(current['head'])) != jsonEncode(sorted(remote['head']))) {
          await agent({'type': 'sync_bootstrap_cancel'});
          setState(() { preview = {}; remote = current; });
          throw AgentException('remote_changed', tr('sync.bootstrap.changed'));
        }
        final restored = await agent({'type': 'sync_bootstrap_apply', 'plan_id': preview['plan_id']});
        restoredPath = restored['target_dir'] as String;
      }
      if (!mounted || epoch != generation) return;
      await AgentBridge.vaultOpenDir(restoredPath!);
      if (!mounted || epoch != generation) return;
      if (!await AgentBridge.unlockWithPassword(secret)) {
        throw AgentException('bad_unlock', tr('sync.bootstrap.openFailed'));
      }
      if (!mounted || epoch != generation) return;
      opened = true;
      try { await AgentBridge.setSyncHostName(host.text.trim()); }
      catch (problem) { warning = message(problem); }
      if (!mounted || epoch != generation) return;
      setState(() => progress = 'sync.bootstrap.connecting');
      try {
        // 验证成功的主密码授权覆盖本次初始化；传输认证始终使用独立的 WebDAV 密码。
        await native('webdavSave', {...draft, 'verify': true});
        if (!mounted || epoch != generation) return;
        await agent({'type': 'sync_bootstrap_finish', 'head': remote['head'], 'location': remote['location']});
        connected = true;
      } catch (problem) {
        warning = [warning, tr('sync.bootstrap.offlineReason', args: {'reason': message(problem)})].where((v) => v.isNotEmpty).join('\n');
      }
      if (mounted) master.clear();
    } catch (problem) { if (mounted && epoch == generation) setState(() => error = message(problem)); }
    finally { if (mounted && epoch == generation) setState(() { busy = false; opening = false; progress = ''; }); }
  }

  Future<void> cancel() async {
    if (opening || cancelling) return;
    setState(() => cancelling = true);
    ++generation;
    try { await native('webdavCancel'); }
    catch (_) { /* 取消网络失败也应释放本地待恢复计划。 */ }
    try { await agent({'type': 'sync_bootstrap_cancel'}); }
    catch (_) { /* 关闭窗口时的清理还有 dispose 兜底，失败不阻止用户退出。 */ }
    finally { if (mounted) Navigator.pop(context); }
  }

  Future<void> reconfigure() async {
    if (busy || opened) return;
    final next = await WebDavSyncPage.configurationDraft(context, bootstrap: true, initialSettings: draft);
    if (next == null || !mounted) return;
    draft['password'] = ''; draft.clear(); draft.addAll(next);
    master.clear(); await load();
  }

  @override
  void dispose() {
    ++generation;
    if (busy) native('webdavCancel').catchError((Object _) => <String, dynamic>{});
    agent({'type': 'sync_bootstrap_cancel'}).catchError((Object _) => <String, dynamic>{});
    master.dispose(); host.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final counts = preview['counts'] as Map? ?? {};
    const kinds = {'login': 'login', 'totp': 'mfa', 'ssh': 'ssh', 'ssh_key': 'ssh', 'server_login': 'server', 'passkey': 'passkey',
      'recovery_codes': 'recovery', 'secure_note': 'note', 'trash': 'trash'};
    return PopScope(canPop: !opening && !busy && !cancelling, child: AppEditDialog(
      title: LText(opened ? 'sync.bootstrap.opened' : 'sync.bootstrap.title'),
      content: SizedBox(width: appEditDialogWidth(context), child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          if (busy) ...[const LinearProgressIndicator(), const SizedBox(height: 12), LText(progress), const SizedBox(height: 12)],
          if (error.isNotEmpty) AppNotice(error),
          if (warning.isNotEmpty) AppNotice(warning),
          if (opened) ...[
            LText(connected ? 'sync.bootstrap.connected' : 'sync.bootstrap.offline'),
            const SizedBox(height: 12), SelectableText(restoredPath ?? ''),
          ] else if (remote['empty'] == true) ...[
            const LText('sync.bootstrap.empty'),
            const SizedBox(height: 12), OutlinedButton(onPressed: busy || cancelling ? null : () => Navigator.pop(context, WebDavBootstrapOutcome.createNew),
              child: const LText('setup.create')),
          ] else if (preview.isNotEmpty) ...[
            const LText('sync.bootstrap.previewHelp'),
            const SizedBox(height: 12), LText('sync.bootstrap.identity', args: {'id': preview['vault_id'] ?? ''}),
            if ((preview['host_name']?.toString() ?? '').isNotEmpty) LText('sync.bootstrap.publisher', args: {'host': preview['host_name']}),
            if (remote['modified'] is String) LText('sync.bootstrap.modified', args: {'time': remote['modified']}),
            const SizedBox(height: 16),
            for (final entry in counts.entries) ListTile(dense: true, contentPadding: EdgeInsets.zero,
              title: LText(entry.key == 'trash' ? 'credentials.trash.title' : 'sync.itemType.${kinds[entry.key] ?? 'record'}'), trailing: Text(entry.value.toString())),
            AppFieldRow(label: tr('vault.syncHost.label'), help: tr('vault.syncHost.help'), child: TextField(controller: host, enabled: !busy, maxLength: 128)),
          ] else if (remote['head'] is Map) ...[
            const LText('sync.bootstrap.passwordHelp'),
            const SizedBox(height: 12), TextField(controller: master, obscureText: true, enabled: !busy, autofocus: true,
              autocorrect: false, enableSuggestions: false, enableIMEPersonalizedLearning: false,
              decoration: InputDecoration(labelText: tr('sync.initial.remotePassword')), onSubmitted: (_) => decrypt()),
          ],
        ]))),
      actions: [
        if (!opened) TextButton(onPressed: opening || cancelling ? null : cancel, child: const LText('common.cancel')),
        if (!opened && !busy) TextButton(onPressed: cancelling ? null : reconfigure, child: const LText('sync.bootstrap.reconfigure')),
        if (!opened && !busy && remote['head'] is! Map) TextButton(onPressed: cancelling ? null : load, child: const LText('sync.bootstrap.reload')),
        if (!opened && preview.isEmpty && remote['head'] is Map) FilledButton(onPressed: busy || cancelling ? null : decrypt, child: const LText('sync.bootstrap.decrypt')),
        if (!opened && preview.isNotEmpty) ...[
          TextButton(onPressed: busy || cancelling ? null : load, child: const LText('sync.bootstrap.reload')),
          FilledButton(onPressed: busy || cancelling ? null : open, child: const LText('sync.bootstrap.open')),
        ],
        if (opened) FilledButton(onPressed: busy ? null : () => Navigator.pop(context, WebDavBootstrapOutcome.opened), child: const LText('common.close')),
      ],
    ));
  }
}
