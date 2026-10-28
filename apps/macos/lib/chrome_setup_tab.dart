import 'package:flutter/material.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';

/// 个人版 Chrome：开发者模式加载扩展，扩展 ID 变更后由用户自行更新并重装 Host。
class ChromeSetupTab extends StatefulWidget {
  const ChromeSetupTab(
      {super.key, required this.extensionIdController, required this.onOpenSettings,
      this.active = true, this.busy = false});

  final TextEditingController extensionIdController;
  final bool busy;
  final bool active;
  final VoidCallback onOpenSettings;

  @override
  State<ChromeSetupTab> createState() => _ChromeSetupTabState();
}

class _ChromeSetupTabState extends State<ChromeSetupTab> {
  Map<String, dynamic> _host = {};
  String _message = '';
  bool _working = false;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  @override
  void didUpdateWidget(covariant ChromeSetupTab oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.active && !oldWidget.active) _refresh();
  }

  Future<void> _refresh() async {
    try {
      final host = await AgentBridge.chromeHostStatus();
      if (mounted) setState(() {
        _host = host;
        widget.extensionIdController.text = host['stored_extension_id']?.toString() ?? '';
      });
    } catch (e) {
      if (mounted)
        setState(() => _message =
            tr('browser.errors.readConfiguration', args: {'error': e is AgentException ? AgentBridge.diagnosticMessage(e) : tr('diagnostics.labels.text')}));
    }
  }

  Future<void> _run(String label, Future<void> Function() action) async {
    if (_working || !mounted) return;
    setState(() => _working = true);
    try {
      await action();
    } catch (e) {
      if (mounted)
        setState(() => _message =
            tr('browser.status.operationFailed', args: {'label': label, 'error': e is AgentException ? AgentBridge.diagnosticMessage(e) : tr('diagnostics.labels.text')}));
    } finally {
      if (mounted) setState(() => _working = false);
    }
  }

  Future<void> _installHost() async {
    final id = widget.extensionIdController.text.trim();
    if (id.isEmpty) {
      setState(() => _message = tr('browser.installHost.status'));
      return;
    }
    await _run(tr('browser.installHost.text'), () async {
      final r = await AgentBridge.installChromeHost(id);
      if (!mounted) return;
      setState(() {
        _message = r['message']?.toString() ?? r.toString();
      });
      await _refresh();
    });
  }

  @override
  Widget build(BuildContext context) {
    final manifestOk = _host['manifest_exists'] == true;
    final hostBinOk = _host['installed_host_exists'] == true;
    final extDirOk = _host['extension_dir_exists'] == true;
    final idMatch = _host['host_id_matches_manifest'] == true;
    final trustedHostOk = _host['trusted_host_configured'] == true;
    final hostCurrent = _host['installed_host_current'] == true;
    final hostPathMatch = _host['manifest_host_matches_installed'] == true;
    final stored = _host['stored_extension_id']?.toString() ?? '';
    final manifestId = _host['manifest_extension_id']?.toString() ?? '';
    final configured = manifestOk &&
        hostBinOk &&
        idMatch &&
        trustedHostOk &&
        hostCurrent &&
        hostPathMatch;
    final busy = widget.busy || _working;

    return AbsorbPointer(
      absorbing: busy,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(24, 6, 24, 24),
        children: [
          AppPanel(
            title: tr('browser.build.title'),
            subtitle: tr('browser.build.description'),
            icon: Icons.language_rounded,
            trailing: AppStatusBadge(configured ? tr('browser.build.text') : tr('browser.build.text.item2'),
                color: configured ? AppColors.green : AppColors.muted),
            child: Column(children: [
              _StepTile(
                step: 1,
                title: tr('browser.build.title.item2'),
                detail: extDirOk
                    ? tr('browser.build.text.item3')
                    : tr('browser.build.text.item4'),
                ok: extDirOk,
              ),
              _StepTile(
                step: 2,
                title: tr('browser.build.title.item3'),
                detail: manifestId.isNotEmpty && !idMatch
                    ? tr('browser.build.text.item5')
                    : tr('browser.build.text.item6'),
                ok: widget.extensionIdController.text.trim().isNotEmpty,
              ),
              _StepTile(
                step: 3,
                title: tr('browser.build.title.item4'),
                detail: configured
                    ? tr('browser.build.text.item7')
                    : tr('browser.build.text.item8'),
                ok: configured,
              ),
            ]),
          ),
          const SizedBox(height: 16),
          AppPanel(
            title: tr('browser.build.title.item5'),
            icon: Icons.extension_outlined,
            child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  AppFieldRow(label: tr('browser.build.text.item9'), child: TextField(
                    controller: widget.extensionIdController,
                    readOnly: true,
                    decoration: InputDecoration(hintText: tr('browser.build.text.item10')),
                  )),
                  const SizedBox(height: 14),
                  Wrap(spacing: 10, runSpacing: 10, children: [
                    OutlinedButton.icon(
                        onPressed: widget.onOpenSettings,
                        icon: const Icon(Icons.settings_outlined),
                        label: const LText('common.openSettings')),
                    FilledButton.icon(
                        onPressed: busy ? null : _installHost,
                        icon: const Icon(Icons.link_rounded),
                        label: LText(_working ? tr('common.processing') : tr('browser.build.text.item11'))),
                    OutlinedButton.icon(
                      onPressed: () => _run(tr('browser.build.text.item12'), () async {
                        final r = await AgentBridge.revealChromeExtensionDir();
                        if (mounted)
                          setState(
                              () => _message = r['message']?.toString() ?? '');
                      }),
                      icon: const Icon(Icons.folder_open_rounded),
                      label: const LText('browser.build.text.item13'),
                    ),
                    OutlinedButton.icon(
                      onPressed: () => _run(tr('browser.build.text.item14'), () async {
                        final r = await AgentBridge.openChromeExtensionsPage();
                        if (mounted)
                          setState(
                              () => _message = r['message']?.toString() ?? '');
                      }),
                      icon: const Icon(Icons.open_in_new_rounded),
                      label: const LText('browser.build.text.item15'),
                    ),
                    TextButton.icon(
                        onPressed: () => _run(tr('browser.build.text.item16'), _refresh),
                        icon: const Icon(Icons.refresh_rounded),
                        label: const LText('common.refresh')),
                  ]),
                  if (_working)
                    const Padding(
                        padding: EdgeInsets.only(top: 14),
                        child: LinearProgressIndicator(minHeight: 2)),
                  if (_message.isNotEmpty) AppNotice(_message),
                  AppNotice(
                      tr('browser.build.text.item17')),
                ]),
          ),
          const SizedBox(height: 16),
          Card(
              child: ExpansionTile(
            shape: const Border(),
            collapsedShape: const Border(),
            leading: const Icon(Icons.description_outlined),
            title: const LText('browser.build.text.item18'),
            childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
            children: [
              Align(
                  alignment: Alignment.centerLeft,
                  child: SelectableText(
                    [
                      if (_host['extension_dir_path'] != null)
                        tr('browser.details.extensionDirectory', args: {'path': _host['extension_dir_path']}),
                      tr('browser.details.hostManifest', args: {'path': manifestOk ? tr('browser.labels.text') : tr('browser.labels.text.item2')}),
                      'Native Host: ${hostBinOk ? tr('browser.labels.text.item3') : tr('browser.labels.text.item4')}',
                      tr('browser.details.hostTrust', args: {'path': trustedHostOk ? tr('browser.labels.text.item5') : tr('browser.labels.text.item6')}),
                      tr('browser.details.hostVersion', args: {'version': hostCurrent ? tr('browser.labels.text.item7') : tr('browser.labels.text.item8')}),
                      tr('browser.details.manifestPath', args: {'path': hostPathMatch ? tr('browser.labels.text.item9') : tr('browser.labels.text.item10')}),
                      if (manifestId.isNotEmpty) tr('browser.details.manifestExtensionId', args: {'extensionId': manifestId}),
                      if (stored.isNotEmpty) tr('browser.details.savedExtensionId', args: {'extensionId': stored}),
                    ].join('\n'),
                    style: const TextStyle(
                        fontSize: 12, fontFamily: 'monospace', height: 1.7),
                  ))
            ],
          )),
        ],
      ),
    );
  }
}

class _StepTile extends StatelessWidget {
  const _StepTile(
      {required this.step,
      required this.title,
      required this.detail,
      required this.ok});

  final int step;
  final String title;
  final String detail;
  final bool ok;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 10),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Container(
            width: 30,
            height: 30,
            decoration: BoxDecoration(
                color: ok
                    ? AppColors.green.withValues(alpha: 0.08)
                    : AppColors.background,
                borderRadius: BorderRadius.circular(10)),
            child: Center(
                child: ok
                    ? Icon(Icons.check_rounded,
                        size: 17, color: AppColors.green)
                    : LText('$step',
                        style: TextStyle(
                            color: AppColors.muted,
                            fontWeight: FontWeight.w600))),
          ),
          const SizedBox(width: 14),
          Expanded(
              child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                Text(title, style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 4),
                Text(detail, style: Theme.of(context).textTheme.bodySmall),
              ])),
        ]),
      );
}
