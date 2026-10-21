import 'package:flutter/material.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';

/// 个人版 Chrome：开发者模式加载扩展，扩展 ID 变更后由用户自行更新并重装 Host。
class ChromeSetupTab extends StatefulWidget {
  const ChromeSetupTab(
      {super.key, required this.extensionIdController, this.busy = false});

  final TextEditingController extensionIdController;
  final bool busy;

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

  Future<void> _refresh() async {
    try {
      final host = await AgentBridge.chromeHostStatus();
      if (mounted) setState(() => _host = host);
    } catch (e) {
      if (mounted)
        setState(() => _message =
            '读取配置失败：${e is AgentException ? AgentBridge.diagnosticMessage(e) : '操作失败，请查看诊断日志'}');
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
            '$label 失败: ${e is AgentException ? AgentBridge.diagnosticMessage(e) : '操作失败，请查看诊断日志'}');
    } finally {
      if (mounted) setState(() => _working = false);
    }
  }

  Future<void> _installHost() async {
    final id = widget.extensionIdController.text.trim();
    if (id.isEmpty) {
      setState(() => _message = '请先填写当前 Chrome 里显示的扩展 ID');
      return;
    }
    await _run('安装 Host', () async {
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
            title: '让凭据随手可用',
            subtitle: '通过 Chrome 扩展保存与填充。首次使用按以下步骤完成本机配置。',
            icon: Icons.language_rounded,
            trailing: AppStatusBadge(configured ? '已配置' : '待配置',
                color: configured ? AppColors.green : AppColors.muted),
            child: Column(children: [
              _StepTile(
                step: 1,
                title: '加载浏览器扩展',
                detail: extDirOk
                    ? '打开扩展目录，在 Chrome 开启开发者模式，然后选择「加载已解压的扩展」。'
                    : '未找到扩展目录，请先完成应用构建或同步扩展产物。',
                ok: extDirOk,
              ),
              _StepTile(
                step: 2,
                title: '复制扩展 ID',
                detail: manifestId.isNotEmpty && !idMatch
                    ? '当前 Host 绑定的 ID 与已保存的 ID 不一致，请更新配置。'
                    : '在 Chrome 扩展卡片中复制 ID，并粘贴到下方。重新加载后请核对 ID。',
                ok: widget.extensionIdController.text.trim().isNotEmpty,
              ),
              _StepTile(
                step: 3,
                title: '完成本机连接配置',
                detail: configured
                    ? 'Native Host 与清单已安装。请在 Chrome 中重新加载扩展。'
                    : '保存扩展 ID，安装对应的 Native Host 配置。',
                ok: configured,
              ),
            ]),
          ),
          const SizedBox(height: 16),
          AppPanel(
            title: '扩展配置',
            icon: Icons.extension_outlined,
            child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  TextField(
                    controller: widget.extensionIdController,
                    decoration: const InputDecoration(
                        labelText: 'Chrome 扩展 ID',
                        hintText: '从 chrome://extensions 复制'),
                    onChanged: (_) => setState(() {}),
                  ),
                  if (stored.isNotEmpty &&
                      stored != widget.extensionIdController.text.trim())
                    const AppNotice('输入的 ID 与已保存配置不同。更新后将覆盖原配置。',
                        icon: Icons.info_outline_rounded),
                  const SizedBox(height: 14),
                  Wrap(spacing: 10, runSpacing: 10, children: [
                    FilledButton.icon(
                        onPressed: busy ? null : _installHost,
                        icon: const Icon(Icons.link_rounded),
                        label: Text(_working ? '处理中…' : '更新 Native Host')),
                    OutlinedButton.icon(
                      onPressed: () => _run('显示目录', () async {
                        final r = await AgentBridge.revealChromeExtensionDir();
                        if (mounted)
                          setState(
                              () => _message = r['message']?.toString() ?? '');
                      }),
                      icon: const Icon(Icons.folder_open_rounded),
                      label: const Text('显示扩展目录'),
                    ),
                    OutlinedButton.icon(
                      onPressed: () => _run('打开扩展页', () async {
                        final r = await AgentBridge.openChromeExtensionsPage();
                        if (mounted)
                          setState(
                              () => _message = r['message']?.toString() ?? '');
                      }),
                      icon: const Icon(Icons.open_in_new_rounded),
                      label: const Text('打开 Chrome 扩展页'),
                    ),
                    TextButton.icon(
                        onPressed: () => _run('刷新状态', _refresh),
                        icon: const Icon(Icons.refresh_rounded),
                        label: const Text('刷新')),
                  ]),
                  if (_working)
                    const Padding(
                        padding: EdgeInsets.only(top: 14),
                        child: LinearProgressIndicator(minHeight: 2)),
                  if (_message.isNotEmpty) AppNotice(_message),
                  const AppNotice(
                      '更新 Host 后请完全退出并重新打开 Chrome。使用扩展前，请保持本应用已启动，并用主密码解锁保险库。'),
                ]),
          ),
          const SizedBox(height: 16),
          Card(
              child: ExpansionTile(
            shape: const Border(),
            collapsedShape: const Border(),
            leading: const Icon(Icons.description_outlined),
            title: const Text('配置详情'),
            childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
            children: [
              Align(
                  alignment: Alignment.centerLeft,
                  child: SelectableText(
                    [
                      if (_host['extension_dir_path'] != null)
                        '扩展目录: ${_host['extension_dir_path']}',
                      'Host 清单: ${manifestOk ? "已安装" : "未安装"}',
                      'Native Host: ${hostBinOk ? "已就绪" : "缺失"}',
                      'Host 信任配置: ${trustedHostOk ? "已设置" : "缺失，请更新 Native Host"}',
                      'Host 版本: ${hostCurrent ? "与当前 App 一致" : "待更新"}',
                      '清单路径: ${hostPathMatch ? "与安装位置一致" : "待修复"}',
                      if (manifestId.isNotEmpty) '清单中的 ID: $manifestId',
                      if (stored.isNotEmpty) '已保存的 ID: $stored',
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
                    ? const Icon(Icons.check_rounded,
                        size: 17, color: AppColors.green)
                    : Text('$step',
                        style: const TextStyle(
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
