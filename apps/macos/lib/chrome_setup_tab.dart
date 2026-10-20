import 'package:flutter/material.dart';

import 'agent_bridge.dart';

/// 个人版 Chrome：开发者模式加载扩展，扩展 ID 变更后由用户自行更新并重装 Host。
class ChromeSetupTab extends StatefulWidget {
  const ChromeSetupTab({super.key, required this.extensionIdController, this.busy = false});

  final TextEditingController extensionIdController;
  final bool busy;

  @override
  State<ChromeSetupTab> createState() => _ChromeSetupTabState();
}

class _ChromeSetupTabState extends State<ChromeSetupTab> {
  Map<String, dynamic> _host = {};
  String _message = '';

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    final host = await AgentBridge.chromeHostStatus();
    if (!mounted) return;
    setState(() => _host = host);
  }

  Future<void> _run(String label, Future<void> Function() action) async {
    try {
      await action();
    } catch (e) {
      setState(() => _message = '$label 失败: $e');
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
    final idMatch = _host['host_id_matches_manifest'] != false;
    final stored = _host['stored_extension_id']?.toString() ?? '';
    final manifestId = _host['manifest_extension_id']?.toString() ?? '';

    return AbsorbPointer(
      absorbing: widget.busy,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: ListView(
          children: [
            Text('Chrome（开发者模式）', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            const Text(
              '不上架商店时，扩展 ID 会在重新「加载已解压的扩展」后变化。'
              '请在 chrome://extensions 复制新 ID，粘贴到下方并点击「更新 Native Host」。'
              '本应用不会固定或预置扩展 ID。',
              style: TextStyle(fontSize: 13, color: Colors.black87),
            ),
            const SizedBox(height: 16),
            _StepTile(
              step: 1,
              title: '在 Chrome 加载扩展',
              detail: extDirOk
                  ? '扩展目录已就绪，可在 Finder 中打开后选择「加载已解压的扩展」。'
                  : '未找到扩展目录，请先 make macos-build / macos-sync-artifacts。',
              ok: extDirOk,
            ),
            _StepTile(
              step: 2,
              title: '复制扩展 ID',
              detail: manifestId.isNotEmpty && !idMatch
                  ? 'Host 当前绑定: $manifestId；与下方输入不一致，填充会失败。'
                  : '开发者模式下，每个扩展卡片上有 ID（可点复制）。',
              ok: widget.extensionIdController.text.trim().isNotEmpty,
            ),
            _StepTile(
              step: 3,
              title: '更新 Native Host',
              detail: manifestOk && hostBinOk && idMatch
                  ? 'manifest 与 Host 二进制已安装。'
                  : '将 allowed_origins 写入 Chrome Native Messaging 清单。',
              ok: manifestOk && hostBinOk && idMatch,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: widget.extensionIdController,
              decoration: const InputDecoration(
                labelText: 'Chrome 扩展 ID',
                hintText: '从 chrome://extensions 复制，粘贴后点「更新 Native Host」',
              ),
              onChanged: (_) => setState(() {}),
            ),
            if (stored.isNotEmpty && stored != widget.extensionIdController.text.trim())
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(
                  '已保存的 ID 为 $stored，与输入框不同；安装后将覆盖保存值。',
                  style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.error),
                ),
              ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                FilledButton(onPressed: _installHost, child: const Text('更新 Native Host')),
                OutlinedButton(
                  onPressed: () => _run('显示目录', () async {
                    final r = await AgentBridge.revealChromeExtensionDir();
                    setState(() => _message = r['message']?.toString() ?? '');
                  }),
                  child: const Text('在 Finder 显示扩展'),
                ),
                OutlinedButton(
                  onPressed: () => _run('打开扩展页', () async {
                    final r = await AgentBridge.openChromeExtensionsPage();
                    setState(() => _message = r['message']?.toString() ?? '');
                  }),
                  child: const Text('打开 chrome://extensions'),
                ),
                OutlinedButton(onPressed: _refresh, child: const Text('刷新状态')),
              ],
            ),
            const SizedBox(height: 16),
            Text('状态', style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 4),
            Text(
              [
                if (_host['extension_dir_path'] != null && _host['extension_dir_path'].toString().isNotEmpty)
                  '扩展目录: ${_host['extension_dir_path']}',
                'Host 清单: ${manifestOk ? "已安装" : "未安装"}',
                'native-host: ${hostBinOk ? "已就绪" : "缺失"}',
                if (manifestId.isNotEmpty) '清单中的 ID: $manifestId',
              ].join('\n'),
              style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
            ),
            if (_message.isNotEmpty) ...[
              const SizedBox(height: 12),
              Text(_message, style: const TextStyle(fontSize: 13)),
            ],
            const SizedBox(height: 12),
            const Text(
              '安装或更新 Host 后请完全退出 Chrome 再重新打开；Vault 须主密码解锁后扩展才能读写凭据。',
              style: TextStyle(fontSize: 12, color: Colors.black54),
            ),
          ],
        ),
      ),
    );
  }
}

class _StepTile extends StatelessWidget {
  const _StepTile({
    required this.step,
    required this.title,
    required this.detail,
    required this.ok,
  });

  final int step;
  final String title;
  final String detail;
  final bool ok;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: CircleAvatar(
        radius: 14,
        backgroundColor: ok ? Colors.green.shade100 : Colors.grey.shade300,
        child: Text('$step', style: const TextStyle(fontSize: 12)),
      ),
      title: Text(title),
      subtitle: Text(detail, style: const TextStyle(fontSize: 12)),
      dense: true,
      contentPadding: EdgeInsets.zero,
    );
  }
}
