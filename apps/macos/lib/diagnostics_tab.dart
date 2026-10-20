import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';

class DiagnosticsTab extends StatefulWidget {
  const DiagnosticsTab({super.key});

  @override
  State<DiagnosticsTab> createState() => _DiagnosticsTabState();
}

class _DiagnosticsTabState extends State<DiagnosticsTab> {
  String _logText = '';
  String _logPath = '';
  bool _loading = false;
  String _repairMsg = '';

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _repairAgentAndHost() async {
    setState(() => _repairMsg = '');
    final restarted = await AgentBridge.restartAgent();
    if (!restarted) {
      setState(() => _repairMsg = 'Agent 重启失败，请完全退出 App 后重开');
      return;
    }
    final host = await AgentBridge.chromeHostStatus();
    final extId = host['stored_extension_id']?.toString() ?? '';
    if (extId.isEmpty) {
      setState(() => _repairMsg = 'Agent 已重启。请在「Chrome」页填写扩展 ID 并点「更新 Native Host」');
      await _refresh();
      return;
    }
    final r = await AgentBridge.installChromeHost(extId);
    setState(() {
      _repairMsg = r['message']?.toString() ?? '已尝试重装 Native Host';
    });
    await _refresh();
  }

  Future<void> _refresh() async {
    setState(() => _loading = true);
    try {
      final data = await AgentBridge.fetchDiagnosticLog();
      if (!mounted) return;
      setState(() {
        _logPath = data['path']?.toString() ?? '';
        _logText = data['text']?.toString() ?? '';
        if (_logText.isEmpty) {
          _logText = '（暂无日志，Agent 启动后会写入 ~/.credpivot/logs/agent.log）';
        }
      });
    } on AgentException catch (e) {
      setState(() => _logText = '读取失败: ${e.message}');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text('诊断日志', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          Text(
            'Agent 将错误与关键事件写入本地文件，便于排查 Vault / IPC / 数据库问题。'
            ' 路径：${_logPath.isEmpty ? '~/.credpivot/logs/agent.log' : _logPath}',
            style: const TextStyle(fontSize: 13),
          ),
          const SizedBox(height: 12),
          const Text(
            '若扩展报 unsupported action 或连接失败，可一键重启 Agent 并按已保存的扩展 ID 重装 Native Host（仍须在 Chrome 重载扩展）。',
            style: TextStyle(fontSize: 13),
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            children: [
              FilledButton(onPressed: _loading ? null : _refresh, child: const Text('刷新')),
              OutlinedButton(
                onPressed: _loading ? null : _repairAgentAndHost,
                child: const Text('修复 Agent / Native Host'),
              ),
              OutlinedButton(
                onPressed: _logText.isEmpty
                    ? null
                    : () {
                        Clipboard.setData(ClipboardData(text: _logText));
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('已复制日志到剪贴板')),
                        );
                      },
                child: const Text('复制全部'),
              ),
            ],
          ),
          if (_repairMsg.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(_repairMsg, style: const TextStyle(fontSize: 12)),
          ],
          const SizedBox(height: 12),
          Expanded(
            child: DecoratedBox(
              decoration: BoxDecoration(
                border: Border.all(color: Colors.black12),
                borderRadius: BorderRadius.circular(8),
                color: Colors.grey.shade50,
              ),
              child: _loading
                  ? const Center(child: CircularProgressIndicator())
                  : SingleChildScrollView(
                      padding: const EdgeInsets.all(8),
                      child: SelectableText(
                        _logText,
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                      ),
                    ),
            ),
          ),
        ],
      ),
    );
  }
}
