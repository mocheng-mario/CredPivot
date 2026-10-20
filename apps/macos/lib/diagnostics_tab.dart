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

  @override
  void initState() {
    super.initState();
    _refresh();
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
          Wrap(
            spacing: 8,
            children: [
              FilledButton(onPressed: _loading ? null : _refresh, child: const Text('刷新')),
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
