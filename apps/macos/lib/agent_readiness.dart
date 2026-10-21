import 'dart:async';

import 'package:flutter/material.dart';

import 'agent_bridge.dart';

/// 轮询后台 Agent 是否可响应 ping。
class AgentReadinessScope extends StatefulWidget {
  const AgentReadinessScope({super.key, required this.builder});

  final Widget Function(BuildContext context, bool agentReady) builder;

  @override
  State<AgentReadinessScope> createState() => _AgentReadinessScopeState();
}

class _AgentReadinessScopeState extends State<AgentReadinessScope> {
  bool _ready = false;
  bool _polling = false;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _poll();
    _timer = Timer.periodic(const Duration(seconds: 2), (_) => _poll());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _poll() async {
    if (_polling || !mounted) return;
    _polling = true;
    try {
      final ok = await AgentBridge.ensureAgentReady();
      if (mounted && ok != _ready) {
        setState(() => _ready = ok);
      }
    } finally {
      _polling = false;
    }
  }

  /// 重启 Agent 后由外层调用以立即刷新状态。
  void refresh() => _poll();

  @override
  Widget build(BuildContext context) => widget.builder(context, _ready);
}

/// Agent 未就绪时仅展示恢复操作。
class AgentNotReadyPane extends StatelessWidget {
  const AgentNotReadyPane({
    super.key,
    required this.onRestartAgent,
    required this.onRelaunchApp,
    this.log,
  });

  final VoidCallback onRestartAgent;
  final VoidCallback onRelaunchApp;
  final String? log;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text('后台 Agent 未启动', style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 12),
          const Text(
            '保险库与 SSH 一键连接都依赖本机 Agent。请先尝试重启 Agent；'
            '仍失败请完全退出应用（Cmd+Q）后重新打开。',
          ),
          const SizedBox(height: 24),
          FilledButton(onPressed: onRestartAgent, child: const Text('重启 Agent')),
          const SizedBox(height: 8),
          OutlinedButton(onPressed: onRelaunchApp, child: const Text('重新打开应用')),
          if (log != null && log!.isNotEmpty) ...[
            const SizedBox(height: 24),
            Text('诊断', style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 8),
            Expanded(
              child: SingleChildScrollView(
                child: Text(log!, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
