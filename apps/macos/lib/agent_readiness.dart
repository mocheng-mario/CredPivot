import 'dart:async';

import 'package:flutter/material.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';

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
  Widget build(BuildContext context) => ListView(
        padding: const EdgeInsets.all(24),
        children: [
          AppPanel(
            title: '正在等待本机 Agent',
            icon: Icons.hub_outlined,
            subtitle: '保险库与服务器连接依赖本机 Agent。服务就绪后，这里会自动恢复。',
            child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const AppNotice('如果长时间没有恢复，请尝试重启 Agent；仍失败时可完全退出应用后重新打开。'),
                  const SizedBox(height: 10),
                  Wrap(spacing: 10, runSpacing: 10, children: [
                    FilledButton.icon(
                        onPressed: onRestartAgent,
                        icon: const Icon(Icons.refresh_rounded),
                        label: const LText('重启 Agent')),
                    OutlinedButton(
                        onPressed: onRelaunchApp, child: const LText('重新打开应用')),
                  ]),
                ]),
          ),
          if (log != null && log!.isNotEmpty) ...[
            const SizedBox(height: 16),
            Card(
                child: ExpansionTile(
              shape: const Border(),
              collapsedShape: const Border(),
              title: const LText('查看诊断信息'),
              leading: const Icon(Icons.info_outline_rounded),
              childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
              children: [
                Align(
                    alignment: Alignment.centerLeft,
                    child: SelectableText(log!,
                        style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 12,
                            height: 1.6)))
              ],
            )),
          ],
        ],
      );
}
