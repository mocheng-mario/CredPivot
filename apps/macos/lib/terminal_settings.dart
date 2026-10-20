import 'package:flutter/material.dart';

import 'agent_bridge.dart';

Future<Map<String, String>> loadTerminalApplication() async {
  final raw = await AgentBridge.getTerminalApplication();
  return {
    'path': raw['path']?.toString() ?? '',
    'name': raw['name']?.toString() ?? '',
  };
}

/// 未配置时弹出选择；返回是否已有可用终端。
Future<bool> ensureTerminalConfigured(BuildContext context) async {
  final cur = await loadTerminalApplication();
  if (cur['path']?.isNotEmpty == true) return true;
  return showTerminalPickerDialog(context);
}

Future<bool> showTerminalPickerDialog(BuildContext context) async {
  final current = await loadTerminalApplication();
  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: const Text('终端设置'),
      content: SizedBox(
        width: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              '一键 SSH 会在你选择的终端应用中执行连接命令。'
              ' 密码一般在终端内输入，或由 SSH 密钥 / IdentityAgent 认证。',
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 12),
            Text(
              current['path']?.isNotEmpty == true
                  ? '当前：${current['name']}\n${current['path']}'
                  : '当前：未选择',
              style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: () async {
                final picked = await AgentBridge.pickTerminalApplication();
                if (picked != null && ctx.mounted) {
                  Navigator.pop(ctx, true);
                }
              },
              icon: const Icon(Icons.apps),
              label: const Text('选择应用程序…'),
            ),
            const SizedBox(height: 8),
            const Text(
              '在 Finder 中选中终端 .app（如 Tabby、iTerm、Warp、系统终端）。',
              style: TextStyle(fontSize: 11, color: Colors.black54),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('关闭')),
      ],
    ),
  );
  return ok == true || (await loadTerminalApplication())['path']?.isNotEmpty == true;
}

String terminalDisplayName(Map<String, String> pref) {
  final name = pref['name'] ?? '';
  if (name.isNotEmpty) return name;
  final path = pref['path'] ?? '';
  if (path.isEmpty) return '未选择';
  final parts = path.split('/');
  return parts.isNotEmpty ? parts.last : path;
}
