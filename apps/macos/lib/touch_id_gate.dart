import 'package:flutter/material.dart';

import 'agent_bridge.dart';

int _sensitiveAuthGeneration = 0;
bool _confirmingSensitiveOperation = false;

/// 锁定后的异步确认不能应用到新的解锁会话。
void clearSensitiveAuthGrace() {
  _sensitiveAuthGeneration++;
}

/// 身份验证由 Agent 限时复用；每个敏感动作仍单独确认用户意图。
Future<bool> requireTouchId(
  BuildContext context, {
  required String reason,
  bool confirmed = false,
}) async {
  if (!context.mounted || _confirmingSensitiveOperation) return false;
  final generation = _sensitiveAuthGeneration;
  _confirmingSensitiveOperation = true;
  try {
    if (!confirmed) {
      final accepted = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('确认敏感操作'),
          content: Text('是否继续$reason？'),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('取消')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('继续')),
          ],
        ),
      );
      if (accepted != true) return false;
    }
    if (!context.mounted || generation != _sensitiveAuthGeneration) return false;
    final ok = await AgentBridge.authenticateTouchId(reason);
    if (!context.mounted || generation != _sensitiveAuthGeneration) return false;
    if (!ok) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('身份验证未通过，请重试或使用主密码')));
    }
    return ok;
  } finally {
    _confirmingSensitiveOperation = false;
  }
}
