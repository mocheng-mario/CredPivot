import 'package:flutter/material.dart';
import 'app_presentation.dart';

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
  final localizedReason = tr(reason);
  final generation = _sensitiveAuthGeneration;
  _confirmingSensitiveOperation = true;
  try {
    if (!confirmed) {
      ModalRoute<bool>? confirmationRoute;
      final accepted = await showDialog<bool>(
        context: context,
        builder: (ctx) {
          confirmationRoute ??= ModalRoute.of<bool>(ctx);
          return AlertDialog(
          title: const LText('auth.confirm.title'),
          content: LText('auth.confirm.body', args: {'reason': localizedReason}),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('common.cancel')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const LText('common.continue')),
          ],
          );
        },
      );
      // pop 返回时确认框仍在退场，先让其释放焦点，再进入系统验证或后续编辑窗口。
      await confirmationRoute?.completed;
      if (accepted != true) return false;
    }
    if (!context.mounted || generation != _sensitiveAuthGeneration) return false;
    final ok = await AgentBridge.authenticateTouchId(localizedReason);
    if (!context.mounted || generation != _sensitiveAuthGeneration) return false;
    if (!ok) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('auth.errors.notVerified')));
    }
    return ok;
  } finally {
    _confirmingSensitiveOperation = false;
  }
}
