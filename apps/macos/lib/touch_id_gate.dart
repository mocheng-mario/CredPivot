import 'package:flutter/material.dart';

import 'agent_bridge.dart';

/// 本会话内已通过敏感操作身份验证（Vault 锁定前有效）。
bool _sensitiveAuthGrace = false;
int _sensitiveAuthGeneration = 0;

/// Vault 锁定或切换会话时调用。
void clearSensitiveAuthGrace() {
  _sensitiveAuthGeneration++;
  _sensitiveAuthGrace = false;
}

/// 敏感操作前验证 Touch ID 或 Mac 登录密码；通过一次后至锁定前不再弹窗。
Future<bool> requireTouchId(
  BuildContext context, {
  required String reason,
}) async {
  if (!context.mounted) return false;
  if (_sensitiveAuthGrace) {
    return true;
  }
  final generation = _sensitiveAuthGeneration;
  final ok = await AgentBridge.authenticateTouchId(reason);
  // 锁定或切换会话后，不能把迟到的成功结果缓存到新会话。
  if (!context.mounted || generation != _sensitiveAuthGeneration) return false;
  if (ok) {
    _sensitiveAuthGrace = true;
  } else {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('身份验证未通过')),
    );
  }
  return ok;
}
