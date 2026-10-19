import 'package:flutter/material.dart';

import 'agent_bridge.dart';

/// 本会话内已通过敏感操作指纹验证（Vault 锁定前有效）。
bool _sensitiveAuthGrace = false;

/// Vault 锁定或切换会话时调用。
void clearSensitiveAuthGrace() {
  _sensitiveAuthGrace = false;
}

/// 敏感操作前的 Touch ID / 指纹门槛；通过一次后至锁定前不再弹窗。
Future<bool> requireTouchId(
  BuildContext context, {
  required String reason,
}) async {
  if (_sensitiveAuthGrace) {
    return true;
  }
  final ok = await AgentBridge.authenticateTouchId(reason);
  if (ok) {
    _sensitiveAuthGrace = true;
  } else if (context.mounted) {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('未通过指纹验证')),
    );
  }
  return ok;
}
