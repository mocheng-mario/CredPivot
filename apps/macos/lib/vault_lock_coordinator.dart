import 'package:flutter/material.dart';

/// 全局 Navigator：锁库时关闭敏感弹窗。
final vaultRootNavigatorKey = GlobalKey<NavigatorState>();

VoidCallback? _vaultLockedListener;

void installVaultLockCoordinator(void Function() onLocked) {
  _vaultLockedListener = onLocked;
}

/// 菜单栏/系统/空闲锁/Agent 返回 locked 时统一入口。
void notifyVaultLocked() {
  _vaultLockedListener?.call();
  vaultRootNavigatorKey.currentState?.popUntil((route) => route.isFirst);
}
