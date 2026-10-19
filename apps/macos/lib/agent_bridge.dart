import 'dart:convert';
import 'package:flutter/services.dart';

/// M0：通过 Swift 平台通道调用进程内 Agent（Rust FFI 在 Runner 内链接）。
class AgentBridge {
  static const _channel = MethodChannel('credpivot/agent');

  static Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    final raw = await _channel.invokeMethod<String>('agentRequest', jsonEncode(body));
    if (raw == null) {
      throw StateError('empty agent response');
    }
    return jsonDecode(raw) as Map<String, dynamic>;
  }

  static Future<void> startAgent() => _channel.invokeMethod('startAgent');

  static Future<void> lockVault() => _channel.invokeMethod('lockVault');

  static Future<bool> unlockWithPassword(String password) async {
    return await _channel.invokeMethod<bool>('unlockPassword', password) ?? false;
  }

  static Future<bool> unlockWithTouchId() async {
    return await _channel.invokeMethod<bool>('unlockTouchId') ?? false;
  }

  static Future<void> registerLoginItem(bool enabled) =>
      _channel.invokeMethod('registerLoginItem', enabled);

  static Future<void> installChromeHost() => _channel.invokeMethod('installChromeHost');

  static Future<Map<String, dynamic>> appendSshIdentityAgent() async {
    final raw = await _channel.invokeMethod<dynamic>('appendSshIdentityAgent');
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {'ok': false, 'message': '未知返回: $raw'};
  }

  static Future<Map<String, dynamic>> removeSshIdentityAgent() async {
    final raw = await _channel.invokeMethod<dynamic>('removeSshIdentityAgent');
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {'ok': false, 'message': '未知返回: $raw'};
  }

  /// 当前 App 进程常驻内存（字节），由 macOS task_info 读取。
  static Future<int> residentMemoryBytes() async =>
      await _channel.invokeMethod<int>('residentMemoryBytes') ?? 0;
}
