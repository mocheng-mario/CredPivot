import 'dart:convert';
import 'package:flutter/services.dart';

/// 通过 Swift 平台通道调用进程内 Agent（Rust FFI 在 Runner 内链接）。
class AgentBridge {
  static const _channel = MethodChannel('credpivot/agent');

  static Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    final raw = await _channel.invokeMethod<String>('agentRequest', jsonEncode(body));
    if (raw == null) {
      throw StateError('empty agent response');
    }
    final decoded = jsonDecode(raw) as Map<String, dynamic>;
    if (decoded['type'] == 'err') {
      throw AgentException(
        decoded['code'] as String? ?? 'error',
        decoded['message'] as String? ?? 'unknown',
      );
    }
    return decoded;
  }

  static Map<String, dynamic> payloadOf(Map<String, dynamic> resp) =>
      resp['payload'] as Map<String, dynamic>? ?? resp;

  static Future<void> startAgent() => _channel.invokeMethod('startAgent');

  static Future<void> lockVault() => _channel.invokeMethod('lockVault');

  static Future<bool> unlockWithPassword(String password) async {
    return await _channel.invokeMethod<bool>('unlockPassword', password) ?? false;
  }

  static Future<bool> unlockWithTouchId() async {
    return await _channel.invokeMethod<bool>('unlockTouchId') ?? false;
  }

  static Future<String> vaultCreate(String password) async {
    final resp = await request({'type': 'vault_create', 'password': password});
    final payload = payloadOf(resp);
    return payload['recovery_key'] as String? ?? '';
  }

  static Future<void> vaultChangePassword(String oldPassword, String newPassword) async {
    await request({
      'type': 'vault_change_password',
      'old_password': oldPassword,
      'new_password': newPassword,
    });
  }

  static Future<void> vaultExportOvb(String outputPath, String password) async {
    await request({
      'type': 'vault_export_ovb',
      'output_path': outputPath,
      'password': password,
    });
  }

  static Future<void> vaultOpenDir(String path) async {
    await request({'type': 'vault_open_dir', 'path': path});
  }

  static Future<void> vaultRecoverOvb({
    required String ovbPath,
    required String targetDir,
    String? password,
    String? recoveryKey,
  }) async {
    await request({
      'type': 'vault_recover_ovb',
      'ovb_path': ovbPath,
      'target_dir': targetDir,
      if (password != null) 'password': password,
      if (recoveryKey != null) 'recovery_key': recoveryKey,
    });
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

  static Future<int> residentMemoryBytes() async =>
      await _channel.invokeMethod<int>('residentMemoryBytes') ?? 0;

  static Future<String?> pickDirectory() => _channel.invokeMethod<String>('pickDirectory');

  static Future<String?> pickOpenFile() => _channel.invokeMethod<String>('pickOpenFile');

  static Future<String?> pickSaveFile([String defaultName = 'backup.ovb']) =>
      _channel.invokeMethod<String>('pickSaveFile', defaultName);
}

class AgentException implements Exception {
  AgentException(this.code, this.message);
  final String code;
  final String message;
  @override
  String toString() => '$code: $message';
}
