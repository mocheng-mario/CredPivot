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

  static Future<bool> agentIsRunning() async =>
      await _channel.invokeMethod<bool>('agentIsRunning') ?? false;

  static Future<bool> restartAgent() async =>
      await _channel.invokeMethod<bool>('restartAgent') ?? false;

  static Future<void> relaunchApp() => _channel.invokeMethod('relaunchApp');

  /// 确保 Agent 可用；失败时返回 false（不抛异常）。
  static Future<bool> ensureAgentReady() async {
    if (await agentIsRunning()) {
      try {
        await request({'type': 'ping'});
        return true;
      } on AgentException catch (e) {
        if (!isAgentNotStartedError(e)) rethrow;
      }
    }
    await startAgent();
    if (await agentIsRunning()) {
      try {
        await request({'type': 'ping'});
        return true;
      } on AgentException catch (_) {
        return false;
      }
    }
    final restarted = await restartAgent();
    if (!restarted) return false;
    try {
      await request({'type': 'ping'});
      return true;
    } on AgentException catch (_) {
      return false;
    }
  }

  static bool isAgentNotStartedError(AgentException e) =>
      e.code == 'agent_not_started' ||
      (e.code == 'ffi_error' &&
          (e.message.contains('agent_not_started') || e.message.contains('agent not started')));

  static String friendlyMessage(AgentException e) {
    if (isAgentNotStartedError(e)) {
      return '后台 Agent 未启动。请先点「重启 Agent」；仍失败请「重新打开应用」（或 Cmd+Q 退出后重开）。';
    }
    return e.message;
  }

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

  static Future<String> getChromeExtensionId() async =>
      await _channel.invokeMethod<String>('getChromeExtensionId') ?? '';

  static Future<Map<String, dynamic>> chromeHostStatus() async {
    final raw = await _channel.invokeMethod<dynamic>('chromeHostStatus');
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {};
  }

  static Future<Map<String, dynamic>> installChromeHost(String extensionId) async {
    final raw = await _channel.invokeMethod<dynamic>('installChromeHost', extensionId);
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {'ok': false, 'message': '未知返回: $raw'};
  }

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

  static Future<String> readTextFile(String path) async {
    final raw = await _channel.invokeMethod<String>('readTextFile', path);
    return raw ?? '';
  }

  static Future<void> copyConcealed(String secret) =>
      _channel.invokeMethod('copyConcealed', secret);

  static Future<List<Map<String, dynamic>>> listCredentials([String? query]) async {
    final resp = await request({
      'type': 'credential_list',
      if (query != null && query.isNotEmpty) 'query': query,
      'limit': 200,
    });
    final payload = payloadOf(resp);
    final items = payload['items'] as List<dynamic>? ?? [];
    return items.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  static Future<Map<String, dynamic>> getCredential(String credentialId) async {
    final detail = await request({'type': 'credential_get', 'credential_id': credentialId});
    return payloadOf(detail);
  }

  static Future<void> trashCredential(String itemId) async {
    await request({'type': 'credential_trash', 'item_id': itemId});
  }

  static Future<Map<String, dynamic>> securitySummary() async {
    final resp = await request({'type': 'security_summary'});
    final payload = payloadOf(resp);
    return Map<String, dynamic>.from(payload['summary'] as Map? ?? {});
  }

  static Future<Map<String, dynamic>> importBitwarden(String json) async {
    final resp = await request({'type': 'import_bitwarden', 'json': json});
    final payload = payloadOf(resp);
    return Map<String, dynamic>.from(payload['report'] as Map? ?? {});
  }

  static Future<Map<String, dynamic>> backupStatus() async {
    final resp = await request({'type': 'backup_status'});
    return Map<String, dynamic>.from(payloadOf(resp)['status'] as Map? ?? {});
  }

  static Future<List<Map<String, dynamic>>> listRestorePoints() async {
    final resp = await request({'type': 'restore_points_list'});
    final points = payloadOf(resp)['points'] as List<dynamic>? ?? [];
    return points.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  static Future<void> recoverRestorePoint(int createdAtMs, String targetDir) async {
    await request({
      'type': 'restore_point_recover',
      'created_at_ms': createdAtMs,
      'target_dir': targetDir,
    });
  }

  static Future<void> migrateVault(String targetDir) async {
    await request({'type': 'vault_migrate', 'target_dir': targetDir});
  }

  static Future<void> securityRebuild(String password, String recoveryKey) async {
    await request({
      'type': 'vault_security_rebuild',
      'password': password,
      'recovery_key': recoveryKey,
    });
  }

  static Future<void> verifyOvb(String ovbPath, String password) async {
    await request({
      'type': 'vault_verify_ovb',
      'ovb_path': ovbPath,
      'password': password,
    });
  }

  static Future<void> verifyRecoveryKey(String recoveryKey) async {
    await request({'type': 'vault_verify_recovery_key', 'recovery_key': recoveryKey});
  }

  static Future<List<Map<String, dynamic>>> listRecoveryCodes() async {
    final resp = await request({'type': 'recovery_codes_list'});
    final items = payloadOf(resp)['items'] as List<dynamic>? ?? [];
    return items.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  static Future<Map<String, dynamic>> createRecoveryCodes(
    String serviceName,
    List<String> codes,
  ) async {
    final resp = await request({
      'type': 'recovery_codes_create',
      'service_name': serviceName,
      'codes': codes,
    });
    return Map<String, dynamic>.from(payloadOf(resp)['item'] as Map? ?? {});
  }
}

class AgentException implements Exception {
  AgentException(this.code, this.message);
  final String code;
  final String message;
  @override
  String toString() => '$code: $message';
}
