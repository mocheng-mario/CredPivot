import 'dart:convert';
import 'package:flutter/services.dart';

/// 通过 Swift 平台通道调用进程内 Agent（Rust FFI 在 Runner 内链接）。
class AgentBridge {
  static const _channel = MethodChannel('credpivot/agent');
  static Future<bool>? _agentReadyCheck;

  /// 接收菜单栏/系统触发的锁定通知。
  static void Function()? _onVaultLocked;

  static void installVaultLockHandler(void Function() onLocked) {
    _onVaultLocked = onLocked;
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'onVaultLocked') {
        _onVaultLocked?.call();
      }
      return null;
    });
  }

  static Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    final raw = await _channel.invokeMethod<String>('agentRequest', jsonEncode(body));
    if (raw == null) {
      throw StateError('empty agent response');
    }
    final decoded = jsonDecode(raw) as Map<String, dynamic>;
    if (decoded['type'] == 'err') {
      final code = decoded['code'] as String? ?? 'error';
      if (code == 'locked') {
        _onVaultLocked?.call();
      }
      throw AgentException(
        code,
        decoded['message'] as String? ?? 'unknown',
      );
    }
    return decoded;
  }

  static Future<void> selectSshKey(String keyId) async {
    await request({'type': 'ssh_select_key', 'key_id': keyId});
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
  static Future<bool> ensureAgentReady() {
    // 启动页、轮询和用户操作复用同一次检查，避免同时启动或重启 Agent。
    return _agentReadyCheck ??= _checkAgentReady()
        .catchError((Object _) => false)
        .whenComplete(() {
          _agentReadyCheck = null;
        });
  }

  static Future<bool> _checkAgentReady() async {
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

  /// 日志区域只显示固定错误分类，避免异常中的导入内容或路径被复制、留存。
  static String diagnosticMessage(AgentException e) {
    if (isAgentNotStartedError(e)) return '后台 Agent 未启动，请重启 Agent';
    switch (e.code) {
      case 'locked':
        return '保险库已锁定，请重新解锁';
      case 'bad_unlock':
        return '身份验证失败';
      case 'conflict':
        return '记录已更新，请刷新后重试';
      case 'not_found':
        return '记录不存在或已删除';
      case 'peer_denied':
      case 'forbidden':
        return '操作未获授权';
      case 'log_config':
        return '日志级别保存失败';
      default:
        return '操作失败，请查看「诊断」页的事件记录';
    }
  }

  static Future<void> lockVault() => _channel.invokeMethod('lockVault');

  static Future<bool> unlockWithPassword(String password) async {
    return await _channel.invokeMethod<bool>('unlockPassword', password) ?? false;
  }

  static Future<bool> unlockWithTouchId() async {
    return await _channel.invokeMethod<bool>('unlockTouchId') ?? false;
  }

  /// Touch ID / Mac 登录密码门槛，不触发 Vault 解锁。
  static Future<bool> authenticateTouchId([String reason = 'CredPivot 需要验证您的身份']) async {
    return await _channel.invokeMethod<bool>('authenticateTouchId', reason) ?? false;
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

  static Future<Map<String, dynamic>> revealChromeExtensionDir() async {
    final raw = await _channel.invokeMethod<dynamic>('revealChromeExtensionDir');
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {'ok': false, 'message': '未知返回: $raw'};
  }

  static Future<Map<String, dynamic>> openChromeExtensionsPage() async {
    final raw = await _channel.invokeMethod<dynamic>('openChromeExtensionsPage');
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

  static Future<List<Map<String, dynamic>>> listCredentialGroups(String scope) async {
    final resp = await request({'type': 'credential_group_list', 'scope': scope});
    final items = payloadOf(resp)['items'] as List<dynamic>? ?? [];
    return items.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  static Future<void> createCredentialGroup(String scope, String name) async {
    await request({'type': 'credential_group_create', 'scope': scope, 'name': name});
  }

  static Future<void> deleteCredentialGroup(String id) async {
    await request({'type': 'credential_group_delete', 'id': id});
  }

  static Future<void> setItemGroup(String itemId, String? groupId) async {
    await request({
      'type': 'credential_item_set_group',
      'item_id': itemId,
      'group_id': groupId ?? '',
    });
  }

  static Future<Map<String, dynamic>> fetchDiagnosticLog({int maxLines = 400}) async {
    final resp = await request({
      'type': 'diagnostic_log_tail',
      'max_lines': maxLines,
    });
    return payloadOf(resp);
  }

  static Future<void> setDiagnosticLogLevel(String level) async {
    await request({'type': 'diagnostic_log_set_level', 'level': level});
  }

  static Future<Map<String, dynamic>> getTerminalApplication() async {
    final raw = await _channel.invokeMethod<dynamic>('getTerminalPreference');
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {'path': '', 'name': ''};
  }

  static Future<Map<String, dynamic>?> pickTerminalApplication() async {
    final raw = await _channel.invokeMethod<dynamic>('pickTerminalApplication');
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return null;
  }

  static Future<void> setTerminalLaunchConfig(Map<String, dynamic> config) async {
    await _channel.invokeMethod<void>('setTerminalLaunchConfig', config);
  }

  static Future<String?> openSshInTerminal({
    required String host,
    required int port,
    required String username,
  }) async {
    return await _channel.invokeMethod<String>('openSshInTerminal', {
      'host': host,
      'port': port,
      'username': username,
    });
  }

  /// 安装 askpass 到 `~/.credpivot/credpivot-askpass`。
  static Future<String> materializeSshAskpass() async {
    final path = await _channel.invokeMethod<String>('materializeSshAskpass');
    if (path == null || path.isEmpty) {
      throw AgentException('ssh_askpass', 'SSH askpass 安装失败');
    }
    return path;
  }

  /// Agent 登记 SSH 会话（密码留在 Vault，由 askpass 按提示领取）。
  static Future<String> sshSessionPrepare({
    required String host,
    required int port,
    required String user,
    required String loginCredentialId,
    String? totpId,
  }) async {
    final resp = await request({
      'type': 'ssh_session_prepare',
      'host': host,
      'port': port,
      'user': user,
      'login_credential_id': loginCredentialId,
      if (totpId != null && totpId.isNotEmpty) 'totp_id': totpId,
    });
    final payload = payloadOf(resp);
    final id = payload['session_id'] as String?;
    if (id == null || id.isEmpty) {
      throw AgentException('ssh_session', '无法创建 SSH 会话');
    }
    return id;
  }

  static Future<String?> openSshWithAskpass({
    required String host,
    required int port,
    required String username,
    required String sessionId,
  }) async {
    return await _channel.invokeMethod<String>('openSshWithAskpass', {
      'host': host,
      'port': port,
      'username': username,
      'sessionId': sessionId,
    });
  }

  static Future<Map<String, dynamic>> createLogin({
    required String origin,
    required String username,
    required String password,
    String displayName = '',
    String? groupId,
    String connectionHost = '',
    String? linkedTotpId,
  }) async {
    final resp = await request({
      'type': 'credential_save',
      'request_id': 'ui-${DateTime.now().millisecondsSinceEpoch}',
      'origin': origin,
      'username': username,
      'password': password,
      'display_name': displayName,
      if (groupId != null && groupId.isNotEmpty) 'group_id': groupId,
      'connection_host': connectionHost,
      if (linkedTotpId != null && linkedTotpId.isNotEmpty) 'linked_totp_id': linkedTotpId,
    });
    return Map<String, dynamic>.from(payloadOf(resp)['credential'] as Map? ?? {});
  }

  static Future<Map<String, dynamic>> updateLogin({
    required String credentialId,
    required String expectedRevision,
    required String origin,
    required String username,
    String displayName = '',
    String? groupId,
    String connectionHost = '',
    String? linkedTotpId,
    String? password,
  }) async {
    final resp = await request({
      'type': 'credential_update',
      'credential_id': credentialId,
      'expected_revision': expectedRevision,
      'origin': origin,
      'username': username,
      'display_name': displayName,
      'group_id': groupId ?? '',
      'connection_host': connectionHost,
      'linked_totp_id': linkedTotpId ?? '',
      if (password != null && password.isNotEmpty) 'password': password,
    });
    return Map<String, dynamic>.from(payloadOf(resp)['item'] as Map? ?? {});
  }

  static Future<List<Map<String, dynamic>>> listTotp() async {
    final resp = await request({'type': 'totp_list'});
    final items = payloadOf(resp)['items'] as List<dynamic>? ?? [];
    return items.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  static Future<Map<String, dynamic>> createTotp({
    required String issuer,
    required String account,
    required String secretBase32,
    String? groupId,
  }) async {
    final resp = await request({
      'type': 'totp_create',
      'issuer': issuer,
      'account': account,
      'secret_base32': secretBase32,
      if (groupId != null && groupId.isNotEmpty) 'group_id': groupId,
    });
    return Map<String, dynamic>.from(payloadOf(resp)['item'] as Map? ?? {});
  }

  static Future<String> totpCode(String totpId) async {
    final resp = await request({'type': 'totp_code', 'totp_id': totpId});
    return payloadOf(resp)['code'] as String? ?? '';
  }

  static Future<Map<String, dynamic>> totpReveal(String totpId) async {
    final resp = await request({'type': 'totp_reveal', 'totp_id': totpId});
    return Map<String, dynamic>.from(payloadOf(resp)['reveal'] as Map? ?? {});
  }

  static Future<List<Map<String, dynamic>>> listServerProfiles() async {
    final resp = await request({'type': 'server_profile_list'});
    final items = payloadOf(resp)['items'] as List<dynamic>? ?? [];
    return items.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  static Future<Map<String, dynamic>> createServerProfile({
    required String label,
    required String host,
    int port = 22,
    String manualUsername = '',
    String? linkedLoginId,
    String? linkedTotpId,
    String? linkedSshKeyId,
    String? groupId,
  }) async {
    final resp = await request({
      'type': 'server_profile_create',
      'label': label,
      'host': host,
      'port': port,
      'manual_username': manualUsername,
      if (linkedLoginId != null && linkedLoginId.isNotEmpty) 'linked_login_id': linkedLoginId,
      if (linkedTotpId != null && linkedTotpId.isNotEmpty) 'linked_totp_id': linkedTotpId,
      if (linkedSshKeyId != null && linkedSshKeyId.isNotEmpty) 'linked_ssh_key_id': linkedSshKeyId,
      if (groupId != null && groupId.isNotEmpty) 'group_id': groupId,
    });
    return Map<String, dynamic>.from(payloadOf(resp)['item'] as Map? ?? {});
  }

  static Future<Map<String, dynamic>> updateServerProfile({
    required String id,
    required String expectedRevision,
    required String label,
    required String host,
    int port = 22,
    String manualUsername = '',
    String? linkedLoginId,
    String? linkedTotpId,
    String? linkedSshKeyId,
    String? groupId,
  }) async {
    final resp = await request({
      'type': 'server_profile_update',
      'id': id,
      'expected_revision': expectedRevision,
      'label': label,
      'host': host,
      'port': port,
      'manual_username': manualUsername,
      'linked_login_id': linkedLoginId ?? '',
      'linked_totp_id': linkedTotpId ?? '',
      'linked_ssh_key_id': linkedSshKeyId ?? '',
      'group_id': groupId ?? '',
    });
    return Map<String, dynamic>.from(payloadOf(resp)['item'] as Map? ?? {});
  }

  static Future<List<Map<String, dynamic>>> listSshKeys() async {
    final resp = await request({'type': 'ssh_key_list'});
    final items = payloadOf(resp)['items'] as List<dynamic>? ?? [];
    return items.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  static Future<Map<String, dynamic>> generateSshKey({
    required String label,
    bool setDefault = false,
    String? groupId,
  }) async {
    final resp = await request({
      'type': 'ssh_key_generate',
      'label': label,
      'set_default': setDefault,
      if (groupId != null && groupId.isNotEmpty) 'group_id': groupId,
    });
    return Map<String, dynamic>.from(payloadOf(resp)['item'] as Map? ?? {});
  }

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

  static Future<String> securityRebuild(String password, String recoveryKey) async {
    final resp = await request({
      'type': 'vault_security_rebuild',
      'password': password,
      'recovery_key': recoveryKey,
    });
    return payloadOf(resp)['new_recovery_key'] as String? ?? '';
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

  static Future<Map<String, dynamic>> updateRecoveryCodes({
    required String id,
    required String expectedRevision,
    required String serviceName,
    required List<String> codes,
  }) async {
    final resp = await request({
      'type': 'recovery_codes_update',
      'id': id,
      'expected_revision': expectedRevision,
      'service_name': serviceName,
      'codes': codes,
    });
    return Map<String, dynamic>.from(payloadOf(resp)['item'] as Map? ?? {});
  }

  static Future<void> trashRecoveryCodes(String itemId) async {
    await request({'type': 'credential_trash', 'item_id': itemId});
  }
}

class AgentException implements Exception {
  AgentException(this.code, this.message);
  final String code;
  final String message;
  @override
  String toString() => '$code: $message';
}
