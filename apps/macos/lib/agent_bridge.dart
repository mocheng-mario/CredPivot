import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart';
import 'app_presentation.dart';

/// 通过 Swift 平台通道调用进程内 Agent（Rust FFI 在 Runner 内链接）。
class AgentBridge {
  static const personalPartitionId = '00000000-0000-4000-8000-000000000001';
  static String activePartitionId = personalPartitionId;
  static const _channel = MethodChannel('credpivot/agent');
  static Future<bool>? _agentReadyCheck;

  /// 接收菜单栏/系统触发的锁定通知。
  static void Function()? _onVaultLocked;
  static void Function(String)? onShortcut;
  static void Function()? onAppForeground;
  static final vaultChanges = ValueNotifier<int>(0);
  static void notifyVaultChanged() => vaultChanges.value++;

  static void installVaultLockHandler(void Function() onLocked) {
    _onVaultLocked = onLocked;
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'onVaultLocked') {
        _onVaultLocked?.call();
      } else if (call.method == 'onShortcut' && call.arguments is String) {
        onShortcut?.call(call.arguments as String);
      } else if (call.method == 'onVaultChanged') {
        notifyVaultChanged();
      } else if (call.method == 'onAppForeground') {
        onAppForeground?.call();
      }
      return null;
    });
  }

  static Future<Map<String, dynamic>> request(Map<String, dynamic> body,
      {String? partitionId, bool allPartitions = false}) async {
    const scopedTypes = {'credential_list', 'credential_save', 'totp_list', 'totp_create',
      'ssh_key_list', 'ssh_key_generate', 'server_profile_list', 'server_profile_create',
      'recovery_codes_list', 'recovery_codes_create', 'credential_group_list', 'credential_group_create', 'passkey_list'};
    final action = body['action'];
    final scoped = !allPartitions && (scopedTypes.contains(body['type']) ||
        (body['type'] == 'vault_manage' && action is Map &&
            {'item_search', 'trash_list', 'note_create', 'ssh_import'}.contains(action['action'])));
    final wire = scoped ? {'type': 'partition_request', 'partition_id': partitionId ?? activePartitionId, 'request': body} : body;
    final raw = await _channel.invokeMethod<String>('agentRequest', jsonEncode(wire));
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
        decoded['details'] is Map ? Map<String, dynamic>.from(decoded['details'] as Map) : null,
      );
    }
    return decoded;
  }

  static Future<void> selectSshKey(String keyId) async {
    await request({'type': 'ssh_select_key', 'key_id': keyId});
  }
  static Future<String> prepareSshIdentityFile(String keyId) async =>
      await _channel.invokeMethod<String>('prepareSshIdentityFile', keyId) ?? (throw AgentException('ssh', tr('ssh.git.failed')));

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
    if (e.code == 'sync_error') return tr(e.message);
    if (e.code == 'auth_required') return tr('agent.friendlyMessage.text');
    if (isAgentNotStartedError(e)) {
      return tr('agent.friendlyMessage.text.item2');
    }
    return e.message;
  }

  /// 日志区域只显示固定错误分类，避免异常中的导入内容或路径被复制、留存。
  static String diagnosticMessage(AgentException e) {
    if (isAgentNotStartedError(e)) return tr('agent.diagnosticMessage.text');
    switch (e.code) {
      case 'locked':
        return tr('agent.diagnosticMessage.text.item2');
      case 'bad_unlock':
        return tr('agent.diagnosticMessage.text.item3');
      case 'auth_required':
        return tr('agent.friendlyMessage.text');
      case 'conflict':
        return tr('agent.diagnosticMessage.text.item4');
      case 'not_found':
        return tr('agent.diagnosticMessage.text.item5');
      case 'peer_denied':
      case 'forbidden':
        return tr('agent.diagnosticMessage.text.item6');
      case 'log_config':
        return tr('agent.diagnosticMessage.text.item7');
      default:
        return tr('agent.diagnosticMessage.text.item8');
    }
  }

  static Future<void> lockVault() => _channel.invokeMethod('lockVault');

  static Future<bool> unlockWithPassword(String password) async {
    return await _channel.invokeMethod<bool>('unlockPassword', password) ?? false;
  }

  static Future<bool> unlockWithTouchId() async {
    return await _channel.invokeMethod<bool>('unlockTouchId') ?? false;
  }

  /// 身份验证按用户配置限时复用，过期后优先 Touch ID、可回退主密码。
  static Future<bool> authenticateTouchId([String reason = 'agent.authenticateTouchId.reason']) async {
    return await _channel.invokeMethod<bool>('authenticateTouchId', reason) ?? false;
  }

  static Future<String> vaultCreate(String password) async {
    final resp = await request({'type': 'vault_create', 'password': password});
    final payload = payloadOf(resp);
    return payload['recovery_key'] as String? ?? '';
  }

  static Future<Map<String, dynamic>> syncHostInfo() async =>
      Map<String, dynamic>.from(await _channel.invokeMethod<Map>('syncHostInfo') ?? {});

  static Future<void> setSyncHostName(String name) =>
      _channel.invokeMethod<void>('setSyncHostName', name);

  static Future<void> vaultChangePassword(String oldPassword, String newPassword) async {
    await request({
      'type': 'vault_change_password',
      'old_password': oldPassword,
      'new_password': newPassword,
    });
    notifyVaultChanged();
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
    activePartitionId = personalPartitionId;
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

  static Future<String?> recordShortcut(String name, Map<String, String> bindings) =>
      _channel.invokeMethod<String>('recordShortcut', {'name': name, 'bindings': bindings});

  static Future<Map<String, dynamic>> fetchAppSettings() async =>
      payloadOf(await request({'type': 'app_settings_get'}));

  static Future<bool> isMainWindowForeground() async =>
      await _channel.invokeMethod<bool>('isMainWindowForeground') == true;

  static Future<String?> backupAppSettings() async =>
      payloadOf(await request({'type': 'app_settings_backup'}))['path'] as String?;

  static Future<Map<String, dynamic>> saveAppSettings(Map<String, dynamic> settings) async =>
      payloadOf(await request({'type': 'app_settings_set', 'settings': settings}));

  static Future<Map<String, dynamic>> loginItemStatus() async {
    final raw = await _channel.invokeMethod<dynamic>('loginItemStatus');
    return raw is Map ? Map<String, dynamic>.from(raw) : {};
  }

  static Future<String> getChromeExtensionId() async =>
      await _channel.invokeMethod<String>('getChromeExtensionId') ?? '';

  static Future<Map<String, dynamic>> chromeHostStatus() async {
    final raw = await _channel.invokeMethod<dynamic>('chromeHostStatus');
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {};
  }

  static Future<Map<String, dynamic>> componentVersions() async {
    final native = await _channel.invokeMapMethod<String,dynamic>('componentVersions') ?? {};
    final status = payloadOf(await request({'type':'status'}));
    return {...native, ...status};
  }

  static Future<Map<String, dynamic>> installChromeHost(String extensionId) async {
    final raw = await _channel.invokeMethod<dynamic>('installChromeHost', extensionId);
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {'ok': false, 'message': tr('browser.errors.unexpectedResponse', args: {'raw': raw})};
  }

  static Future<Map<String, dynamic>> revealChromeExtensionDir() async {
    final raw = await _channel.invokeMethod<dynamic>('revealChromeExtensionDir');
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {'ok': false, 'message': tr('browser.errors.unexpectedResponse', args: {'raw': raw})};
  }

  static Future<Map<String, dynamic>> openChromeExtensionsPage() async {
    final raw = await _channel.invokeMethod<dynamic>('openChromeExtensionsPage');
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {'ok': false, 'message': tr('browser.errors.unexpectedResponse', args: {'raw': raw})};
  }

  static Future<Map<String, dynamic>> sshIdentityAgentStatus() async {
    final raw = await _channel.invokeMethod<dynamic>('sshIdentityAgentStatus');
    return raw is Map ? Map<String, dynamic>.from(raw) : {'ok': false};
  }

  static Future<Map<String, dynamic>> appendSshIdentityAgent() async {
    final raw = await _channel.invokeMethod<dynamic>('appendSshIdentityAgent');
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {'ok': false, 'message': tr('browser.errors.unexpectedResponse', args: {'raw': raw})};
  }

  static Future<Map<String, dynamic>> removeSshIdentityAgent() async {
    final raw = await _channel.invokeMethod<dynamic>('removeSshIdentityAgent');
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    return {'ok': false, 'message': tr('browser.errors.unexpectedResponse', args: {'raw': raw})};
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

  static Future<Map<String, dynamic>> manage(Map<String, dynamic> action,
          {String? partitionId, bool allPartitions = false}) async =>
      payloadOf(await request({'type': 'vault_manage', 'action': action}, partitionId: partitionId, allPartitions: allPartitions));

  static Future<List<String>> scanQrImage({String? image}) async =>
      (await _channel.invokeListMethod<String>('scanQrImage', image == null ? null : {'image': image})) ?? [];

  static Future<void> showMainWindow() => _channel.invokeMethod('showMainWindow');

  static Future<void> writeTextFile(String path, String text) =>
      _channel.invokeMethod('writeTextFile', {'path': path, 'text': text});

  /// 在验证/取密之前记录代次；不能在复制时重新获取，否则锁定后重解锁会放行旧结果。
  static Future<int> clipboardSession() async {
    final status = payloadOf(await request({'type': 'status'}));
    final generation = status['vault_lock_generation'];
    if (status['unlocked'] != true || generation is! num) {
      _onVaultLocked?.call();
      throw AgentException('locked', tr('common.unlockFirst'));
    }
    return generation.toInt();
  }

  static Future<void> copyConcealed(String secret, {required int session}) async {
    try {
      await _channel.invokeMethod('copyConcealed', {
        'secret': secret, 'vault_lock_generation': session,
      });
    } on PlatformException catch (error) {
      if (error.code == 'locked') _onVaultLocked?.call();
      throw AgentException(error.code, error.message ?? tr('common.operationFailed'));
    }
  }

  static Future<List<Map<String, dynamic>>> listCredentialGroups(String scope, {String? partitionId}) async {
    final resp = await request({'type': 'credential_group_list', 'scope': scope}, partitionId: partitionId);
    final items = payloadOf(resp)['items'] as List<dynamic>? ?? [];
    return items.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  static Future<void> createCredentialGroup(String scope, String name, {String? partitionId}) async {
    await request({'type': 'credential_group_create', 'scope': scope, 'name': name}, partitionId: partitionId);
    notifyVaultChanged();
  }

  static Future<void> deleteCredentialGroup(String id) async {
    await request({'type': 'credential_group_delete', 'id': id});
    notifyVaultChanged();
  }

  static Future<void> setItemGroup(String itemId, String? groupId) async {
    await request({
      'type': 'credential_item_set_group',
      'item_id': itemId,
      'group_id': groupId ?? '',
    });
    notifyVaultChanged();
  }

  static Future<Map<String, dynamic>> fetchDiagnosticLog({int maxLines = 400, String? file}) async {
    final resp = await request({
      'type': 'diagnostic_log_tail',
      'max_lines': maxLines,
      if (file != null) 'file': file,
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
    String? identityFile,
  }) async {
    return await _channel.invokeMethod<String>('openSshInTerminal', {
      'host': host,
      'port': port,
      'username': username,
      if (identityFile != null) 'identityFile': identityFile,
    });
  }

  /// 安装 askpass 到 `~/.credpivot/credpivot-askpass`。
  static Future<String> materializeSshAskpass() async {
    final path = await _channel.invokeMethod<String>('materializeSshAskpass');
    if (path == null || path.isEmpty) {
      throw AgentException('ssh_askpass', tr('agent.materializeSshAskpass.text'));
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
      throw AgentException('ssh_session', tr('agent.sshSessionPrepare.text'));
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
    String? partitionId,
    required String origin,
    required String username,
    required String password,
    String displayName = '',
    String? groupId,
    String connectionHost = '',
    String? linkedTotpId,
    List<Map<String, dynamic>>? websiteRules,
    List<String>? linkedMfaIds,
    int? passwordActiveSinceMs,
  }) async {
    final resp = await request({
      'type': 'credential_save',
      'request_id': 'ui-${DateTime.now().millisecondsSinceEpoch}',
      'origin': origin,
      'username': username,
      'password': password,
      if (passwordActiveSinceMs != null) 'password_active_since_ms': passwordActiveSinceMs,
      'display_name': displayName,
      if (groupId != null && groupId.isNotEmpty) 'group_id': groupId,
      'connection_host': connectionHost,
      if (linkedTotpId != null && linkedTotpId.isNotEmpty) 'linked_totp_id': linkedTotpId,
      if (websiteRules != null) 'website_rules': websiteRules,
      if (linkedMfaIds != null) 'linked_mfa_ids': linkedMfaIds,
    }, partitionId: partitionId);
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
    List<Map<String, dynamic>>? websiteRules,
    List<String>? linkedMfaIds,
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
      if (websiteRules != null) 'website_rules': websiteRules,
      if (linkedMfaIds != null) 'linked_mfa_ids': linkedMfaIds,
    });
    return Map<String, dynamic>.from(payloadOf(resp)['item'] as Map? ?? {});
  }

  static Future<List<Map<String, dynamic>>> listTotp({String? partitionId}) async {
    final resp = await request({'type': 'totp_list'}, partitionId: partitionId);
    final items = payloadOf(resp)['items'] as List<dynamic>? ?? [];
    return items.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  static Future<Map<String, dynamic>> createTotp({
    String? partitionId,
    required String issuer,
    required String account,
    required String secretBase32,
    String? groupId,
    List<Map<String, dynamic>> websiteRules = const [],
  }) async {
    final resp = await request({
      'type': 'totp_create',
      'website_rules': websiteRules,
      'issuer': issuer,
      'account': account,
      'secret_base32': secretBase32,
      if (groupId != null && groupId.isNotEmpty) 'group_id': groupId,
    }, partitionId: partitionId);
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

  static Future<List<Map<String, dynamic>>> listServerProfiles({String? partitionId}) async {
    final resp = await request({'type': 'server_profile_list'}, partitionId: partitionId);
    final items = payloadOf(resp)['items'] as List<dynamic>? ?? [];
    return items.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  static Future<Map<String, dynamic>> createServerProfile({
    String? partitionId,
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
    }, partitionId: partitionId);
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

  static Future<List<Map<String, dynamic>>> listSshKeys({String? partitionId}) async {
    final resp = await request({'type': 'ssh_key_list'}, partitionId: partitionId);
    final items = payloadOf(resp)['items'] as List<dynamic>? ?? [];
    return items.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  static Future<Map<String, dynamic>> generateSshKey({
    required String label,
    bool setDefault = false,
    String? groupId,
    String comment = '',
    String signPolicy = '',
    List<String> gitRules = const [],
  }) async {
    final resp = await request({
      'type': 'ssh_key_generate',
      'label': label,
      'set_default': setDefault,
      'comment': comment,
      'sign_policy': signPolicy,
      'git_rules': gitRules,
      if (groupId != null && groupId.isNotEmpty) 'group_id': groupId,
    });
    return Map<String, dynamic>.from(payloadOf(resp)['item'] as Map? ?? {});
  }

  static Future<List<Map<String, dynamic>>> listCredentials([String? query, String? partitionId]) async {
    // 分页取元数据，避免超过 200 条后旧账号和服务器关联选项静默消失。
    final items = <Map<String, dynamic>>[];
    final seen = <String>{};
    var offset = 0;
    final scope = partitionId ?? activePartitionId;
    while (true) {
      final resp = await request({
        'type': 'credential_list',
        if (query != null && query.isNotEmpty) 'query': query,
        'limit': 200,
        'offset': offset,
      }, partitionId: scope);
      final page = payloadOf(resp)['items'] as List<dynamic>? ?? [];
      final previousCount = items.length;
      // 分页期间账号可能被更新而移动位置，避免重复项破坏选择框状态。
      for (final entry in page) {
        final item = Map<String, dynamic>.from(entry as Map);
        if (seen.add(item['id'] as String)) items.add(item);
      }
      if (page.length < 200 || items.length == previousCount) return items;
      offset += page.length;
    }
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

  static Future<void> recoverRestorePoint(int createdAtMs, String targetDir, {String? password}) async {
    await request({
      'type': 'restore_point_recover',
      'created_at_ms': createdAtMs,
      'target_dir': targetDir,
      if (password != null) 'password': password,
    });
  }

  static Future<void> migrateVault(String targetDir) async {
    await request({'type': 'vault_migrate', 'target_dir': targetDir});
  }

  static Future<Map<String, dynamic>> securityRebuild(String password, String recoveryKey) async {
    final resp = await request({
      'type': 'vault_security_rebuild',
      'password': password,
      'recovery_key': recoveryKey,
    });
    return payloadOf(resp);
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

  static Future<List<Map<String, dynamic>>> listRecoveryCodes({String? partitionId}) async {
    final resp = await request({'type': 'recovery_codes_list'}, partitionId: partitionId);
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
  AgentException(this.code, this.message, [this.details]);
  final String code;
  final String message;
  final Map<String, dynamic>? details;
  @override
  String toString() => '$code: $message';
}
