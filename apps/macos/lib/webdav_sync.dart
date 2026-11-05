import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';
import 'touch_id_gate.dart';
import 'android_webdav.dart';

/// 生命周期属于 App，而非侧边栏页面；离开同步页后仍可同步，锁定则取消网络操作。
class WebDavSync extends ChangeNotifier with WidgetsBindingObserver {
  static final instance = WebDavSync();
  static const _channel = MethodChannel('credpivot/agent');
  Map<String, dynamic> settings = {}, status = {}, preview = {};
  Map<String, dynamic>? _remote;
  bool unlocked = false, busy = false, _started = false, _attention = false;
  bool _interacting = false;
  int _epoch = 0, _failures = 0;
  DateTime _due = DateTime.now(),
      _retryAfter = DateTime.fromMillisecondsSinceEpoch(0),
      _serverRetryAfter = DateTime.fromMillisecondsSinceEpoch(0);
  Timer? _timer;
  String error = '', backupPath = '', remoteBackupPath = '';
  String cleanupNotice = '';
  String progress = '', lastResult = '';
  Map<String, dynamic>? errorRecord;
  Future<void> Function(String message)? onFailure;
  bool _showingFailure = false;

  String get failureMessage {
    final record = errorRecord;
    final reason = error.isEmpty ? tr('sync.errors.operation') : error;
    if (record == null) return reason;
    const types = {'login': 'login', 'totp': 'mfa', 'ssh': 'ssh', 'ssh_key': 'ssh',
      'server_login': 'server', 'recovery_codes': 'recovery', 'secure_note': 'note',
      'passkey': 'passkey', 'group': 'group', 'partition': 'partition'};
    final type = tr('sync.itemType.${types[record['kind']] ?? 'record'}');
    final title = record['title']?.toString().trim() ?? '';
    final account = record['account']?.toString().trim() ?? '';
    var identifier = [if (title.isNotEmpty) title,
      if (account.isNotEmpty && !title.contains(account)) account].join(' · ');
    if (identifier.isEmpty) {
      final id = record['id']?.toString().split(':').last ?? '';
      identifier = id.isEmpty ? tr('sync.conflict.untitled') : '#${id.length > 8 ? id.substring(0, 8) : id}';
    }
    if (record['trashed'] == true) {
      identifier = tr('sync.errors.trashedItem', args: {'identifier': identifier});
    }
    return tr('sync.errors.itemFailure', args: {'type': type, 'identifier': identifier, 'reason': reason});
  }

  bool get configured => settings['location'] is String;
  bool get connected =>
      configured &&
      status['connected'] == true &&
      status['location'] == settings['location'];
  bool get hasPreview => preview['plan_id'] is String;
  List<Map<String, dynamic>> get conflicts =>
      (preview['conflicts'] as List? ?? [])
          .map((v) => Map<String, dynamic>.from(v as Map))
          .toList();
  Map<String, String> get decisions =>
      Map<String, String>.from(preview['decisions'] as Map? ?? {});

  void start() {
    if (_started) return;
    _started = true;
    WidgetsBinding.instance.addObserver(this);
    AgentBridge.vaultChanges.addListener(_changed);
    _timer = Timer.periodic(const Duration(seconds: 5), (_) => _automatic());
  }

  void stop() {
    _timer?.cancel();
    _timer = null;
    AgentBridge.vaultChanges.removeListener(_changed);
    WidgetsBinding.instance.removeObserver(this);
    _started = false;
    setUnlocked(false);
  }

  void _changed() {
    if (busy) return;
    _due = DateTime.now().add(const Duration(seconds: 15));
    // 业务数据变化后旧预览不能继续应用，需重新生成；Agent 也会检查内容指纹。
    preview = {};
    notifyListeners();
  }

  void setUnlocked(bool value) {
    if (unlocked == value) return;
    unlocked = value;
    _epoch++;
    if (!value) {
      preview = {};
      status = {};
      settings = {};
      _remote = null;
      error = '';
      errorRecord = null;
      backupPath = '';
      remoteBackupPath = '';
      cleanupNotice = '';
      progress = '';
      lastResult = '';
      _attention = false;
      _invoke('webdavCancel').catchError((Object _) => <String, dynamic>{});
    } else {
      _due = DateTime.now();
      refresh().catchError((Object _) {});
    }
    // 调用者可能正在构建页面，通知放到本帧之后。
    WidgetsBinding.instance.addPostFrameCallback((_) => notifyListeners());
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed && unlocked) _due = DateTime.now();
  }

  Future<Map<String, dynamic>> _invoke(String method, [Map<String, dynamic>? args]) async {
    if (Platform.isAndroid) return AndroidWebDav.instance.invoke(method, args);
    return Map<String, dynamic>.from(await _channel.invokeMethod<Map>(method, args) ?? {});
  }
  Future<Map<String, dynamic>> _native(String method, [Map<String, dynamic>? args]) => _invoke(method, args);
  Future<Map<String, dynamic>> _agent(Map<String, dynamic> args) async =>
      AgentBridge.payloadOf(await AgentBridge.request(args));
  Future<void> refresh() async {
    if (!unlocked) return;
    final epoch = _epoch;
    final nextSettings = await _native('webdavSettings');
    final nextStatus = await _agent({'type': 'sync_status'});
    final hostInfo = await AgentBridge.syncHostInfo();
    if (epoch != _epoch || !unlocked) return;
    if (settings['location'] != nextSettings['location']) {
      _remote = null;
      preview = {};
      cleanupNotice = '';
      _serverRetryAfter = DateTime.fromMillisecondsSinceEpoch(0);
      _retryAfter = _serverRetryAfter;
    }
    settings = nextSettings;
    status = {...nextStatus, ...hostInfo};
    notifyListeners();
  }

  void _automatic() {
    if (!unlocked ||
        busy ||
        _showingFailure ||
        !connected ||
        settings['automatic'] != true ||
        _attention ||
        _interacting ||
        hasPreview ||
        DateTime.now().isBefore(_due) ||
        DateTime.now().isBefore(_retryAfter)) {
      return;
    }
    check();
  }

  Future<void> _run(Future<void> Function(int epoch) action) async {
    if (busy || !unlocked || _showingFailure) return;
    busy = true;
    error = '';
    errorRecord = null;
    progress = 'sync.progress.working';
    lastResult = '';
    notifyListeners();
    final epoch = _epoch;
    var failed = false;
    try {
      await action(epoch);
      if (epoch == _epoch) {
        _failures = 0;
        _attention = false;
        // 清理虽不影响同步成功，但服务端限流仍约束整条连接，不能在成功收尾时清掉。
        _retryAfter = _serverRetryAfter;
      }
    } catch (e) {
      if (epoch == _epoch && unlocked) {
        failed = true;
        final details = e is AgentException ? e.details : null;
        final record = details?['record'];
        if (record is Map) {
          errorRecord = {for (final key in ['id', 'kind', 'title', 'account', 'trashed'])
            if (record.containsKey(key)) key: record[key]};
        }
        _failures++;
        // 限流/断网采用退避；认证和格式问题等待用户处理，避免无效轮询。
        final localChanged = e is AgentException &&
            e.code == 'sync_error' &&
            ['sync.errors.localChanged', 'sync.errors.previewExpired']
                .contains(e.message);
        final retryable = localChanged ||
            (e is PlatformException &&
                [
                  'sync_network',
                  'sync.errors.network',
                  'sync.errors.rateLimited',
                  'sync.errors.server',
                  'sync.errors.remoteChanged'
                ].contains(e.code));
        if (localChanged) preview = {};
        _attention = !retryable;
        final serverDelay = e is PlatformException && e.details is Map
            ? (e.details as Map)['retry_after']
            : null;
        _retryAfter = DateTime.now().add(Duration(
            seconds: serverDelay is num
                ? serverDelay.toInt().clamp(60, 86400).toInt()
                : (60 * (1 << _failures.clamp(0, 6).toInt()))
                    .clamp(60, 3600)
                    .toInt()));
        _recordRateLimit(e);
        error = e is AgentException
            ? (e.code == 'sync_error'
                ? tr(e.message)
                : AgentBridge.friendlyMessage(e))
            : e is PlatformException
                ? (e.message ?? tr('sync.errors.network'))
                : tr('sync.errors.operation');
        // 首次应用已提交但网络发布失败时，也要展示待发布状态并允许自动重试。
        try {
          await refresh();
        } catch (_) {}
      }
    } finally {
      if (epoch == _epoch) {
        _due = DateTime.now().add(Duration(
            seconds: (settings['interval_seconds'] as num?)?.toInt() ?? 300));
      }
      busy = false;
      progress = '';
      final handler = failed && epoch == _epoch && unlocked ? onFailure : null;
      final message = handler != null ? failureMessage : '';
      _showingFailure = handler != null;
      notifyListeners();
      try {
        if (handler != null) await handler(message);
      } finally {
        _showingFailure = false;
      }
    }
  }

  void _recordRateLimit(Object error) {
    if (error is! PlatformException ||
        error.code != 'sync.errors.rateLimited') {
      return;
    }
    final seconds =
        error.details is Map ? (error.details as Map)['retry_after'] : null;
    final until = DateTime.now().add(Duration(
        seconds:
            seconds is num ? seconds.toInt().clamp(1, 86400).toInt() : 120));
    if (until.isAfter(_serverRetryAfter)) _serverRetryAfter = until;
    if (_serverRetryAfter.isAfter(_retryAfter)) _retryAfter = _serverRetryAfter;
  }

  Future<void> save(Map<String, dynamic> values) => _run((epoch) async {
        final saved = await _native('webdavSave', {...values, 'verify': true});
        if (epoch != _epoch) return;
        if (settings['location'] != saved['location']) {
          _serverRetryAfter = DateTime.fromMillisecondsSinceEpoch(0);
          _retryAfter = _serverRetryAfter;
        }
        settings = saved;
        preview = {};
        _remote = null;
        await refresh();
      });

  Future<Map<String, dynamic>> testConfiguration(
      Map<String, dynamic> values) async {
    try {
      return await _native('webdavTest', values);
    } on PlatformException catch (e) {
      _recordRateLimit(e);
      final details = e.details is Map ? e.details as Map : const {};
      return {
        'ok': false,
        'cancelled': e.code == 'sync.test.cancelled',
        'checks': details['checks'] ?? [],
        'message': e.message ?? tr('sync.errors.operation'),
      };
    } catch (_) {
      return {
        'ok': false,
        'checks': [],
        'message': tr('sync.errors.operation')
      };
    }
  }

  Future<void> cancelConfigurationTest() async { await _invoke('webdavTestCancel'); }
  Future<void> _prepare(int epoch,
      {String? strategy, String remotePassword = ''}) async {
    progress = 'sync.progress.preparing';
    notifyListeners();
    final remote = await _native('webdavRead',
        _remote?['etag'] is String ? {'etag': _remote!['etag']} : null);
    if (epoch != _epoch || !unlocked) return;
    if (remote['not_modified'] != true) _remote = remote;
    final source = _remote;
    if (source == null || source['location'] != settings['location']) {
      throw StateError('sync context changed');
    }
    final result = await _agent({
      'type': 'sync_prepare',
      'location': settings['location'],
      'head': source['head'],
      'remote_ovb': source['remote_ovb'],
      if (strategy != null) 'strategy': strategy,
      'remote_password': remotePassword
    });
    if (epoch != _epoch || !unlocked) return;
    preview = result;
  }

  Future<void> prepareInitial(String strategy, String remotePassword) =>
      _run((epoch) async {
        await _native('webdavProbe');
        if (epoch == _epoch) {
          await _prepare(epoch,
              strategy: strategy, remotePassword: remotePassword);
        }
      });
  Future<void> check() => _run((epoch) async {
        _attention = false;
        await refresh();
        if (!connected || epoch != _epoch) return;
        await _prepare(epoch);
        if (epoch == _epoch && hasPreview && conflicts.isEmpty) {
          await _apply(epoch);
        }
      });
  Future<void> choose(String key, String side) async {
    if (busy || !hasPreview) return;
    final updated = {...decisions, key: side};
    final offset = (preview['changes_offset'] as num?)?.toInt() ?? 0;
    await _run((epoch) async {
      final result = await _agent({
        'type': 'sync_resolve',
        'plan_id': preview['plan_id'],
        'decisions': updated
      });
      if (epoch == _epoch) {
        preview = result;
        if (offset > 0) {
          final page = await _agent({'type': 'sync_preview_page',
            'plan_id': result['plan_id'], 'offset': offset, 'limit': 20});
          if (epoch == _epoch && preview['plan_id'] == page['plan_id']) {
            preview = {...preview, ...page};
          }
        }
      }
    });
  }

  Future<void> loadPreviewPage(int offset) async {
    if (busy || !hasPreview) return;
    final planId = preview['plan_id'];
    await _run((epoch) async {
      final page = await _agent({'type': 'sync_preview_page',
        'plan_id': planId, 'offset': offset, 'limit': 20});
      if (epoch == _epoch && preview['plan_id'] == page['plan_id']) {
        preview = {...preview, ...page};
      }
    });
  }

  Future<void> interact(Future<void> Function() action) async {
    if (busy || _interacting) return;
    // 配置和身份验证窗口打开期间，不启动后台同步来抢占用户的本次操作。
    _interacting = true;
    try {
      await action();
    } finally {
      _interacting = false;
    }
  }

  Future<void> apply() => _run(_apply);

  Future<void> cancelPreview() => _run((epoch) async {
        await _agent({'type': 'sync_cancel'});
        if (epoch == _epoch) {
          preview = {};
        }
      });
  Future<void> _apply(int epoch) async {
    if (!hasPreview || _remote == null) {
      throw AgentException('sync_error', 'sync.errors.previewExpired');
    }
    progress = 'sync.progress.applying';
    notifyListeners();
    final location = settings['location'];
    final tag = _remote!['etag'];
    final expectedHead = _remote!['head'];
    dynamic cleanupHead = expectedHead, cleanupTag = tag;
    final hostInfo = await AgentBridge.syncHostInfo();
    if (epoch != _epoch || !unlocked) return;
    final result = await _agent({'type': 'sync_apply', 'plan_id': preview['plan_id'],
      'host_name': hostInfo['sync_host_name'] ?? ''});
    if (epoch != _epoch || !unlocked) return;
    preview = {};
    backupPath = result['backup_path']?.toString() ?? backupPath;
    if (result['changed'] == true) AgentBridge.notifyVaultChanged();
    if (result['no_upload'] != true) {
      progress = 'sync.progress.uploading';
      notifyListeners();
      remoteBackupPath =
          expectedHead is Map ? expectedHead['snapshot']?.toString() ?? '' : '';
      final published = await _native('webdavPublish', {
        'location': location,
        'etag': tag,
        'expected_head': expectedHead,
        'head': result['head'],
        'ovb': result['ovb']
      });
      if (epoch != _epoch || !unlocked) return;
      cleanupHead = result['head'];
      cleanupTag = published['etag'];
      remoteBackupPath = published['remote_backup_path']?.toString() ?? '';
      progress = 'sync.progress.acknowledging';
      notifyListeners();
      await _agent({
        'type': 'sync_acknowledge',
        'location': location,
        'head': result['head']
      });
    }
    _remote = null;
    if (epoch == _epoch) await refresh();
    if (epoch != _epoch || !unlocked) return;
    // 仅在远端发布/确认和状态刷新完成后展示成功；清理失败另行提示。
    lastResult = tr(result['no_upload'] == true && result['changed'] != true
        ? 'sync.result.upToDate'
        : 'sync.result.completed');
    notifyListeners();
    // 只有已验证并完成确认的远端版本才能作为清理依据；失败上传留到后续成功同步再处理。
    if (epoch == _epoch &&
        unlocked &&
        connected &&
        status['pending_upload'] == false &&
        cleanupHead is Map &&
        cleanupTag is String) {
      try {
        progress = 'sync.progress.cleanup';
        notifyListeners();
        final cleaned = await _native('webdavCleanup',
            {'location': location, 'head': cleanupHead, 'etag': cleanupTag});
        if (epoch == _epoch && cleaned['completed'] == true) cleanupNotice = '';
      } catch (e) {
        if (epoch != _epoch || !unlocked) return;
        _recordRateLimit(e);
        const reasons = {
          'sync.cleanup.deferred',
          'sync.cleanup.incomplete',
          'sync.cleanup.changed',
          'sync.cleanup.deleteUnsupported'
        };
        // 清理异常独立展示，不把已成功的同步改成失败或暂停自动同步。
        cleanupNotice =
            e is PlatformException && e.code == 'sync.errors.rateLimited'
                ? e.message ?? tr('sync.errors.rateLimited')
                : tr(e is PlatformException && reasons.contains(e.code)
                    ? e.code
                    : 'sync.cleanup.failed');
      }
    }
  }

  Future<void> pause(bool automatic) => _run((epoch) async {
        final saved =
            await _native('webdavSave', {...settings, 'automatic': automatic});
        if (epoch == _epoch) {
          settings = saved;
          _attention = false;
          _due = DateTime.now();
        }
      });
  Future<void> disconnect() => _run((epoch) async {
        await _native('webdavRemove');
        if (epoch == _epoch) {
          settings = {};
          status = {};
          preview = {};
          _remote = null;
          backupPath = '';
          remoteBackupPath = '';
          cleanupNotice = '';
          lastResult = '';
        }
      });
}

class WebDavSyncPage extends StatelessWidget {
  const WebDavSyncPage({super.key});
  WebDavSync get sync => WebDavSync.instance;

  static Future<Map<String, dynamic>?> configurationDraft(BuildContext context, {bool bootstrap = false, Map<String, dynamic>? initialSettings}) async {
    final sync = WebDavSync.instance;
    final stored = initialSettings ?? (bootstrap ? <String, dynamic>{} : sync.settings);
    final storedServer = stored['server_url']?.toString() ?? '';
    final server = TextEditingController(
        text: storedServer.isEmpty
            ? stored['root']?.toString() ?? ''
            : storedServer);
    final existing = Uri.tryParse(server.text);
    final port = TextEditingController(
        text: stored['port']?.toString() ?? (existing?.hasPort == true ? existing!.port.toString() : ''));
    final directory = TextEditingController(
        text: storedServer.isEmpty
            ? ((stored['location'] is String) ? '' : 'CredPivot')
            : stored['directory']?.toString() ?? '');
    final username = TextEditingController(
        text: stored['username']?.toString() ?? '');
    final password = TextEditingController(text: bootstrap ? stored['password']?.toString() ?? '' : '');
    final dailyHistoryCount = TextEditingController(
        text: ((stored['daily_history_count'] as num?)?.toInt() ?? 5).toString());
    // 下一项实现 S3 / S3 兼容存储；目前仅展示入口，不提交为 WebDAV 配置。
    const providers = ['custom', 'nutstore', 'nextcloud', 'owncloud', 's3'];
    var provider = stored['provider']?.toString() ?? 'custom';
    if (!providers.contains(provider)) provider = 'custom';
    var interval = (stored['interval_seconds'] as num?)?.toInt() ?? 300;
    final intervals = {60, 300, 900, 1800, 3600, interval}.toList()..sort();
    var automatic = stored['automatic'] != false;
    final initial = [
      server.text,
      port.text,
      directory.text,
      username.text,
      provider,
      interval,
      automatic,
      dailyHistoryCount.text
    ];
    final form = GlobalKey<FormState>();
    var testing = false;
    var testStarted = false, cancelRequested = false;
    Map<String, dynamic>? testReport;
    void clearTest() => testReport = null;
    Map<String, dynamic> draftValues() => {
          'provider': provider,
          'server_url': server.text.trim(),
          'port': port.text.trim(),
          'directory': directory.text,
          'username': username.text.trim(),
          'password': password.text,
          'automatic': automatic,
          'interval_seconds': interval,
          'daily_history_count': int.tryParse(dailyHistoryCount.text.trim()),
        };
    String? addressError(String? value) {
      try {
        final text = value?.trim() ?? '';
        final uri = Uri.tryParse(text);
        if (uri == null ||
            uri.scheme.toLowerCase() != 'https' ||
            uri.host.isEmpty ||
            uri.userInfo.isNotEmpty ||
            uri.hasQuery ||
            uri.hasFragment ||
            RegExp(r'[\x00-\x20\x7f\\]').hasMatch(text) ||
            uri.pathSegments.any((s) => s == '.' || s == '..')) {
          return tr('sync.errors.address');
        }
        if (uri.hasPort && (uri.port < 1 || uri.port > 65535)) {
          return tr('sync.errors.port');
        }
        return null;
      } on FormatException {
        return tr('sync.errors.address');
      }
    }

    String? portError(String? value) {
      final text = value?.trim() ?? '';
      if (text.isEmpty) return null;
      final number = int.tryParse(text);
      if (number == null || number < 1 || number > 65535) {
        return tr('sync.errors.port');
      }
      try {
        final uri = Uri.tryParse(server.text.trim());
        if (uri?.hasPort == true && uri!.port != number) {
          return tr('sync.errors.portConflict');
        }
      } on FormatException {
        return tr('sync.errors.address');
      }
      return null;
    }

    String? directoryError(String? value) {
      final text = value ?? '';
      if (utf8.encode(text).length > 2048 ||
          RegExp(r'[\x00-\x1f\x7f\\]').hasMatch(text) ||
          text.split('/').any((s) => s == '.' || s == '..')) {
        return tr('sync.errors.directoryPath');
      }
      return null;
    }

    String previewUrl() {
      if (addressError(server.text) != null ||
          portError(port.text) != null ||
          directoryError(directory.text) != null) {
        return '';
      }
      final uri = Uri.parse(server.text.trim());
      final segments = uri.pathSegments.toList();
      if (segments.isNotEmpty && segments.last.isEmpty) {
        segments.removeLast();
      }
      segments.addAll(directory.text.split('/').where((s) => s.isNotEmpty));
      segments.add('');
      var resolved = uri.replace(
          port: port.text.trim().isEmpty ? null : int.parse(port.text.trim()),
          pathSegments: segments);
      if (resolved.path.isEmpty) {
        resolved = resolved.replace(path: '/');
      }
      return resolved.toString();
    }

    Map<String, dynamic>? values;
    try {
      values = await showDraftDialog<Map<String, dynamic>>(
          context: context,
          isBusy: () => testing,
          hasChanges: () =>
              password.text.isNotEmpty ||
              [
                server.text,
                port.text,
                directory.text,
                username.text,
                provider == 's3' ? initial[4] : provider,
                interval,
                automatic,
                dailyHistoryCount.text
              ]
                  .asMap()
                  .entries
                  .any((entry) => entry.value != initial[entry.key]),
          builder: (ctx) => StatefulBuilder(
              builder: (ctx, setLocal) => AlertDialog(
                    title: LText(bootstrap ? 'sync.bootstrap.configure' : 'sync.configure.title'),
                    content: SizedBox(
                        width: appEditDialogWidth(ctx),
                        child: AbsorbPointer(
                            absorbing: testing,
                            child: SingleChildScrollView(
                                child: Form(
                                    key: form,
                                    child: Column(
                                        mainAxisSize: MainAxisSize.min,
                                        crossAxisAlignment:
                                            CrossAxisAlignment.stretch,
                                        children: [
                                          if (provider != 's3') ...[
                                            const LText('sync.configure.help'),
                                            const SizedBox(height: 20),
                                          ],
                                          AppFieldRow(label: tr(
                                                      'sync.configure.provider'), child: DropdownButtonFormField<String>(
                                              initialValue: provider,
                                              isExpanded: true,
                                              decoration: InputDecoration(),
                                              items: providers
                                                  .map((v) => DropdownMenuItem(
                                                      value: v,
                                                      child: LText(
                                                          'sync.providers.$v')))
                                                  .toList(),
                                              onChanged: (value) {
                                                if (value != null) {
                                                  setLocal(() {
                                                    clearTest();
                                                    provider = value;
                                                    // 模板只补全空地址，切换提供方不覆盖用户已经输入的自定义连接。
                                                    if (server.text
                                                            .trim()
                                                            .isEmpty &&
                                                        value == 'nutstore') {
                                                      server.text =
                                                          'https://dav.jianguoyun.com/dav/';
                                                    }
                                                  });
                                                }
                                              })),
                                          const SizedBox(height: 18),
                                          if (provider == 's3')
                                            AppNotice(tr(
                                                'sync.providers.s3Unavailable'))
                                          else ...[
                                            LText(provider == 'nutstore'
                                                ? 'sync.configure.policyNutstore'
                                                : 'sync.configure.policyStandard'),
                                            const SizedBox(height: 18),
                                            AppFieldRow(label: tr(
                                                        'sync.configure.server'), help: tr(
                                                        'sync.configure.serverHelp'), child: TextFormField(
                                                controller: server,
                                                autocorrect: false,
                                                enableSuggestions: false,
                                                validator: addressError,
                                                onChanged: (_) =>
                                                    setLocal(clearTest),
                                                decoration: InputDecoration(errorMaxLines: 3))),
                                            const SizedBox(height: 18),
                                            AppFieldRow(label: tr(
                                                        'sync.configure.port'), help: tr(
                                                        'sync.configure.portHelp'), child: TextFormField(
                                                controller: port,
                                                keyboardType:
                                                    TextInputType.number,
                                                validator: portError,
                                                onChanged: (_) =>
                                                    setLocal(clearTest),
                                                decoration: InputDecoration(errorMaxLines: 3))),
                                            const SizedBox(height: 18),
                                            AppFieldRow(label: tr(
                                                        'sync.configure.directory'), help: tr(
                                                        'sync.configure.directoryHelp'), child: TextFormField(
                                                controller: directory,
                                                autocorrect: false,
                                                enableSuggestions: false,
                                                validator: directoryError,
                                                onChanged: (_) =>
                                                    setLocal(clearTest),
                                                decoration: InputDecoration(errorMaxLines: 3))),
                                            if (previewUrl().isNotEmpty) ...[
                                              const SizedBox(height: 12),
                                              const LText(
                                                  'sync.configure.resolvedUrl'),
                                              const SizedBox(height: 6),
                                              SelectableText(previewUrl()),
                                            ],
                                            const SizedBox(height: 18),
                                            AppFieldRow(label: tr(
                                                        'sync.configure.username'), child: TextFormField(
                                                controller: username,
                                                onChanged: (_) =>
                                                    setLocal(clearTest),
                                                autocorrect: false,
                                                enableSuggestions: false,
                                                validator: (v) => v == null ||
                                                        v.trim().isEmpty ||
                                                        utf8
                                                                .encode(
                                                                    v.trim())
                                                                .length >
                                                            1024 ||
                                                        v.contains(':') ||
                                                        RegExp(r'[\x00-\x1f\x7f]')
                                                            .hasMatch(v)
                                                    ? tr('sync.errors.username')
                                                    : null,
                                                decoration: InputDecoration(errorMaxLines: 3))),
                                            const SizedBox(height: 18),
                                            AppFieldRow(label: tr(
                                                        'sync.configure.password'), help: tr(
                                                        'sync.configure.passwordHelp'), child: TextFormField(
                                                controller: password,
                                                onChanged: (_) =>
                                                    setLocal(clearTest),
                                                obscureText: true,
                                                autocorrect: false,
                                                enableSuggestions: false,
                                                validator: (v) => (v == null ||
                                                            v.isEmpty) &&
                                                        (stored['password_saved'] !=
                                                                true ||
                                                            previewUrl() !=
                                                                stored[
                                                                    'root'] ||
                                                            username.text
                                                                    .trim() !=
                                                                stored[
                                                                    'username'])
                                                    ? tr(
                                                        'sync.errors.passwordMissing')
                                                    : null,
                                                decoration: InputDecoration(errorMaxLines: 3))),
                                            const SizedBox(height: 18),
                                            AppFieldRow(label: tr(
                                                        'sync.configure.interval'), child: DropdownButtonFormField<int>(isExpanded: true,
                                                initialValue: interval,
                                                decoration: InputDecoration(),
                                                items: intervals
                                                    .map((v) => DropdownMenuItem(
                                                        value: v,
                                                        child: v % 60 == 0
                                                            ? LText(
                                                                'sync.configure.minutes',
                                                                args: {
                                                                    'minutes':
                                                                        v ~/ 60
                                                                  })
                                                            : LText(
                                                                'sync.configure.seconds',
                                                                args: {
                                                                    'seconds': v
                                                                  })))
                                                    .toList(),
                                                onChanged: (value) {
                                                  if (value != null) {
                                                    setLocal(() {
                                                      clearTest();
                                                      interval = value;
                                                    });
                                                  }
                                                })),
                                            const SizedBox(height: 18),
                                            AppFieldRow(label: tr('sync.configure.dailyHistoryCount'), help: tr('sync.configure.dailyHistoryHelp'), child: TextFormField(
                                                controller: dailyHistoryCount,
                                                keyboardType: TextInputType.number,
                                                inputFormatters: [
                                                  FilteringTextInputFormatter.digitsOnly,
                                                ],
                                                decoration: InputDecoration(),
                                                validator: (value) {
                                                  final count = int.tryParse(value?.trim() ?? '');
                                                  return count == null || count < 3 || count > 99
                                                      ? tr('sync.errors.dailyHistoryCount') : null;
                                                },
                                                onChanged: (_) => setLocal(clearTest))),
                                            AppFieldRow(label: tr('sync.configure.automatic'),
                                              child: Align(alignment: Alignment.centerLeft, child: Switch(
                                                value: automatic,
                                                onChanged: (value) =>
                                                    setLocal(() {
                                                      clearTest();
                                                      automatic = value;
                                                    })))),
                                            const SizedBox(height: 16),
                                            LText(bootstrap ? 'sync.bootstrap.connectionHelp' : 'sync.test.help'),
                                            if (testing) ...[
                                              const SizedBox(height: 12),
                                              const LinearProgressIndicator(),
                                              const SizedBox(height: 8),
                                              const LText('sync.test.running'),
                                            ],
                                            if (testReport != null) ...[
                                              const SizedBox(height: 14),
                                              Text(
                                                  tr(testReport!['cancelled'] ==
                                                          true
                                                      ? 'sync.test.cancelled'
                                                      : testReport!['ok'] ==
                                                              true
                                                          ? 'sync.test.success'
                                                          : 'sync.test.failed'),
                                                  style: const TextStyle(
                                                      fontWeight:
                                                          FontWeight.w600)),
                                              for (final check
                                                  in (testReport!['checks']
                                                          as List? ??
                                                      []))
                                                Padding(
                                                    padding:
                                                        const EdgeInsets.only(
                                                            top: 10),
                                                    child: Row(
                                                        crossAxisAlignment:
                                                            CrossAxisAlignment
                                                                .start,
                                                        children: [
                                                          Icon(
                                                              check['passed'] ==
                                                                      true
                                                                  ? Icons
                                                                      .check_circle_outline
                                                                  : Icons
                                                                      .info_outline,
                                                              size: 18,
                                                              color: check[
                                                                          'passed'] ==
                                                                      true
                                                                  ? Theme.of(
                                                                          ctx)
                                                                      .colorScheme
                                                                      .primary
                                                                  : Theme.of(
                                                                          ctx)
                                                                      .colorScheme
                                                                      .tertiary),
                                                          const SizedBox(
                                                              width: 8),
                                                          Expanded(
                                                              child: Text([
                                                            tr('sync.probe.${check['key']}'),
                                                            if ((check['statuses']
                                                                        as List? ??
                                                                    [])
                                                                .isNotEmpty)
                                                              'HTTP ${(check['statuses'] as List).join(', ')}',
                                                            if (check['passed'] !=
                                                                    true &&
                                                                check['skipped'] !=
                                                                    true)
                                                              tr('sync.test.fallback'),
                                                          ].join(' · '))),
                                                        ])),
                                              if (testReport!['ok'] ==
                                                  true) ...[
                                                const SizedBox(height: 12),
                                                LText('sync.test.initialMode',
                                                    args: {
                                                      'mode': tr(
                                                          'sync.test.mode.${testReport!['initial_creation']}')
                                                    }),
                                              ],
                                              if (testReport!['message']
                                                  is String) ...[
                                                const SizedBox(height: 12),
                                                AppNotice(testReport!['message']
                                                    as String),
                                              ],
                                            ],
                                          ],
                                        ]))))),
                    actions: [
                      TextButton(
                          onPressed: cancelRequested
                              ? null
                              : () async {
                                  if (testing) {
                                    setLocal(() => cancelRequested = true);
                                    if (testStarted) {
                                      await sync.cancelConfigurationTest();
                                    }
                                    return;
                                  }
                                  Navigator.pop(ctx);
                                },
                          child: LText(
                              testing ? 'sync.test.stop' : 'common.cancel')),
                      if (!bootstrap) OutlinedButton.icon(
                          onPressed: testing || provider == 's3'
                              ? null
                              : () async {
                                  if (form.currentState?.validate() != true) {
                                    return;
                                  }
                                  final draft = draftValues();
                                  setLocal(() {
                                    testing = true;
                                    cancelRequested = false;
                                    clearTest();
                                  });
                                  try {
                                    if (!await requireTouchId(ctx,
                                        reason: 'sync.auth.test')) {
                                      return;
                                    }
                                    if (!ctx.mounted || !sync.unlocked) return;
                                    if (cancelRequested) {
                                      setLocal(() => testReport = {
                                            'ok': false,
                                            'cancelled': true,
                                            'checks': []
                                          });
                                      return;
                                    }
                                    testStarted = true;
                                    final report =
                                        await sync.testConfiguration(draft);
                                    if (ctx.mounted) {
                                      setLocal(() => testReport = report);
                                    }
                                  } finally {
                                    draft['password'] = '';
                                    testStarted = false;
                                    if (ctx.mounted) {
                                      setLocal(() {
                                        testing = false;
                                        cancelRequested = false;
                                      });
                                    }
                                  }
                                },
                          icon: const Icon(Icons.network_check, size: 18),
                          label: const LText('sync.test.action')),
                      FilledButton(
                          onPressed: provider == 's3' || testing
                              ? null
                              : () {
                                  if (form.currentState!.validate()) {
                                    Navigator.pop(ctx, draftValues());
                                  }
                                },
                          child: LText(bootstrap ? 'common.continue' : 'sync.configure.save')),
                    ],
                  )));
    } finally {
      server.dispose();
      port.dispose();
      directory.dispose();
      username.dispose();
      password.dispose();
      dailyHistoryCount.dispose();
    }
    return values;
  }

  Future<void> _configure(BuildContext context) async {
    final values = await configurationDraft(context);
    if (values == null || !context.mounted) return;
    if (!await requireTouchId(context, reason: 'sync.auth.configure')) {
      values['password'] = '';
      return;
    }
    try { await sync.save(values); }
    finally { values['password'] = ''; }
  }

  Future<void> _initial(BuildContext context) async {
    String? strategy;
    final password = TextEditingController();
    Map<String, String>? values;
    try {
      values = await showDraftDialog<Map<String, String>>(
          context: context,
          hasChanges: () => strategy != null || password.text.isNotEmpty,
          builder: (ctx) => StatefulBuilder(
              builder: (ctx, setLocal) => AlertDialog(
                    title: const LText('sync.initial.title'),
                    content: SizedBox(
                        width: appEditDialogWidth(ctx),
                        child: SingleChildScrollView(
                            child: Column(
                                mainAxisSize: MainAxisSize.min,
                                crossAxisAlignment: CrossAxisAlignment.stretch,
                                children: [
                              const LText('sync.initial.help'),
                              const SizedBox(height: 18),
                              RadioGroup<String>(
                                  groupValue: strategy,
                                  onChanged: (value) =>
                                      setLocal(() => strategy = value),
                                  child: Column(children: [
                                    for (final value in [
                                      'remote',
                                      'local',
                                      'merge'
                                    ]) ...[
                                      RadioListTile<String>(
                                          value: value,
                                          contentPadding: EdgeInsets.zero,
                                          title: LText('sync.strategy.$value'),
                                          subtitle: LText(
                                              'sync.strategy.${value}Help')),
                                      const SizedBox(height: 8)
                                    ],
                                  ])),
                              const SizedBox(height: 12),
                              AppFieldRow(label: tr('sync.initial.remotePassword'), help: tr(
                                          'sync.initial.remotePasswordHelp'), child: TextField(
                                  controller: password,
                                  obscureText: true,
                                  autocorrect: false,
                                  enableSuggestions: false,
                                  decoration: InputDecoration())),
                            ]))),
                    actions: [
                      TextButton(
                          onPressed: () => Navigator.pop(ctx),
                          child: const LText('common.cancel')),
                      FilledButton(
                          onPressed: strategy == null
                              ? null
                              : () => Navigator.pop(ctx, {
                                    'strategy': strategy!,
                                    'password': password.text
                                  }),
                          child: const LText('sync.initial.preview'))
                    ],
                  )));
    } finally {
      password.dispose();
    }
    if (values == null || !context.mounted) return;
    try {
      await sync.prepareInitial(values['strategy']!, values['password']!);
      _showSyncResult(context);
    } finally {
      values['password'] = '';
    }
  }

  Future<void> _apply(BuildContext context) async {
    if (await requireTouchId(context, reason: 'sync.auth.apply')) {
      await sync.apply();
      _showSyncResult(context);
    }
  }

  Future<void> _check(BuildContext context) async {
    await sync.check();
    _showSyncResult(context);
  }

  void _showSyncResult(BuildContext context) {
    if (!context.mounted || !sync.unlocked) return;
    // 失败由 App 根页面统一弹窗，避免手动操作再重复弹出或排队显示底部提示。
    if (sync.error.isNotEmpty) return;
    final message = sync.hasPreview
            ? tr('sync.result.needsReview')
            : sync.lastResult;
    if (message.isEmpty) return;
    // 确认按钮位于预览底部；浮动提示避免结果只出现在屏幕上方而被忽略。
    final messenger = ScaffoldMessenger.of(context);
    messenger.hideCurrentSnackBar();
    messenger.showSnackBar(SnackBar(
        content: Text(message), duration: const Duration(seconds: 6)));
  }

  Future<void> _disconnect(BuildContext context) async {
    if (await requireTouchId(context, reason: 'sync.auth.disconnect')) {
      await sync.disconnect();
    }
  }

  Future<void> _toggle(BuildContext context) async {
    if (await requireTouchId(context, reason: 'sync.auth.configure')) {
      await sync.pause(sync.settings['automatic'] != true);
    }
  }

  String _time(dynamic value) {
    if (value is! num || value <= 0) return tr('sync.time.unknown');
    final date = DateTime.fromMillisecondsSinceEpoch(value.toInt()).toLocal();
    String two(int n) => n.toString().padLeft(2, '0');
    return '${date.year}-${two(date.month)}-${two(date.day)} ${two(date.hour)}:${two(date.minute)}:${two(date.second)} ${date.timeZoneName}';
  }

  String _field(String value) {
    if (value == 'deletion') return tr('sync.fields.deletion');
    final table = value.split('.').first, field = value.split('.').last;
    if (['secret', 'active_password_revision', 'password_active_since_ms']
        .contains(field)) {
      return tr('sync.fields.password');
    }
    if (field == 'username') return tr('sync.fields.username');
    if (['origin', 'uris', 'pending_mfa_uris'].contains(field)) return tr('sync.fields.websites');
    if (field == 'notes') return tr('sync.fields.notes');
    if (field == 'custom_fields') return tr('sync.fields.customFields');
    if (field == 'related_item_ids') return tr('sync.fields.relatedRecords');
    if (['tags', 'favorite', 'category'].contains(field)) return tr('sync.fields.organization');
    if (['history_limit', 'reminder_days', 'mfa_state', 'ssh_sign_policy'].contains(field)) return tr('sync.fields.policy');
    if (['linked_mfa_ids', 'mfa_bindings', 'otp_extra_parameters'].contains(field)) return tr('sync.fields.mfa');
    if (field == 'linked_login_id') return tr('sync.fields.loginLink');
    if (field == 'partition_id') return tr('partitions.label');
    if (field == 'linked_ssh_key_id') return tr('sync.fields.ssh');
    if (field == 'details_json') return tr('sync.fields.details');
    if (field == 'title' || field == 'name' || field == 'label') {
      return tr('sync.fields.title');
    }
    if (field == 'group_id' || table == 'credential_groups') {
      return tr('sync.fields.group');
    }
    if (field == 'trashed' || field == 'trashed_at_ms') {
      return tr('sync.fields.trash');
    }
    if (table == 'totp_credentials' || field == 'linked_totp_id') {
      return tr('sync.fields.mfa');
    }
    if (table == 'password_candidates' || table == 'password_history') {
      return tr('sync.fields.history');
    }
    if (table.startsWith('recovery_code')) {
      return tr('sync.fields.recoveryCodes');
    }
    if (table == 'ssh_keys') return tr('sync.fields.ssh');
    if (table == 'passkey_credentials') return tr('sync.fields.passkey');
    if (table == 'server_login_profiles') return tr('sync.fields.server');
    return tr('sync.fields.other');
  }

  Widget _side(
      Map<String, dynamic> conflict, String side, BuildContext context) {
    final info = Map<String, dynamic>.from(conflict[side] as Map);
    final selected = sync.decisions[conflict['key']] == side;
    return Expanded(
        child: Material(
            color: selected
                ? AppColors.primary.withValues(alpha: .08)
                : AppColors.background,
            borderRadius: BorderRadius.circular(12),
            child: InkWell(
                borderRadius: BorderRadius.circular(12),
                onTap: sync.busy
                    ? null
                    : () => sync.choose(conflict['key'] as String, side),
                child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(children: [
                            Icon(
                                selected
                                    ? Icons.radio_button_checked
                                    : Icons.radio_button_off,
                                size: 18,
                                color: selected
                                    ? AppColors.primary
                                    : AppColors.muted),
                            const SizedBox(width: 8),
                            Expanded(child: LText('sync.side.$side'))
                          ]),
                          const SizedBox(height: 12),
                          if (info['deleted'] == true)
                            const LText('sync.conflict.deleted')
                          else
                            Text(
                                info['title']?.toString() ??
                                    tr('sync.conflict.untitled'),
                                style: const TextStyle(
                                    fontWeight: FontWeight.w600)),
                          const SizedBox(height: 8),
                          if ((info['partition_name']?.toString() ?? '').isNotEmpty)
                            Text('${tr('partitions.label')}：${info['partition_name']}'),
                          LText('sync.conflict.created',
                              args: {'time': _time(info['created_at_ms'])}),
                          const SizedBox(height: 6),
                          LText('sync.conflict.modified',
                              args: {'time': _time(info['updated_at_ms'])}),
                        ])))));
  }

  Widget _conflict(Map<String, dynamic> conflict, BuildContext context) {
    final local = conflict['local'] as Map, remote = conflict['remote'] as Map;
    final lt = local['updated_at_ms'], rt = remote['updated_at_ms'];
    final seconds =
        lt is num && rt is num ? ((lt - rt).abs() / 1000).round() : null;
    return Container(
        margin: const EdgeInsets.only(top: 16),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
            border: Border.all(color: AppColors.border),
            borderRadius: BorderRadius.circular(14)),
        child:
            Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text(
              (local['title'] ??
                      remote['title'] ??
                      tr('sync.conflict.untitled'))
                  .toString(),
              style: const TextStyle(fontWeight: FontWeight.w600)),
          const SizedBox(height: 8),
          LText('sync.conflict.fields', args: {
            'fields': (conflict['changed_fields'] as List)
                .map((v) => _field(v.toString()))
                .toSet()
                .join('、')
          }),
          const SizedBox(height: 8),
          if (seconds != null)
            LText('sync.conflict.timeDifference', args: {
              'days': seconds ~/ 86400,
              'hours': seconds % 86400 ~/ 3600,
              'minutes': seconds % 3600 ~/ 60,
              'seconds': seconds % 60
            }),
          const SizedBox(height: 14),
          Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            _side(conflict, 'local', context),
            const SizedBox(width: 12),
            _side(conflict, 'remote', context)
          ]),
        ]));
  }

  Widget _diffSide(BuildContext context, Map? metadata, {String? action}) {
    if (metadata == null) return const LText('sync.diff.pending');
    final color = action == 'deleted'
        ? Theme.of(context).colorScheme.error
        : action == 'added'
            ? AppColors.green
            : AppColors.primary;
    return SizedBox(
      width: 220,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (action != null) ...[
            LText('sync.diff.action.$action', style: TextStyle(color: color, fontWeight: FontWeight.w600)),
            const SizedBox(height: 6),
          ],
          if (metadata['deleted'] == true)
            const LText('sync.diff.absent')
          else ...[
            Text(metadata['title']?.toString() ?? tr('sync.conflict.untitled'),
                maxLines: 2, overflow: TextOverflow.ellipsis),
            for (final field in ['partition_name', 'username', 'website'])
              if ((metadata[field]?.toString() ?? '').isNotEmpty)
                Tooltip(message: metadata[field].toString(),
                    child: Text(metadata[field].toString(), maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(fontSize: 12, color: AppColors.muted))),
            if (metadata['trashed'] == true) const LText('sync.diff.trashed'),
            Text(_time(metadata['updated_at_ms']),
                style: TextStyle(fontSize: 11, color: AppColors.muted)),
          ],
        ],
      ),
    );
  }

  Widget _diffTable(BuildContext context) {
    if (!sync.preview.containsKey('changes')) {
      return AppNotice(tr('sync.diff.unavailable'));
    }
    final rows = (sync.preview['changes'] as List? ?? [])
        .map((value) => Map<String, dynamic>.from(value as Map)).toList();
    if (rows.isEmpty) return AppNotice(tr('sync.diff.noChanges'));
    final start = (sync.preview['changes_offset'] as num?)?.toInt() ?? 0;
    final total = (sync.preview['changes_total'] as num?)?.toInt() ?? rows.length;
    final end = start + rows.length;
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        const LText('sync.diff.help'),
        const SizedBox(height: 12),
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: DataTable(
            columnSpacing: 20,
            horizontalMargin: 12,
            dataRowMinHeight: 130,
            dataRowMaxHeight: 180,
            columns: const [
              DataColumn(label: LText('sync.diff.record')),
              DataColumn(label: LText('sync.diff.local')),
              DataColumn(label: LText('sync.diff.remote')),
              DataColumn(label: LText('sync.diff.result')),
            ],
            rows: rows.map((change) {
              final local = change['local'] as Map;
              final remote = change['remote'] as Map;
              final fields = (change['changed_fields'] as List? ?? [])
                  .map((field) => _field(field.toString())).toSet().join('、');
              return DataRow(key: ValueKey(change['key']), cells: [
                DataCell(SizedBox(width: 190, child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text((local['title'] ?? remote['title'] ?? tr('sync.conflict.untitled')).toString(),
                        maxLines: 2, overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontWeight: FontWeight.w600)),
                    if (fields.isNotEmpty) ...[
                      const SizedBox(height: 8),
                      Text(fields, maxLines: 3, overflow: TextOverflow.ellipsis,
                          style: TextStyle(fontSize: 12, color: AppColors.muted)),
                    ],
                    if (change['conflict'] == true) ...[
                      const SizedBox(height: 8),
                      LText(change['pending'] == true ? 'sync.diff.conflict' : 'sync.diff.resolved',
                          style: TextStyle(color: AppColors.primary)),
                    ],
                  ],
                ))),
                DataCell(_diffSide(context, local, action: change['local_action'] as String)),
                DataCell(_diffSide(context, remote, action: change['remote_action'] as String)),
                DataCell(_diffSide(context, change['result'] as Map?)),
              ]);
            }).toList(),
          ),
        ),
        const SizedBox(height: 12),
        Wrap(spacing: 12, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
          LText('sync.diff.range', args: {'start': start + 1, 'end': end, 'total': total}),
          TextButton(onPressed: sync.busy || start == 0 ? null : () => sync.loadPreviewPage((start - 20).clamp(0, total).toInt()),
              child: const LText('sync.diff.previous')),
          TextButton(onPressed: sync.busy || end >= total ? null : () => sync.loadPreviewPage(end),
              child: const LText('sync.diff.next')),
        ]),
      ]);
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
      listenable: sync,
      builder: (context, _) => ListView(
              padding: const EdgeInsets.fromLTRB(24, 6, 24, 24),
              children: [
                AppPanel(
                    title: tr('sync.title'),
                    subtitle: tr('sync.description'),
                    icon: Icons.cloud_sync_outlined,
                    trailing: FilledButton.icon(
                        onPressed: !sync.unlocked || sync.busy || sync.hasPreview
                            ? null
                            : () => sync.interact(() => !sync.configured
                                ? _configure(context)
                                : sync.connected
                                    ? _check(context)
                                    : _initial(context)),
                        icon: const Icon(Icons.sync, size: 18),
                        label: LText(sync.configured
                            ? 'sync.actions.now'
                            : 'sync.actions.configure')),
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          if (sync.busy) ...[
                            const LinearProgressIndicator(),
                            const SizedBox(height: 8),
                            LText(sync.progress.isEmpty
                                ? 'sync.progress.working'
                                : sync.progress),
                            const SizedBox(height: 16)
                          ],
                          if (sync.error.isNotEmpty) ...[
                            AppNotice(sync.failureMessage),
                            const SizedBox(height: 16)
                          ],
                          if (sync.cleanupNotice.isNotEmpty) ...[
                            AppNotice(sync.cleanupNotice),
                            const SizedBox(height: 16)
                          ],
                          if (sync.lastResult.isNotEmpty) ...[
                            Row(children: [
                              Icon(Icons.check_circle_outline,
                                  size: 18, color: AppColors.green),
                              const SizedBox(width: 8),
                              Expanded(child: Text(sync.lastResult)),
                            ]),
                            const SizedBox(height: 16)
                          ],
                          LText(sync.connected
                              ? (sync.settings['automatic'] == true
                                  ? 'sync.status.automatic'
                                  : 'sync.status.paused')
                              : 'sync.status.notConnected'),
                          if (sync.hasPreview) ...[
                            const SizedBox(height: 10),
                            const LText('sync.status.previewPending')
                          ],
                          if (sync.unlocked) ...[
                            const SizedBox(height: 10),
                            LText('sync.host.local', args: {'name': sync.status['sync_host_name'] ?? ''}),
                          ],
                          if (sync.configured) ...[
                            const SizedBox(height: 10),
                            LText('sync.cleanup.policy', args: {
                              'dailyCount': (sync.settings['daily_history_count'] as num?)?.toInt() ?? 5}),
                            if (!sync.connected) ...[
                              const SizedBox(height: 10),
                              const LText('sync.status.joinHelp')
                            ],
                            const SizedBox(height: 12),
                            SelectableText(sync.settings['root'].toString()),
                            const SizedBox(height: 8),
                            LText('sync.status.lastSuccess', args: {
                              'time': _time(sync.status['last_synced_ms'])
                            }),
                            if (sync.connected && sync.status['generation'] != null) ...[
                              const SizedBox(height: 8),
                              LText('sync.host.remote', args: {'name':
                                (sync.status['remote_host_name']?.toString() ?? '').isEmpty
                                  ? tr('sync.host.unknown') : sync.status['remote_host_name']}),
                            ],
                            if (sync.status['pending_upload'] == true) ...[
                              const SizedBox(height: 8),
                              const LText('sync.status.pending')
                            ],
                          ],
                          const SizedBox(height: 20),
                          Wrap(spacing: 10, runSpacing: 10, children: [
                            if (sync.connected)
                              OutlinedButton(
                                  onPressed: sync.busy
                                      ? null
                                      : () => sync
                                          .interact(() => _initial(context)),
                                  child: const LText('sync.actions.reconnect')),
                            if (sync.connected)
                              OutlinedButton(
                                  onPressed: sync.busy
                                      ? null
                                      : () =>
                                          sync.interact(() => _toggle(context)),
                                  child: LText(
                                      sync.settings['automatic'] == true
                                          ? 'sync.actions.pause'
                                          : 'sync.actions.resume')),
                            if (sync.configured)
                              TextButton(
                                  onPressed: sync.busy
                                      ? null
                                      : () => sync
                                          .interact(() => _configure(context)),
                                  child: const LText('sync.actions.configure')),
                            if (sync.configured)
                              TextButton(
                                  onPressed: sync.busy
                                      ? null
                                      : () => sync
                                          .interact(() => _disconnect(context)),
                                  child:
                                      const LText('sync.actions.disconnect')),
                          ]),
                        ])),
                if (sync.hasPreview) ...[
                  const SizedBox(height: 20),
                  AppPanel(
                      title: tr('sync.preview.title'),
                      subtitle: tr('sync.preview.help'),
                      icon: Icons.compare_arrows,
                      child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            if (sync.busy) ...[
                              const LinearProgressIndicator(),
                              const SizedBox(height: 8),
                              LText(sync.progress.isEmpty
                                  ? 'sync.progress.working'
                                  : sync.progress),
                              const SizedBox(height: 16)
                            ],
                            LText('sync.preview.counts', args: {
                              'local': sync.preview['local_count'],
                              'remote': sync.preview['remote_count'],
                              'result': sync.preview['result_count']
                            }),
                            if (sync.preview['remote_present'] == true) ...[
                              const SizedBox(height: 8),
                              LText('sync.host.remote', args: {'name':
                                (sync.preview['remote_host_name']?.toString() ?? '').isEmpty
                                  ? tr('sync.host.unknown') : sync.preview['remote_host_name']}),
                            ],
                            const SizedBox(height: 8),
                            LText('sync.preview.differences', args: {
                              'local': sync.preview['local_only'],
                              'remote': sync.preview['remote_only'],
                              'conflicts': sync.conflicts.length
                            }),
                            if ((sync.preview['possible_duplicates'] as num? ??
                                    0) >
                                0) ...[
                              const SizedBox(height: 12),
                              LText('sync.preview.duplicates', args: {
                                'count': sync.preview['possible_duplicates']
                              })
                            ],
                            if (sync.preview['initial'] == true) ...[
                              const SizedBox(height: 10),
                              LText('sync.strategy.${sync.preview['strategy']}')
                            ],
                            if (sync.preview['remote_present'] == false) ...[
                              const SizedBox(height: 10),
                              const LText('sync.preview.remoteEmpty')
                            ],
                            const SizedBox(height: 18),
                            if (sync.conflicts.length > sync.decisions.length) ...[
                              LText('sync.diff.unresolved', args: {
                                'count': sync.conflicts.length - sync.decisions.length,
                              }),
                              const SizedBox(height: 10),
                            ],
                            _diffTable(context),
                            for (final conflict in sync.conflicts.where((conflict) =>
                                (sync.preview['changes'] as List? ?? []).any((row) => row['key'] == conflict['key'])))
                              _conflict(conflict, context),
                            const SizedBox(height: 20),
                            Wrap(
                                alignment: WrapAlignment.end,
                                spacing: 12,
                                runSpacing: 10,
                                children: [
                                  TextButton(
                                      onPressed:
                                          sync.busy ? null : sync.cancelPreview,
                                      child: const LText(
                                          'sync.actions.cancelPreview')),
                                  FilledButton(
                                      onPressed: sync.busy ||
                                              sync.decisions.length !=
                                                  sync.conflicts.length
                                          ? null
                                          : () => sync
                                              .interact(() => _apply(context)),
                                      child: const LText('sync.actions.apply'))
                                ]),
                          ]))
                ],
                if (sync.backupPath.isNotEmpty ||
                    sync.remoteBackupPath.isNotEmpty) ...[
                  const SizedBox(height: 20),
                  AppPanel(
                      title: tr('sync.backup.title'),
                      icon: Icons.restore_outlined,
                      child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            if (sync.backupPath.isNotEmpty) ...[
                              const LText('sync.backup.local'),
                              const SizedBox(height: 8),
                              SelectableText(sync.backupPath)
                            ],
                            if (sync.remoteBackupPath.isNotEmpty) ...[
                              const SizedBox(height: 12),
                              const LText('sync.backup.remote'),
                              const SizedBox(height: 8),
                              SelectableText(sync.remoteBackupPath)
                            ],
                          ]))
                ],
              ]));
}
