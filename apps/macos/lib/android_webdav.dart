import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/services.dart';
import 'agent_bridge.dart';
import 'app_presentation.dart';

/// Android 只负责 HTTPS 密文传输；合并、MAC 校验及提交仍由同一 Rust Core 完成。
class AndroidWebDav {
  static final instance = AndroidWebDav();
  static const _channel = MethodChannel('credpivot/agent');
  final _clients = <HttpClient>{};
  final _random = Random.secure();
  int _epoch = 0;
  String _cancellationKey = 'sync.errors.locked';
  bool _busy = false;
  bool _bootstrapRead = false;
  String? _verifiedLocation;
  String? _cleanupLocation;
  DateTime _cleanupDue = DateTime.fromMillisecondsSinceEpoch(0);
  final _historyReferences = <String, _DavHistory>{};
  bool _cleanupDeleteVerified = false;
  final _retryAfter = <String, DateTime>{};

  String _nonce() {
    final bytes = List.generate(16, (_) => _random.nextInt(256));
    bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
    final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    // 沿用桌面探针的 UUID 命名，失败遗留文件仍能被既有清理策略识别。
    return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
  }
  Never _fail(String key) => throw PlatformException(code: key, message: tr(key));
  Future<Map<String, dynamic>> _agent(Map<String, dynamic> request) async => AgentBridge.payloadOf(await AgentBridge.request(request));
  Future<String> _hash(List<int> data) async => (await _channel.invokeMethod<String>('androidSha256', Uint8List.fromList(data)))!;

  void cancel({String reason = 'sync.errors.locked'}) {
    _epoch++;
    _cancellationKey = reason;
    _verifiedLocation = null;
    for (final client in _clients.toList()) { client.close(force: true); }
  }

  Future<void> _check(int epoch, {Map<String, dynamic>? publishing}) async {
    if (epoch != _epoch) _fail(_cancellationKey);
    final state = await _agent({'type': 'status'});
    if (_bootstrapRead) {
      if (state['vault_exists'] != false || state['unlocked'] == true) _fail('sync.bootstrap.existing');
    } else if (state['unlocked'] != true) { _fail('sync.errors.locked'); }
    if (publishing != null) await _agent({'type': 'sync_publish_authorize', ...publishing});
    if (epoch != _epoch) _fail(_cancellationKey);
  }

  Future<Map<String, dynamic>> _settings() async {
    final result = await _agent({'type': 'app_settings_get'});
    if ((result['warning'] ?? '') != '') _fail('sync.errors.settingsRead');
    return Map<String, dynamic>.from(result['settings'] as Map);
  }

  Future<String> _password(Map<String, dynamic> config) async {
    if (config['_password'] is String) return config['_password'] as String;
    final password = await _channel.invokeMethod<String>('androidSecureRead', config['location']);
    if (password == null || password.isEmpty) _fail('sync.errors.passwordMissing');
    return password;
  }

  Future<Map<String, dynamic>> _normalize(Map<String, dynamic> args) async {
    final input = (args['server_url'] ?? args['root'] ?? '').toString().trim();
    final uri = Uri.tryParse(input);
    if (uri == null || uri.scheme != 'https' || uri.host.isEmpty || uri.userInfo.isNotEmpty || uri.hasQuery || uri.hasFragment ||
        RegExp(r'[\x00-\x20\x7f\\]').hasMatch(input) || uri.pathSegments.any((s) => s == '.' || s == '..')) { _fail('sync.errors.address'); }
    final rawPort = args['port']?.toString() ?? '';
    final port = rawPort.isEmpty ? null : int.tryParse(rawPort);
    if (rawPort.isNotEmpty && (port == null || port < 1 || port > 65535)) _fail('sync.errors.port');
    if (port != null && uri.hasPort && uri.port != port) _fail('sync.errors.portConflict');
    var base = uri.replace(port: port ?? (uri.hasPort ? uri.port : null));
    if (!base.path.endsWith('/')) base = base.replace(path: '${base.path}/');
    final directory = (args['directory'] ?? '').toString();
    if (utf8.encode(directory).length > 2048 || RegExp(r'[\x00-\x1f\x7f\\]').hasMatch(directory) || directory.split('/').any((s) => s == '.' || s == '..')) _fail('sync.errors.directoryPath');
    final segments = directory.split('/').where((s) => s.isNotEmpty).toList();
    final baseSegments = base.pathSegments.toList();
    if (baseSegments.isNotEmpty && baseSegments.last.isEmpty) baseSegments.removeLast();
    final root = base.replace(pathSegments: [...baseSegments, ...segments, '']).toString();
    final username = (args['username'] ?? '').toString().trim();
    if (username.isEmpty || utf8.encode(username).length > 1024 || RegExp(r'[:\x00-\x1f\x7f]').hasMatch(username)) _fail('sync.errors.username');
    final interval = args['interval_seconds'];
    if (interval is! int || interval < 60 || interval > 3600) _fail('sync.errors.interval');
    final count = args['daily_history_count'] ?? 5;
    if (count is! int || count < 3 || count > 99) _fail('sync.errors.dailyHistoryCount');
    final provider = args['provider'] ?? 'custom';
    if (!['custom', 'nutstore', 'nextcloud', 'owncloud'].contains(provider)) _fail('sync.errors.configuration');
    if (root.length > 4096) _fail('sync.errors.address');
    return {'root': root, 'server_url': base.toString(), 'directory': segments.join('/'), 'username': username,
      'provider': provider, 'location': await _hash(utf8.encode(jsonEncode([root, username]).replaceAll('/', r'\/'))),
      'interval_seconds': interval, 'daily_history_count': count, 'automatic': args['automatic'] != false};
  }

  Future<_DavReply> _request(Map<String, dynamic> config, String path, int epoch,
      {String method = 'GET', List<int>? body, Map<String, String> headers = const {}, int limit = 64 * 1024 * 1024,
      Map<String, dynamic>? publishing}) async {
    if (_bootstrapRead && method != 'GET') _fail('sync.errors.operation');
    await _check(epoch, publishing: publishing);
    final location = config['location'] as String;
    final retry = _retryAfter[location];
    if (retry != null && DateTime.now().isBefore(retry)) {
      throw PlatformException(code: 'sync.errors.rateLimited', message: tr('sync.errors.rateLimited'),
        details: {'retry_after': retry.difference(DateTime.now()).inSeconds + 1});
    }
    final root = Uri.parse(config['root'] as String), uri = Uri.parse(config['root'] as String).resolve(path);
    if (path.startsWith('/') || path.contains(':') || path.contains('\\') || path.split('/').any((s) => s == '.' || s == '..') ||
        uri.origin != root.origin || !uri.path.startsWith(root.path) || uri.hasQuery || uri.hasFragment) { _fail('sync.errors.requestPath'); }
    final password = await _password(config);
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 30);
    _clients.add(client);
    try {
      final reply = await (() async {
        final request = await client.openUrl(method, uri);
        request.followRedirects = false;
        request.headers.set('Authorization', 'Basic ${base64Encode(utf8.encode('${config['username']}:$password'))}');
        request.headers.set('User-Agent', 'CredPivot/1');
        request.headers.set('Content-Type', 'application/octet-stream');
        headers.forEach(request.headers.set);
        if (body != null) { request.contentLength = body.length; request.add(body); }
        final response = await request.close();
        if (response.contentLength > limit) _fail('sync.errors.format');
        final buffer = BytesBuilder(copy: false);
        await for (final chunk in response) {
          if (buffer.length + chunk.length > limit) _fail('sync.errors.format');
          buffer.add(chunk);
        }
        return _DavReply(response.statusCode, buffer.takeBytes(), response.headers);
      })().timeout(const Duration(seconds: 45));
      await _check(epoch, publishing: publishing);
      if (reply.status == 401) _fail('sync.errors.unauthorized');
      if (reply.status == 403) _fail('sync.errors.forbidden');
      if (reply.status == 429) {
        final delay = (int.tryParse(reply.headers.value('retry-after') ?? '') ?? 120).clamp(60, 86400).toInt();
        _retryAfter[location] = DateTime.now().add(Duration(seconds: delay));
        throw PlatformException(code: 'sync.errors.rateLimited', message: tr('sync.errors.rateLimited'), details: {'retry_after': delay});
      }
      if (reply.status >= 500) _fail('sync.errors.server');
      if (reply.status >= 300 && reply.status < 400 && reply.status != 304) _fail('sync.errors.redirect');
      return reply;
    } on PlatformException { rethrow; }
    on AgentException { rethrow; }
    catch (_) { if (epoch != _epoch) _fail(_cancellationKey); _fail('sync.errors.network'); }
    finally { _clients.remove(client); client.close(force: true); }
  }

  String _tag(_DavReply reply) => _validatedTag(reply.headers.value('etag') ?? '');

  String _validatedTag(String tag) {
    if (tag.isEmpty) _fail('sync.errors.etagMissing');
    if (tag.toUpperCase().startsWith('W/')) _fail('sync.errors.etagWeak');
    final opaque = tag.startsWith('"') && tag.endsWith('"') ? tag.substring(1, tag.length - 1) : tag;
    if (tag.length > 1024 || opaque.isEmpty || opaque.codeUnits.any((c) => c != 33 && (c < 35 || c > 126))) _fail('sync.errors.etagFormat');
    return tag;
  }

  Future<void> _directory(Map<String, dynamic> config, String path, int epoch, {bool create = true}) async {
    var reply = await _request(config, path, epoch, method: 'PROPFIND',
        body: utf8.encode('<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>'),
        headers: {'Depth': '0', 'Content-Type': 'application/xml'}, limit: 256 * 1024);
    if (reply.status == 404 && create) {
      reply = await _request(config, path, epoch, method: 'MKCOL', limit: 1024);
      if (![201, 405].contains(reply.status)) _fail('sync.errors.directory');
      return _directory(config, path, epoch, create: false);
    }
    if (reply.status != 207) _fail('sync.errors.directory');
    final rows = await _channel.invokeListMethod<dynamic>('androidDavParse', reply.body) ?? [];
    final expected = Uri.parse(config['root'] as String).resolve(path);
    if (!rows.any((r) => r is Map && r['collection'] == true && expected.resolve(r['href'] as String) == expected)) _fail('sync.errors.directory');
  }

  Future<_DavReply> _move(Map<String, dynamic> config, String source, String target, int epoch, {Map<String, dynamic>? publishing}) =>
      _request(config, source, epoch, method: 'MOVE', headers: {'Destination': Uri.parse(config['root'] as String).resolve(target).toString(), 'Overwrite': 'F'}, limit: 1024,
        publishing: publishing);
  bool _rejects(Map<String, dynamic> config, int status) => status == 412 || (config['provider'] == 'nutstore' && status == 409);
  bool _same(List<int> a, List<int> b) => a.length == b.length && List.generate(a.length, (i) => a[i] == b[i]).every((v) => v);

  Future<void> _probe(Map<String, dynamic> config, int epoch, List<Map<String, dynamic>> checks) async {
    _verifiedLocation = null;
    _cleanupDeleteVerified = false;
    void passed(String key, [List<int> statuses = const []]) => checks.add({'key': key, 'passed': true, 'statuses': statuses});
    final base = {...config, 'root': config['server_url']};
    await _directory(base, '', epoch, create: false);
    var prefix = '';
    for (final part in (config['directory'] as String).split('/').where((s) => s.isNotEmpty)) {
      prefix += '${Uri.encodeComponent(part)}/'; await _directory(base, prefix, epoch);
    }
    passed('directory');
    final paths = List.generate(5, (_) => '.credpivot-probe-${_nonce()}');
    final first = utf8.encode('credpivot-one-${_nonce()}'), second = utf8.encode('credpivot-two-${_nonce()}');
    var succeeded = false;
    try {
      final created = await _request(config, paths[0], epoch, method: 'PUT', body: first, limit: 1024);
      final old = await _request(config, paths[0], epoch, limit: 1024);
      if (![200, 201, 204].contains(created.status) || old.status != 200 || !_same(old.body, first)) _fail('sync.errors.probeReadback');
      passed('readWrite', [created.status, old.status]);
      final tag = _tag(old);
      final wrong = await _request(config, paths[0], epoch, method: 'PUT', body: second, headers: {'If-Match': '"${_nonce()}"'}, limit: 1024);
      final unchanged = await _request(config, paths[0], epoch, limit: 1024);
      if (wrong.status != 412 || !_same(unchanged.body, first) || _tag(unchanged) != tag) _fail('sync.errors.probeMatchWrong');
      passed('matchWrong', [wrong.status]);
      final updated = await _request(config, paths[0], epoch, method: 'PUT', body: second, headers: {'If-Match': tag}, limit: 1024);
      final visible = await _request(config, paths[0], epoch, limit: 1024);
      if (![200, 201, 204].contains(updated.status) || !_same(visible.body, second) || _tag(visible) == tag) _fail('sync.errors.probeMatchUpdate');
      passed('matchUpdate', [updated.status]);
      final stale = await _request(config, paths[0], epoch, method: 'PUT', body: first, headers: {'If-Match': tag}, limit: 1024);
      final retained = await _request(config, paths[0], epoch, limit: 1024);
      if (stale.status != 412 || !_same(retained.body, second)) _fail('sync.errors.probeMatchStale');
      passed('matchStale', [stale.status]);
      final current = _tag(retained);
      final concurrentBody = utf8.encode(_nonce());
      final updates = await Future.wait([
        _request(config, paths[0], epoch, method: 'PUT', body: first, headers: {'If-Match': current}, limit: 1024),
        _request(config, paths[0], epoch, method: 'PUT', body: concurrentBody, headers: {'If-Match': current}, limit: 1024),
      ]);
      final updatedVisible = await _request(config, paths[0], epoch, limit: 1024);
      if (updates.where((r) => [200, 201, 204].contains(r.status)).length != 1 || updates.where((r) => r.status == 412).length != 1 ||
          updatedVisible.status != 200 || !_same(updatedVisible.body, updates[0].status == 412 ? concurrentBody : first)) { _fail('sync.errors.conditionalWrite'); }
      passed('matchConcurrent', updates.map((r) => r.status).toList());
      await _unique(config, paths[1], first, epoch);
      await _unique(config, paths[2], second, epoch);
      final moved = await _move(config, paths[1], paths[3], epoch);
      final movedBody = await _request(config, paths[3], epoch, limit: 1024);
      final gone = await _request(config, paths[1], epoch, limit: 1024);
      if (moved.status != 201 || movedBody.status != 200 || !_same(movedBody.body, first) || gone.status != 404) _fail('sync.errors.probeInitialMoveCreate');
      passed('initialMoveCreate', [moved.status]);
      final denied = await _move(config, paths[2], paths[3], epoch);
      final destination = await _request(config, paths[3], epoch, limit: 1024);
      final source = await _request(config, paths[2], epoch, limit: 1024);
      if (!_rejects(config, denied.status) || destination.status != 200 || source.status != 200 || !_same(destination.body, first) || !_same(source.body, second)) _fail('sync.errors.probeInitialMove');
      passed('initialMove', [denied.status]);
      await _unique(config, paths[1], first, epoch);
      final moves = await Future.wait([_move(config, paths[1], paths[4], epoch), _move(config, paths[2], paths[4], epoch)]);
      final winner = moves[0].status == 201 ? 0 : 1;
      final finalBody = await _request(config, paths[4], epoch, limit: 1024);
      final lost = await _request(config, paths[winner == 0 ? 2 : 1], epoch, limit: 1024);
      final won = await _request(config, paths[winner == 0 ? 1 : 2], epoch, limit: 1024);
      if (moves.where((r) => r.status == 201).length != 1 || !_rejects(config, moves[1 - winner].status) ||
          finalBody.status != 200 || lost.status != 200 || !_same(finalBody.body, winner == 0 ? first : second) || !_same(lost.body, winner == 0 ? second : first) || won.status != 404) { _fail('sync.errors.probeInitialMove'); }
      passed('initialMoveConcurrent', moves.map((r) => r.status).toList());
      await _directory(config, 'snapshots/', epoch); await _directory(config, 'backups/', epoch);
      passed('subdirectories');
      succeeded = true;
    } finally {
      var cleaned = true;
      for (final path in paths) {
        if (epoch != _epoch) { cleaned = false; break; }
        try {
          final deleted = await _request(config, path, epoch, method: 'DELETE', limit: 1024);
          final missing = await _request(config, path, epoch, limit: 1024);
          if (![200, 204, 404].contains(deleted.status) || missing.status != 404) cleaned = false;
        } catch (_) { cleaned = false; }
      }
      if (succeeded) {
        if (epoch != _epoch) _fail(_cancellationKey);
        if (!cleaned) _fail('sync.errors.probeCleanup');
        _verifiedLocation = config['location'] as String;
        passed('cleanup');
      }
    }
  }

  String _snapshot(Map<String, dynamic> head) {
    final path = head['snapshot'];
    if (head['format'] != 'credpivot-sync' || head['version'] != 1 || path is! String || path.length > 180 ||
        !RegExp(r'^snapshots/credpivot_[A-Za-z0-9_-]+\.ovb$').hasMatch(path)) { _fail('sync.errors.format'); }
    return path;
  }

  Map<String, dynamic> _json(_DavReply reply) {
    try { return Map<String, dynamic>.from(jsonDecode(utf8.decode(reply.body)) as Map); }
    catch (_) { _fail('sync.errors.format'); }
  }

  Future<void> _unique(Map<String, dynamic> config, String path, List<int> bytes, int epoch, {Map<String, dynamic>? publishing}) async {
    final exists = await _request(config, path, epoch, publishing: publishing);
    if (exists.status == 200) { if (!_same(exists.body, bytes)) _fail('sync.errors.integrity'); return; }
    if (exists.status != 404) _fail('sync.errors.upload');
    final reply = await _request(config, path, epoch, method: 'PUT', body: bytes, publishing: publishing, limit: 1024);
    if (![200, 201, 204].contains(reply.status)) _fail('sync.errors.upload');
    final actual = await _request(config, path, epoch, publishing: publishing);
    if (actual.status != 200 || !_same(actual.body, bytes)) _fail('sync.errors.integrity');
  }

  Future<Map<String, dynamic>> _read(Map<String, dynamic> config, Map<String, dynamic> args, int epoch) async {
    for (var attempt = 0; attempt < 3; attempt++) {
      final reply = await _request(config, 'head.json', epoch, headers: attempt == 0 && args['etag'] is String ? {'If-None-Match': args['etag'] as String} : {}, limit: 64 * 1024);
      if (reply.status == 304) return {'not_modified': true, 'location': config['location']};
      if (reply.status == 404) return {'empty': true, 'location': config['location']};
      if (reply.status != 200) _fail('sync.errors.format');
      final head = _json(reply);
      String? tag;
      if (_bootstrapRead) { try { tag = _tag(reply); } on PlatformException { tag = null; } }
      else { tag = _tag(reply); }
      final snapshot = await _request(config, _snapshot(head), epoch);
      if (snapshot.status == 404 && attempt < 2) continue;
      if (snapshot.status != 200 || await _hash(snapshot.body) != head['sha256']) _fail('sync.errors.integrity');
      return {'head': head, if (tag != null) 'etag': tag, 'remote_ovb': base64Encode(snapshot.body), 'location': config['location'],
        if (_bootstrapRead && reply.headers.value('last-modified') != null) 'modified': reply.headers.value('last-modified')};
    }
    _fail('sync.errors.remoteChanged');
  }

  Future<Map<String, dynamic>> _publish(Map<String, dynamic> config, Map<String, dynamic> args, int epoch) async {
    if (args['location'] != config['location']) _fail('sync.errors.configuration');
    final head = Map<String, dynamic>.from(args['head'] as Map);
    final publishing = {'location': config['location'], 'head': head};
    await _check(epoch, publishing: publishing);
    final text = args['ovb'] as String;
    if (text.length > 90 * 1024 * 1024) _fail('sync.errors.format');
    final archive = base64Decode(text);
    if (await _hash(archive) != head['sha256']) _fail('sync.errors.integrity');
    if (_verifiedLocation != config['location']) await _probe(config, epoch, []);
    await _unique(config, _snapshot(head), archive, epoch, publishing: publishing);
    final prior = await _request(config, 'head.json', epoch, publishing: publishing, limit: 64 * 1024);
    final bytes = utf8.encode(jsonEncode(head));
    var backup = '';
    if (args['etag'] is String) {
      if (prior.status != 200 || _tag(prior) != args['etag']) _fail('sync.errors.remoteChanged');
      final old = _json(prior);
      if (old['revision'] != head['parent'] || jsonEncode(_sorted(old)) != jsonEncode(_sorted(args['expected_head']))) _fail('sync.errors.remoteChanged');
      backup = _snapshot(old);
      final authorization = await _agent({'type': 'sync_publish_authorize', ...publishing});
      final history = {'format': 'credpivot-history', 'version': 1, 'head': old,
        'important': authorization['preserve_previous'] == true, 'retired': false};
      try {
        final modified = prior.headers.value('last-modified');
        if (modified != null) history['published_at_ms'] = HttpDate.parse(modified).millisecondsSinceEpoch;
      } catch (_) {}
      await _unique(config, 'backups/head_${DateTime.now().millisecondsSinceEpoch}_${_nonce()}.json', utf8.encode(jsonEncode(history)), epoch, publishing: publishing);
      final committed = await _request(config, 'head.json', epoch, method: 'PUT', body: bytes,
        headers: {'If-Match': args['etag'] as String, 'Content-Type': 'application/json'}, publishing: publishing, limit: 1024);
      if (committed.status == 412) _fail('sync.errors.remoteChanged');
      if (![200, 201, 204].contains(committed.status)) _fail('sync.errors.upload');
    } else {
      if (prior.status != 404) _fail('sync.errors.remoteChanged');
      final staged = '.credpivot-probe-${_nonce()}';
      try {
        await _unique(config, staged, bytes, epoch, publishing: publishing);
        final moved = await _move(config, staged, 'head.json', epoch, publishing: publishing);
        if (_rejects(config, moved.status)) _fail('sync.errors.remoteChanged');
        if (moved.status != 201) _fail('sync.errors.upload');
      } finally {
        try { await _request(config, staged, epoch, method: 'DELETE', limit: 1024, publishing: publishing); } catch (_) {}
      }
    }
    final visible = await _request(config, 'head.json', epoch, publishing: publishing, limit: 64 * 1024);
    if (visible.status != 200 || jsonEncode(_sorted(_json(visible))) != jsonEncode(_sorted(head))) _fail('sync.errors.remoteChanged');
    return {'published': true, 'etag': _tag(visible), 'remote_backup_path': backup};
  }

  dynamic _sorted(dynamic value) {
    if (value is Map) { final keys = value.keys.cast<String>().toList()..sort(); return {for (final k in keys) k: _sorted(value[k])}; }
    if (value is List) return value.map(_sorted).toList();
    return value;
  }

  /// 与桌面端相同的两阶段淘汰：先标记，经过读取窗口后才删除快照。
  Future<Map<String, dynamic>> _cleanup(Map<String, dynamic> config, Map<String, dynamic> args, int epoch) async {
    final status = await _agent({'type': 'sync_status'});
    if (args['location'] != config['location'] || status['connected'] != true || status['location'] != config['location'] || status['pending_upload'] == true ||
        args['head'] is! Map || args['etag'] is! String) _fail('sync.cleanup.changed');
    final head = Map<String, dynamic>.from(args['head'] as Map), tag = args['etag'] as String;
    final currentSnapshot = _snapshot(head);
    if (_cleanupLocation != config['location']) {
      _cleanupLocation = config['location'] as String;
      _cleanupDue = DateTime.fromMillisecondsSinceEpoch(0); _historyReferences.clear(); _cleanupDeleteVerified = false;
    }
    if (DateTime.now().isBefore(_cleanupDue)) return {'throttled': true};
    _cleanupDue = DateTime.now().add(const Duration(minutes: 15));
    var remaining = 64;
    Future<_DavReply> request(String path, {String method = 'GET', List<int>? body, Map<String, String> headers = const {}, int limit = 64 * 1024}) async {
      if (remaining-- <= 0) _fail('sync.cleanup.deferred');
      return _request(config, path, epoch, method: method, body: body, headers: headers, limit: limit);
    }
    Future<_DavReply> current() async {
      final reply = await request('head.json', headers: {'If-Match': tag});
      if (reply.status != 200 || _tag(reply) != tag || jsonEncode(_sorted(_json(reply))) != jsonEncode(_sorted(head))) _fail('sync.cleanup.changed');
      return reply;
    }
    Future<List<_DavEntry>> listing(String directory) async {
      final reply = await request(directory, method: 'PROPFIND', headers: {'Depth': '1', 'Content-Type': 'application/xml'},
        body: utf8.encode('<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getetag/><d:getlastmodified/></d:prop></d:propfind>'), limit: 8 * 1024 * 1024);
      if (reply.status != 207 || (reply.headers.value('link') ?? '').toLowerCase().contains('next')) _fail('sync.cleanup.incomplete');
      final rows = await _channel.invokeListMethod<dynamic>('androidDavParse', reply.body) ?? [];
      if (rows.isEmpty || rows.length > 10000 || (config['provider'] == 'nutstore' && rows.length >= 750)) _fail('sync.cleanup.incomplete');
      final root = Uri.parse(config['root'] as String).resolve(directory);
      final entries = <_DavEntry>[], names = <String>{};
      var foundDirectory = false;
      for (final row in rows.cast<Map>()) {
        final url = root.resolve(row['href'].toString());
        if (url.origin != root.origin || url.hasQuery || url.hasFragment || url.userInfo.isNotEmpty) _fail('sync.cleanup.incomplete');
        if (url.path.replaceFirst(RegExp(r'/$'), '') == root.path.replaceFirst(RegExp(r'/$'), '')) {
          if (row['collection'] != true) _fail('sync.cleanup.incomplete');
          foundDirectory = true; continue;
        }
        if (!url.path.startsWith(root.path)) _fail('sync.cleanup.incomplete');
        var name = Uri.decodeComponent(url.path.substring(root.path.length));
        if (row['collection'] == true) name = name.replaceFirst(RegExp(r'/$'), '');
        if (name.isEmpty || name.contains('/') || name.contains('\\') || !names.add(name)) _fail('sync.cleanup.incomplete');
        if (row['collection'] == true) continue;
        // 不删除未知文件；缺少可靠时间或 ETag 的本应用文件也不能猜测其状态。
        final owned = directory.isEmpty ? RegExp(r'^\.credpivot-probe-[0-9a-fA-F-]{36}$').hasMatch(name)
          : RegExp(directory == 'backups/' ? r'^head_(\d+|\d{8}T\d{6}Z)_[0-9a-fA-F-]{36}\.json$'
              : r'^credpivot_(\d+|\d{8}T\d{6}Z)_[0-9a-fA-F-]{36}\.ovb$').hasMatch(name);
        if (!owned) continue;
        final entryTag = row['getetag']?.toString() ?? '';
        DateTime modified;
        try { modified = HttpDate.parse(row['getlastmodified'].toString()); } catch (_) { _fail('sync.cleanup.incomplete'); }
        _validatedTag(entryTag);
        if (directory.isNotEmpty) {
          final raw = name.split('_')[1];
          final intDate = int.tryParse(raw);
          DateTime? created;
          if (intDate != null && intDate > 0 && intDate <= 253402300799000) { created = DateTime.fromMillisecondsSinceEpoch(intDate, isUtc: true); }
          else if (RegExp(r'^\d{8}T\d{6}Z$').hasMatch(raw)) {
            created = DateTime.tryParse('${raw.substring(0, 4)}-${raw.substring(4, 6)}-${raw.substring(6, 8)}T${raw.substring(9, 11)}:${raw.substring(11, 13)}:${raw.substring(13, 15)}Z');
          }
          if (created == null) _fail('sync.cleanup.incomplete');
          if (created.isAfter(modified)) modified = created;
        }
        entries.add(_DavEntry('$directory$name', entryTag, modified));
      }
      if (!foundDirectory) _fail('sync.cleanup.incomplete');
      return entries;
    }
    Future<void> remove(_DavEntry entry) async {
      if (remaining < 3) _fail('sync.cleanup.deferred');
      await current();
      final deleted = await request(entry.path, method: 'DELETE', headers: {'If-Match': entry.etag}, limit: 1024);
      if (![200, 204, 404].contains(deleted.status) || (await request(entry.path, limit: 1024)).status != 404) _fail('sync.cleanup.changed');
    }
    try {
      final observed = await current();
      DateTime serverTime;
      try { serverTime = HttpDate.parse(observed.headers.value('date') ?? ''); } catch (_) { _fail('sync.cleanup.incomplete'); }
      final now = serverTime.isBefore(DateTime.now()) ? serverTime : DateTime.now();
      final historyCutoff = now.subtract(const Duration(days: 30));
      final orphanCutoff = now.subtract(const Duration(days: 7));
      final readCutoff = now.subtract(const Duration(minutes: 10));
      final backups = await listing('backups/'), snapshots = await listing('snapshots/'), probes = await listing('');
      final snapshotsByPath = {for (final e in snapshots) e.path: e};
      final paths = backups.map((e) => e.path).toSet();
      _historyReferences.removeWhere((key, _) => !paths.contains(key));
      for (final entry in backups) {
        if (_historyReferences[entry.path]?.etag == entry.etag) continue;
        final reply = await request(entry.path, headers: {'If-Match': entry.etag});
        if (reply.status != 200 || _tag(reply) != entry.etag) _fail('sync.cleanup.incomplete');
        final object = _json(reply), wrapped = object['format'] == 'credpivot-history';
        if (wrapped && (object['version'] != 1 || object['head'] is! Map || object['important'] is! bool || object['retired'] is! bool)) _fail('sync.cleanup.incomplete');
        final storedHead = wrapped ? Map<String, dynamic>.from(object['head'] as Map) : object;
        final published = object['published_at_ms'];
        if (published != null && (published is! num || !published.isFinite || published <= 0 || published > 253402300799000)) _fail('sync.cleanup.incomplete');
        _historyReferences[entry.path] = _DavHistory(entry.etag, _snapshot(storedHead), storedHead,
          published == null ? null : DateTime.fromMillisecondsSinceEpoch((published as num).toInt(), isUtc: true),
          wrapped && object['important'] == true, wrapped && object['retired'] == true);
      }
      final refs = Map<String, _DavHistory>.from(_historyReferences);
      DateTime date(_DavEntry entry) => refs[entry.path]!.published ?? snapshotsByPath[refs[entry.path]!.snapshot]?.modified ?? entry.modified;
      final active = backups.where((e) => !refs[e.path]!.retired).toList()
        ..sort((a, b) { final order = date(b).compareTo(date(a)); return order != 0 ? order : a.path.compareTo(b.path); });
      final canonical = <String, _DavEntry>{};
      for (final e in active) {
        final ref = refs[e.path]!, previous = canonical[refs[e.path]!.snapshot];
        if (previous == null || (ref.important && !refs[previous.path]!.important)) canonical[ref.snapshot] = e;
      }
      final retained = <String>{}, days = <String, int>{};
      var recent = 0;
      final dailyCount = config['daily_history_count'] as int? ?? 5;
      if (dailyCount < 3 || dailyCount > 99) _fail('sync.errors.dailyHistoryCount');
      for (final e in active) {
        final ref = refs[e.path]!, published = date(e);
        if (canonical[ref.snapshot]?.path != e.path || published.isBefore(historyCutoff)) continue;
        if (ref.snapshot == currentSnapshot) { if (ref.important) retained.add(e.path); continue; }
        if (published.isAfter(now)) { retained.add(e.path); continue; }
        if (recent++ < 5) retained.add(e.path);
        final day = published.toUtc().toIso8601String().split('T').first, count = days[published.toUtc().toIso8601String().split('T').first] ?? 0;
        if ((days.containsKey(day) || days.length < 30) && count < dailyCount) { retained.add(e.path); days[day] = count + 1; }
        if (ref.important) retained.add(e.path);
      }
      final retiring = active.where((e) => !retained.contains(e.path) && e.modified.isBefore(readCutoff)).toList();
      final retired = backups.where((e) => refs[e.path]!.retired && e.modified.isBefore(readCutoff)).toList();
      final protected = {currentSnapshot, ...active.map((e) => refs[e.path]!.snapshot)};
      final managed = refs.values.map((e) => e.snapshot).toSet();
      final unused = snapshots.where((e) => !managed.contains(e.path) && e.path != currentSnapshot && e.modified.isBefore(orphanCutoff)).toList();
      final abandoned = probes.where((e) => e.modified.isBefore(orphanCutoff)).toList();
      if (retiring.isEmpty && retired.isEmpty && unused.isEmpty && abandoned.isEmpty) return {'completed': true};
      if (!_cleanupDeleteVerified) {
        final path = '.credpivot-probe-${_nonce()}', bytes = utf8.encode(_nonce());
        try {
          final made = await request(path, method: 'PUT', body: bytes, limit: 1024);
          final original = await request(path, limit: 1024);
          if (![200, 201, 204].contains(made.status) || original.status != 200 || !_same(original.body, bytes)) _fail('sync.cleanup.deleteUnsupported');
          final realTag = _tag(original), wrongTag = '"${_nonce()}"';
          final wrongUpdate = await request(path, method: 'PUT', body: utf8.encode(_nonce()), headers: {'If-Match': wrongTag}, limit: 1024);
          final wrongDelete = await request(path, method: 'DELETE', headers: {'If-Match': wrongTag}, limit: 1024);
          final unchanged = await request(path, limit: 1024);
          if (wrongUpdate.status != 412 || wrongDelete.status != 412 || unchanged.status != 200 || !_same(unchanged.body, bytes) || _tag(unchanged) != realTag) _fail('sync.cleanup.deleteUnsupported');
          final deleted = await request(path, method: 'DELETE', headers: {'If-Match': realTag}, limit: 1024);
          if (![200, 204].contains(deleted.status) || (await request(path, limit: 1024)).status != 404) _fail('sync.cleanup.deleteUnsupported');
          _cleanupDeleteVerified = true;
        } finally { try { await _request(config, path, epoch, method: 'DELETE', limit: 1024); } catch (_) {} }
      }
      var marked = 0, deletedHeads = 0, deletedSnapshots = 0, deletedProbes = 0;
      for (final e in retiring) {
        if (remaining < 3) _fail('sync.cleanup.deferred');
        await current();
        final ref = refs[e.path]!;
        final marker = {'format': 'credpivot-history', 'version': 1, 'head': ref.head, 'important': ref.important, 'retired': true, 'published_at_ms': date(e).millisecondsSinceEpoch};
        final body = utf8.encode(jsonEncode(marker));
        final changed = await request(e.path, method: 'PUT', body: body, headers: {'If-Match': e.etag, 'Content-Type': 'application/json'}, limit: 1024);
        final verified = await request(e.path);
        if (![200, 204].contains(changed.status) || verified.status != 200 || !_same(verified.body, body)) _fail('sync.cleanup.changed');
        _historyReferences[e.path] = _DavHistory(_tag(verified), ref.snapshot, ref.head, date(e), ref.important, true); marked++;
      }
      final removed = <String>{};
      for (final e in retired) {
        final path = refs[e.path]!.snapshot, snapshot = snapshotsByPath[refs[e.path]!.snapshot];
        if (!protected.contains(path) && snapshot != null && !removed.contains(path)) {
          if (!snapshot.modified.isBefore(readCutoff)) continue;
          await remove(snapshot); removed.add(path); deletedSnapshots++;
        }
        await remove(e); _historyReferences.remove(e.path); deletedHeads++;
      }
      for (final e in unused) { await remove(e); deletedSnapshots++; }
      for (final e in abandoned) { await remove(e); deletedProbes++; }
      return {'completed': true, 'retired_heads': marked, 'deleted_heads': deletedHeads, 'deleted_snapshots': deletedSnapshots, 'deleted_probes': deletedProbes};
    } on PlatformException catch (error) {
      if (error.code == 'sync.cleanup.deferred') _cleanupDue = DateTime.now().add(const Duration(minutes: 5));
      rethrow;
    }
  }

  Future<Map<String, dynamic>> invoke(String method, [Map<String, dynamic>? arguments]) async {
    if (method == 'webdavCancel' || method == 'webdavTestCancel') {
      cancel(reason: method == 'webdavTestCancel' ? 'sync.test.cancelled' : 'sync.errors.locked');
      return {};
    }
    if (_busy) _fail('sync.errors.busy');
    _busy = true;
    _bootstrapRead = method == 'webdavBootstrapRead';
    final epoch = _epoch, args = arguments ?? <String, dynamic>{};
    final checks = <Map<String, dynamic>>[];
    try {
      await _check(epoch);
      if (_bootstrapRead) {
        final draft = await _normalize(args);
        final password = args['password']?.toString() ?? '';
        if (password.isEmpty) _fail('sync.errors.passwordMissing');
        return {...await _read({...draft, '_password': password}, args, epoch), 'configuration': draft};
      }
      final settings = await _settings();
      var config = Map<String, dynamic>.from(settings['webdav'] as Map? ?? {});
      if (method == 'webdavSettings') return {...config, 'password_saved': config.isNotEmpty && (await _channel.invokeMethod<String>('androidSecureRead', config['location'])) != null};
      if (method == 'webdavRemove') {
        await _agent({'type': 'sync_disconnect'});
        settings['webdav'] = null;
        await _agent({'type': 'app_settings_set', 'settings': settings});
        if (config['location'] is String) await _channel.invokeMethod('androidSecureWrite', {'location': config['location']});
        _verifiedLocation = null;
        _cleanupLocation = null; _cleanupDeleteVerified = false; _historyReferences.clear();
        return {'removed': true};
      }
      if (method == 'webdavSave' || method == 'webdavTest') {
        await _agent({'type': 'sync_control_authorize'});
        final next = await _normalize(args);
        final supplied = (args['password'] ?? '').toString();
        final old = await _channel.invokeMethod<String>('androidSecureRead', next['location']);
        final password = supplied.isNotEmpty ? supplied : old;
        if (password == null || password.isEmpty) _fail('sync.errors.passwordMissing');
        if (method == 'webdavTest' || args['verify'] == true || supplied.isNotEmpty || config['location'] != next['location'] || config['provider'] != next['provider']) {
          await _probe({...next, '_password': password}, epoch, checks);
        }
        if (method == 'webdavTest') { _verifiedLocation = null; return {'ok': true, 'checks': checks, 'initial_creation': 'move'}; }
        await _check(epoch);
        await _channel.invokeMethod('androidSecureWrite', {'location': next['location'], 'password': password});
        settings['webdav'] = next;
        try { await _agent({'type': 'app_settings_set', 'settings': settings}); }
        catch (_) { await _channel.invokeMethod('androidSecureWrite', {'location': next['location'], 'password': old}); rethrow; }
        return {...next, 'password_saved': true};
      }
      if (config.isEmpty) _fail('sync.errors.configuration');
      if (method == 'webdavProbe') { await _probe(config, epoch, checks); return {'ok': true}; }
      if (method == 'webdavRead') return await _read(config, args, epoch);
      if (method == 'webdavPublish') return await _publish(config, args, epoch);
      if (method == 'webdavCleanup') return await _cleanup(config, args, epoch);
      _fail('sync.errors.operation');
    } on PlatformException catch (error) {
      if (method == 'webdavTest') { throw PlatformException(code: error.code, message: error.message,
        details: {if (error.details is Map) ...Map<String, dynamic>.from(error.details as Map), 'checks': checks}); }
      rethrow;
    } finally { _bootstrapRead = false; _busy = false; }
  }
}

class _DavEntry {
  _DavEntry(this.path, this.etag, this.modified);
  final String path, etag;
  final DateTime modified;
}

class _DavHistory {
  _DavHistory(this.etag, this.snapshot, this.head, this.published, this.important, this.retired);
  final String etag, snapshot;
  final Map<String, dynamic> head;
  final DateTime? published;
  final bool important, retired;
}

class _DavReply {
  _DavReply(this.status, this.body, this.headers);
  final int status;
  final Uint8List body;
  final HttpHeaders headers;
}
