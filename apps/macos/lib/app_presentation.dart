import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'agent_bridge.dart';

/// 固定语义 key 与中文参考目录共用；导入包只能提供译文，不能改写参数定义。
class AppPresentation extends ChangeNotifier with WidgetsBindingObserver {
  static final instance = AppPresentation();
  static final _keyPattern =
      RegExp(r'^[a-z][a-zA-Z0-9]*(?:\.[a-zA-Z][a-zA-Z0-9]*)+$');
  static final _parameterPattern = RegExp(r'\{([a-zA-Z][a-zA-Z0-9_]*)\}');
  static const _maxBytes = 4 * 1024 * 1024;
  String theme = 'system', language = 'zh-CN';
  static const defaultAccentColor = '#565DD9';
  String accentColor = defaultAccentColor;
  ColorScheme _lightScheme = ColorScheme.fromSeed(seedColor: const Color(0xFF565DD9));
  ColorScheme _darkScheme = ColorScheme.fromSeed(
      seedColor: const Color(0xFF565DD9), brightness: Brightness.dark);

  // 颜色方案在主题色变化时生成一次，避免每个列表项重建时重复计算调色板。
  ColorScheme schemeFor(Brightness brightness) =>
      brightness == Brightness.dark ? _darkScheme : _lightScheme;
  final Map<String, Map<String, dynamic>> _packs = {};
  final Map<String, String> names = {'zh-CN': '简体中文'};
  final List<String> loadWarnings = [];
  Map<String, dynamic> _catalog = {};
  Map<String, dynamic> _messages = {};
  bool _observing = false;

  bool get dark =>
      theme == 'dark' ||
      (theme == 'system' &&
          WidgetsBinding.instance.platformDispatcher.platformBrightness ==
              Brightness.dark);
  ThemeMode get mode => theme == 'dark'
      ? ThemeMode.dark
      : theme == 'light'
          ? ThemeMode.light
          : ThemeMode.system;
  String get directory =>
      '${Platform.environment['HOME'] ?? Directory.systemTemp.path}/.credpivot/languages';

  /// 首帧之前读取内置目录，避免启动/解锁期间把内部 key 显示给用户。
  Future<void> loadCatalog() async {
    if (_catalog.isNotEmpty) return;
    final data = Map<String, dynamic>.from(
        jsonDecode(await rootBundle.loadString('assets/languages/zh-CN.json'))
            as Map);
    _catalog = Map<String, dynamic>.from(data['messages'] as Map);
    try {
      _packs['zh-CN'] = _validate(data);
    } catch (_) {
      // 校验失败不能留下“已加载”的半成品状态，让后续调用跳过校验。
      _catalog = {};
      rethrow;
    }
  }

  Future<void> load() async {
    await loadCatalog();
    if (!_observing) {
      WidgetsBinding.instance.addObserver(this);
      _observing = true;
    }
    _packs.removeWhere((key, _) => key != 'zh-CN');
    loadWarnings.clear();
    final folder = Directory(directory);
    if (await folder.exists()) {
      await for (final file in folder.list(followLinks: false)) {
        if (file is! File || !file.path.endsWith('.json')) continue;
        try {
          if (await file.length() > _maxBytes)
            throw const FormatException('language.errors.tooLarge');
          final pack = _validate(jsonDecode(await file.readAsString()));
          if (pack['locale'] != 'zh-CN')
            _packs[pack['locale'].toString()] = pack;
        } catch (error) {
          // 旧版/损坏的包不影响解锁，但须在语言设置里说明没有加载。
          final key =
              error is FormatException && _catalog.containsKey(error.message)
                  ? error.message
                  : 'language.errors.invalid';
          loadWarnings.add(tr('language.status.skippedFile',
              args: {'file': file.uri.pathSegments.last, 'reason': tr(key)}));
        }
      }
    }
    final settings = await AgentBridge.fetchAppSettings();
    apply(Map<String, dynamic>.from(settings['settings'] as Map));
  }

  @override
  void didChangePlatformBrightness() {
    if (theme == 'system') notifyListeners();
  }

  void apply(Map<String, dynamic> settings) {
    theme = settings['theme']?.toString() ?? 'system';
    final requested = settings['accent_color']?.toString() ?? defaultAccentColor;
    final nextAccent = RegExp(r'^#[0-9a-fA-F]{6}$').hasMatch(requested)
        ? requested.toUpperCase() : defaultAccentColor;
    if (accentColor != nextAccent) {
      accentColor = nextAccent;
      final seed = Color(int.parse('FF${accentColor.substring(1)}', radix: 16));
      _lightScheme = ColorScheme.fromSeed(seedColor: seed);
      _darkScheme = ColorScheme.fromSeed(seedColor: seed, brightness: Brightness.dark);
    }
    language = settings['language']?.toString() ?? 'zh-CN';
    names.clear();
    for (final pack in _packs.values) {
      names[pack['locale'].toString()] = pack['name'].toString();
    }
    final pack = _packs[language] ?? _packs['zh-CN'];
    _messages = Map<String, dynamic>.from(pack?['messages'] as Map? ?? {});
    notifyListeners();
  }

  String translate(String key, {Map<String, Object?> args = const {}}) {
    final reference = _catalog[key];
    // 已翻译的运行状态及用户数据按原样返回，不做中文反查或句子正则匹配。
    if (reference is! Map) return key;
    final translated = (_messages[key] as Map?)?['translation'] as String?;
    final template = translated != null && translated.trim().isNotEmpty
        ? translated
        : reference['source'] as String;
    // 一次替换，不递归处理参数中的花括号，避免改写用户内容。
    return template.replaceAllMapped(
        _parameterPattern,
        (match) =>
            args.containsKey(match[1]) ? args[match[1]].toString() : match[0]!);
  }

  Set<String> _parameters(String text) =>
      _parameterPattern.allMatches(text).map((m) => m[1]!).toSet();

  Map<String, dynamic> _validate(dynamic data) {
    if (data is Map && data['version'] == 1)
      throw const FormatException('language.errors.legacy');
    if (data is! Map ||
        data['format'] != 'credpivot-language' ||
        data['version'] != 2 ||
        data['locale'] is! String ||
        data['name'] is! String ||
        data['messages'] is! Map) {
      throw const FormatException('language.errors.invalid');
    }
    final locale = data['locale'] as String;
    final name = data['name'] as String;
    if (!RegExp(r'^[a-zA-Z0-9_-]{1,64}$').hasMatch(locale) ||
        name.trim().isEmpty ||
        name.length > 100) {
      throw const FormatException('language.errors.identity');
    }
    final messages = data['messages'] as Map;
    if (messages.length > 10000)
      throw const FormatException('language.errors.tooLarge');
    final sanitized = <String, dynamic>{};
    for (final entry in messages.entries) {
      if (entry.key is! String ||
          !_keyPattern.hasMatch(entry.key as String) ||
          (entry.key as String).length > 200 ||
          entry.value is! Map) {
        throw const FormatException('language.errors.entry');
      }
      final translation = (entry.value as Map)['translation'];
      if (translation is! String || translation.length > 8192)
        throw const FormatException('language.errors.entry');
      final source = _catalog[entry.key];
      // 旧包可含已退役 key；运行时忽略，重新导出时以当前内置目录为准。
      if (source is! Map) continue;
      final expected = _parameters(source['source'] as String);
      final actual = _parameters(translation);
      if (translation.trim().isNotEmpty &&
          (expected.length != actual.length || !expected.containsAll(actual))) {
        throw FormatException('language.errors.parameters', entry.key);
      }
      sanitized[entry.key as String] = {'translation': translation};
    }
    return {
      'format': 'credpivot-language',
      'version': 2,
      'locale': locale,
      'name': name,
      'messages': sanitized
    };
  }

  Future<String?> importPack() async {
    final path = await AgentBridge.pickOpenFile();
    if (path == null) return null;
    final text = await AgentBridge.readTextFile(path);
    if (utf8.encode(text).length > _maxBytes)
      throw const FormatException('language.errors.tooLarge');
    final pack = _validate(jsonDecode(text));
    final locale = pack['locale'].toString();
    if (locale == 'zh-CN')
      throw const FormatException('language.errors.reservedLocale');
    await Directory(directory).create(recursive: true);
    await AgentBridge.writeTextFile('$directory/$locale.json',
        const JsonEncoder.withIndent('  ').convert(pack));
    _packs[locale] = pack;
    names[locale] = pack['name'].toString();
    notifyListeners();
    return locale;
  }

  Map<String, dynamic> _export(String locale, String name,
      {bool blank = false}) {
    final translations = (_packs[locale]?['messages'] as Map?) ?? {};
    return {
      'format': 'credpivot-language',
      'version': 2,
      'locale': locale,
      'name': name,
      'source_locale': 'zh-CN',
      'instructions':
          'Edit locale, name, and each translation only. Keep message keys and named placeholders unchanged. Empty or missing translations use the Chinese source. Reference fields are regenerated on export.',
      'messages': {
        for (final entry in _catalog.entries)
          entry.key: {
            ...Map<String, dynamic>.from(entry.value as Map),
            'translation': blank
                ? ''
                : (translations[entry.key] as Map?)?['translation'] ?? '',
          },
      },
    };
  }

  Future<String?> exportTemplate() async => _writeExport(
      _export('en', 'English', blank: true), 'language-template.json');

  String coverage(String locale) {
    final messages = (_packs[locale]?['messages'] as Map?) ?? {};
    final translated = _catalog.keys
        .where((key) =>
            ((messages[key] as Map?)?['translation'] as String? ?? '')
                .trim()
                .isNotEmpty)
        .length;
    return tr('language.status.coverage',
        args: {'translated': translated, 'total': _catalog.length});
  }

  Future<String?> exportPack(String locale) async {
    final actual = _packs.containsKey(locale) ? locale : 'zh-CN';
    return _writeExport(
        _export(actual, _packs[actual]!['name'].toString()), '$actual.json');
  }

  Future<String?> _writeExport(
      Map<String, dynamic> pack, String filename) async {
    final path = await AgentBridge.pickSaveFile(filename);
    if (path == null) return null;
    await AgentBridge.writeTextFile(
        path, const JsonEncoder.withIndent('  ').convert(pack));
    return path;
  }

  String errorMessage(Object error) {
    if (error is FormatException && _catalog.containsKey(error.message)) {
      final message = tr(error.message);
      return error.source is String ? '$message (${error.source})' : message;
    }
    return tr('language.errors.invalid');
  }
}

String tr(String key, {Map<String, Object?> args = const {}}) =>
    AppPresentation.instance.translate(key, args: args);

/// 固定 UI key；凭据内容、文件路径和日志继续使用 Text/SelectableText。
class LText extends StatelessWidget {
  const LText(this.data,
      {super.key,
      this.args = const {},
      this.style,
      this.textAlign,
      this.textDirection,
      this.softWrap,
      this.overflow,
      this.maxLines,
      this.semanticsLabel});
  final String data;
  final Map<String, Object?> args;
  final TextStyle? style;
  final TextAlign? textAlign;
  final TextDirection? textDirection;
  final bool? softWrap;
  final TextOverflow? overflow;
  final int? maxLines;
  final String? semanticsLabel;
  @override
  Widget build(BuildContext context) => ListenableBuilder(
      listenable: AppPresentation.instance,
      builder: (context, _) => Text(tr(data, args: args),
          style: style,
          textAlign: textAlign,
          textDirection: textDirection,
          softWrap: softWrap,
          overflow: overflow,
          maxLines: maxLines,
          semanticsLabel: semanticsLabel));
}
