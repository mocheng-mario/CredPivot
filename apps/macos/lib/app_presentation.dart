import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'agent_bridge.dart';

/// 语言包只包含 UI 文案，不接触保险库数据；缺少的条目回退为原文。
class AppPresentation extends ChangeNotifier with WidgetsBindingObserver {
  static final instance = AppPresentation();
  String theme = 'system', language = 'zh-CN';
  final Map<String, Map<String, dynamic>> _packs = {};
  final Map<String, String> names = {'zh-CN': '简体中文'};
  Map<String, String> _messages = {};
  final List<(RegExp, String, List<int>)> _templates = [];
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
  Future<void> load() async {
    if (!_observing) {
      WidgetsBinding.instance.addObserver(this);
      _observing = true;
    }
    _packs.clear();
    _packs['zh-CN'] = _validate(
        jsonDecode(await rootBundle.loadString('assets/languages/zh-CN.json')));
    final folder = Directory(directory);
    if (await folder.exists()) {
      await for (final file in folder.list(followLinks: false)) {
        if (file is! File || !file.path.endsWith('.json')) continue;
        try {
          if (await file.length() > 4 * 1024 * 1024) continue;
          final pack = _validate(jsonDecode(await file.readAsString()));
          if (pack['locale'] != 'zh-CN')
            _packs[pack['locale'].toString()] = pack;
        } catch (_) {/* 损坏的语言包不影响解锁。 */}
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
    language = settings['language']?.toString() ?? 'zh-CN';
    names.clear();
    for (final pack in _packs.values) {
      names[pack['locale'].toString()] = pack['name'].toString();
    }
    final pack = _packs[language] ?? _packs['zh-CN'];
    _messages = Map<String, String>.from(pack?['messages'] as Map? ?? {});
    _templates.clear();
    for (final entry in _messages.entries) {
      if (!RegExp(r'\{\d+\}').hasMatch(entry.key)) continue;
      final chunks = entry.key.split(RegExp(r'\{\d+\}'));
      final indexes = RegExp(r'\{(\d+)\}')
          .allMatches(entry.key)
          .map((m) => int.parse(m[1]!))
          .toList();
      _templates.add((
        RegExp('^${chunks.map(RegExp.escape).join('(.*?)')}\$', dotAll: true),
        entry.value,
        indexes
      ));
    }
    notifyListeners();
  }

  String translate(String text) {
    if (language == 'zh-CN') return text;
    final exact = _messages[text];
    if (exact != null) return exact;
    if (text.length <= 4096) {
      for (final (pattern, template, indexes) in _templates) {
        final match = pattern.firstMatch(text);
        if (match == null) continue;
        return template.replaceAllMapped(RegExp(r'\{(\d+)\}'), (m) {
          final index = indexes.indexOf(int.parse(m[1]!));
          return index >= 0 ? match.group(index + 1) ?? '' : m[0]!;
        });
      }
    }
    return text;
  }

  Map<String, dynamic> _validate(dynamic data) {
    if (data is! Map ||
        data['version'] != 1 ||
        data['locale'] is! String ||
        data['name'] is! String ||
        data['messages'] is! Map) throw const FormatException('语言包格式无效');
    final locale = data['locale'] as String;
    if (!RegExp(r'^[a-zA-Z0-9_-]{1,64}$').hasMatch(locale) ||
        (data['name'] as String).length > 100)
      throw const FormatException('语言标识无效');
    final messages = data['messages'] as Map;
    if (messages.length > 10000) throw const FormatException('语言包过大');
    for (final entry in messages.entries) {
      if (entry.key is! String ||
          entry.value is! String ||
          (entry.key as String).length > 4096 ||
          (entry.value as String).length > 8192)
        throw const FormatException('语言条目无效');
      final source = RegExp(r'\{\d+\}')
          .allMatches(entry.key as String)
          .map((m) => m[0])
          .toList()
        ..sort();
      final target = RegExp(r'\{\d+\}')
          .allMatches(entry.value as String)
          .map((m) => m[0])
          .toList()
        ..sort();
      if (source.join(',') != target.join(','))
        throw const FormatException('翻译占位符不匹配');
    }
    return Map<String, dynamic>.from(data);
  }

  Future<String?> importPack() async {
    final path = await AgentBridge.pickOpenFile();
    if (path == null) return null;
    final text = await AgentBridge.readTextFile(path);
    if (utf8.encode(text).length > 4 * 1024 * 1024)
      throw const FormatException('语言包不能超过 4MB');
    final pack = _validate(jsonDecode(text));
    final locale = pack['locale'].toString();
    // 中文原文作为不可覆盖的回退和模板，避免导入损坏后丢失默认界面。
    if (locale == 'zh-CN')
      throw const FormatException('请为自定义语言使用其他 locale，例如 zh-TW、en');
    await Directory(directory).create(recursive: true);
    await AgentBridge.writeTextFile('$directory/$locale.json',
        const JsonEncoder.withIndent('  ').convert(pack));
    _packs[locale] = pack;
    names[locale] = pack['name'].toString();
    notifyListeners();
    return locale;
  }

  Future<String?> exportPack(String locale) async {
    final pack = _packs[locale] ?? _packs['zh-CN'];
    final path = await AgentBridge.pickSaveFile('$locale.json');
    if (path == null) return null;
    await AgentBridge.writeTextFile(
        path, const JsonEncoder.withIndent('  ').convert(pack));
    return path;
  }
}

String tr(String text) => AppPresentation.instance.translate(text);

/// 仅用于界面文案；用户输入、凭据内容、日志和文件路径继续使用原始 Text。
class LText extends StatelessWidget {
  const LText(this.data,
      {super.key,
      this.style,
      this.textAlign,
      this.textDirection,
      this.softWrap,
      this.overflow,
      this.maxLines,
      this.semanticsLabel});
  final String data;
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
        builder: (context, _) => Text(tr(data),
            style: style,
            textAlign: textAlign,
            textDirection: textDirection,
            softWrap: softWrap,
            overflow: overflow,
            maxLines: maxLines,
            semanticsLabel: semanticsLabel),
      );
}
