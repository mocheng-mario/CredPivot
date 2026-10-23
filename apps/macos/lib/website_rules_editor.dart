import 'dart:math';
import 'package:flutter/material.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';

Map<String, dynamic> newWebsiteRule([String uri = '']) => {
  'id': List.generate(16, (_) => Random.secure().nextInt(256).toRadixString(16).padLeft(2, '0')).join(),
  'uri': uri, 'match_mode': 'exact_origin',
};

Future<String?> websiteRulesError(List<Map<String, dynamic>> rules, {bool allowEmpty = false}) async {
  if (rules.isEmpty && !allowEmpty) return tr('websiteRules.websiteRulesError.text');
  try {
    await AgentBridge.manage({'action': 'website_rules_test', 'rules': rules});
    return null;
  } on AgentException catch (e) {
    return e.message;
  }
}

/// 编辑与测试共用 Agent 的匹配器，不在 Dart 中另写一套正则规则。
class WebsiteRulesEditor extends StatefulWidget {
  const WebsiteRulesEditor({super.key, required this.rules, this.enabled = true, this.onChanged, this.onRemove});
  final List<Map<String, dynamic>> rules;
  final bool enabled;
  final VoidCallback? onChanged;
  final Future<bool> Function(String)? onRemove;
  @override
  State<WebsiteRulesEditor> createState() => _WebsiteRulesEditorState();
}

class _WebsiteRulesEditorState extends State<WebsiteRulesEditor> {
  final target = TextEditingController();
  final modes = const {
    'exact_origin': 'websiteRules.modes.exact',
    'wildcard': 'websiteRules.modes.wildcard',
    'regex': 'websiteRules.modes.regex',
    'never': 'websiteRules.Function.text',
    'bitwarden_default': 'websiteRules.Function.text.item2',
  };
  int revision = 0;
  bool testing = false;
  Map<String, dynamic>? result;
  String error = '';

  @override
  void dispose() { target.dispose(); super.dispose(); }

  void changed() {
    revision++;
    setState(() { result = null; error = ''; });
    widget.onChanged?.call();
  }

  Future<void> test() async {
    if (testing || target.text.trim().isEmpty) return;
    final version = revision;
    // 固定本次输入，等待响应期间编辑规则时不能显示过时的测试结果。
    final rules = widget.rules.map((rule) => Map<String, dynamic>.from(rule)).toList();
    setState(() { testing = true; result = null; error = ''; });
    try {
      final response = await AgentBridge.manage({'action': 'website_rules_test', 'rules': rules, 'target': target.text.trim()});
      if (mounted && version == revision) setState(() => result = response);
    } on AgentException catch (e) {
      if (mounted && version == revision) setState(() => error = e.message);
    } catch (_) {
      if (mounted && version == revision) setState(() => error = tr('websiteRules.test.text'));
    } finally {
      if (mounted) setState(() => testing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final checks = (result?['results'] as List? ?? []).cast<Map>();
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, mainAxisSize: MainAxisSize.min, children: [
      LText('websiteRules.title', style: Theme.of(context).textTheme.titleMedium),
      const SizedBox(height: 6),
      const LText('websiteRules.build.text', style: TextStyle(fontSize: 12)),
      const SizedBox(height: 12),
      for (var index = 0; index < widget.rules.length; index++) ...[
        Container(
          key: ObjectKey(widget.rules[index]),
          margin: const EdgeInsets.only(bottom: 12),
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(border: Border.all(color: AppColors.border), borderRadius: BorderRadius.circular(12)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Row(children: [
              Expanded(child: LText('websiteRules.editor.index', args: {'index': index + 1}, style: const TextStyle(fontWeight: FontWeight.w600))),
              SizedBox(width: 180, child: DropdownButtonFormField<String>(
                isExpanded: true,
                value: widget.rules[index]['match_mode']?.toString() ?? 'exact_origin',
                decoration: InputDecoration(labelText: tr('websiteRules.fields.mode')),
                items: [
                  for (final entry in modes.entries) DropdownMenuItem(value: entry.key, child: LText(entry.value)),
                  if (!modes.containsKey(widget.rules[index]['match_mode'])) DropdownMenuItem(value: widget.rules[index]['match_mode']?.toString() ?? '', child: const LText('websiteRules.build.text.item3')),
                ],
                onChanged: !widget.enabled ? null : (value) { widget.rules[index]['match_mode'] = value; changed(); },
              )),
              IconButton(tooltip: tr('websiteRules.build.text.item4'), onPressed: !widget.enabled ? null : () async {
                final rule = widget.rules[index];
                if (widget.onRemove != null && !await widget.onRemove!(rule['id'].toString())) return;
                if (!mounted) return;
                widget.rules.remove(rule); changed();
              }, icon: const Icon(Icons.close)),
            ]),
            const SizedBox(height: 12),
            TextFormField(
              enabled: widget.enabled,
              initialValue: widget.rules[index]['uri']?.toString() ?? '',
              decoration: InputDecoration(
                labelText: tr(widget.rules[index]['match_mode'] == 'regex' ? tr('websiteRules.modes.regex') : tr('websiteRules.fields.address')),
                hintText: widget.rules[index]['match_mode'] == 'regex' ? r'https://(login|sso)\.example\.com' : widget.rules[index]['match_mode'] == 'wildcard' ? 'https://*.example.com' : 'https://example.com',
                helperText: widget.rules[index]['match_mode'] == 'regex' ? tr('websiteRules.build.text.item5') : widget.rules[index]['match_mode'] == 'wildcard' ? tr('websiteRules.build.text.item6') : widget.rules[index]['match_mode'] == 'exact_origin' || widget.rules[index]['match_mode'] == 'bitwarden_default' ? tr('websiteRules.build.text.item7') : null,
                helperMaxLines: 3,
              ),
              onChanged: (value) { widget.rules[index]['uri'] = value; changed(); },
            ),
            if (index < checks.length) Padding(padding: const EdgeInsets.only(top: 8), child: LText(
              checks[index]['error']?.toString() ?? (checks[index]['inactive'] == true ? tr('websiteRules.build.text.item8') : checks[index]['matched'] == true ? tr('websiteRules.match') : tr('websiteRules.noMatch')),
              style: TextStyle(fontSize: 12, color: checks[index]['error'] != null ? Theme.of(context).colorScheme.error : checks[index]['matched'] == true ? AppColors.green : AppColors.muted),
            )),
          ]),
        ),
      ],
      Align(alignment: Alignment.centerLeft, child: TextButton.icon(
        onPressed: !widget.enabled || widget.rules.length >= 100 ? null : () { widget.rules.add(newWebsiteRule()); changed(); },
        icon: const Icon(Icons.add), label: const LText('websiteRules.build.text.item9'),
      )),
      const SizedBox(height: 12),
      Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Expanded(child: TextField(controller: target, enabled: widget.enabled, decoration: InputDecoration(labelText: tr('websiteRules.build.text.item10'), hintText: 'https://login.example.com'), onChanged: (_) => changed(), onSubmitted: (_) => test())),
        const SizedBox(width: 12),
        OutlinedButton(onPressed: !widget.enabled || testing || target.text.trim().isEmpty ? null : test, child: LText(testing ? tr('websiteRules.build.text.item11') : tr('websiteRules.build.text.item12'))),
      ]),
      if (result != null) Padding(padding: const EdgeInsets.only(top: 12), child: LText('websiteRules.test.result', args: {'result': result!['matched'] == true ? tr('websiteRules.labels.text') : tr('websiteRules.labels.text.item2'), 'origin': result!['origin']}, style: TextStyle(color: result!['matched'] == true ? AppColors.green : AppColors.muted))),
      if (error.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 12), child: Text(error, style: TextStyle(color: Theme.of(context).colorScheme.error))),
    ]);
  }
}
