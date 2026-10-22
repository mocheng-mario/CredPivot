import 'package:flutter/material.dart';
import 'app_ui.dart';

/// 卡片展示不同的验证器，网站范围独立展开；关联仍引用账号规则 ID。
class MfaBindingsEditor extends StatefulWidget {
  const MfaBindingsEditor({super.key, required this.rules, required this.bindings, required this.mfas, this.enabled = true});
  final List<Map<String, dynamic>> rules, bindings, mfas;
  final bool enabled;
  @override
  State<MfaBindingsEditor> createState() => _MfaBindingsEditorState();
}

class _MfaBindingsEditorState extends State<MfaBindingsEditor> {
  Widget _bindingCard(BuildContext context, Map<String, dynamic> binding, int index) {
    final options = widget.mfas.where((m) => m['id'] == binding['totp_id'] ||
        !widget.bindings.any((b) => b['totp_id'] == m['id'])).toList();
    Map<String, dynamic>? selected;
    for (final mfa in options) {
      if (mfa['id'] == binding['totp_id']) selected = mfa;
    }
    final selectedRules = widget.rules.where((r) =>
        (binding['website_rule_ids'] as List).contains(r['id'])).toList();
    final account = selected?['account']?.toString() ?? '';
    return Container(
      key: ObjectKey(binding),
      margin: const EdgeInsets.only(top: 12),
      padding: const EdgeInsets.fromLTRB(14, 14, 14, 4),
      decoration: BoxDecoration(border: Border.all(color: AppColors.border), borderRadius: BorderRadius.circular(12)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          Expanded(child: DropdownButtonFormField<String>(
            isExpanded: true,
            value: selected == null ? null : binding['totp_id'] as String,
            decoration: InputDecoration(labelText: tr('验证器 ${index + 1}')),
            items: [for (final m in options) DropdownMenuItem(
              value: m['id'] as String,
              child: Tooltip(message: '${m['issuer']} · ${m['account']}',
                child: Text('${m['issuer']} · ${m['account']}', overflow: TextOverflow.ellipsis)),
            )],
            selectedItemBuilder: (_) => [for (final m in options) Align(
              alignment: Alignment.centerLeft,
              child: Text(m['issuer']?.toString().isNotEmpty == true ? m['issuer'].toString() : '未命名 MFA',
                maxLines: 1, overflow: TextOverflow.ellipsis),
            )],
            onChanged: !widget.enabled ? null : (v) => setState(() => binding['totp_id'] = v),
          )),
          IconButton(tooltip: tr('解除此 MFA 的关联'),
            onPressed: !widget.enabled ? null : () => setState(() => widget.bindings.remove(binding)),
            icon: const Icon(Icons.link_off_rounded)),
        ]),
        Padding(padding: const EdgeInsets.fromLTRB(12, 6, 12, 0), child: Tooltip(
          message: account,
          child: Text(selected == null ? '此 MFA 已不可用，请重新选择' : '账号标签：${account.isEmpty ? '未填写' : account}',
            maxLines: 1, overflow: TextOverflow.ellipsis, style: Theme.of(context).textTheme.bodySmall),
        )),
        ExpansionTile(
          tilePadding: EdgeInsets.zero,
          childrenPadding: const EdgeInsets.only(bottom: 10),
          shape: const Border(), collapsedShape: const Border(),
          initiallyExpanded: selectedRules.isEmpty,
          title: Tooltip(message: selectedRules.map((r) => r['uri']).join('\n'),
            child: LText('适用网站 · 已选 ${selectedRules.length}/${widget.rules.length} 条规则',
              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600))),
          children: [for (final rule in widget.rules) CheckboxListTile(
            dense: true, contentPadding: EdgeInsets.zero, controlAffinity: ListTileControlAffinity.leading,
            value: (binding['website_rule_ids'] as List).contains(rule['id']),
            title: Text(rule['uri'].toString().isEmpty ? '（尚未填写的网站）' : rule['uri'].toString()),
            subtitle: rule['match_mode'] == 'never' ? const LText('此规则已停用') : null,
            onChanged: !widget.enabled ? null : (checked) => setState(() {
              final ids = binding['website_rule_ids'] as List;
              if (checked == true) {
                if (!ids.contains(rule['id'])) ids.add(rule['id']);
              } else {
                ids.remove(rule['id']);
              }
            }),
          )],
        ),
      ]),
    );
  }

  @override
  Widget build(BuildContext context) {
    final available = widget.mfas.where((m) =>
        !widget.bindings.any((b) => b['totp_id'] == m['id'])).toList();
    final sharedRules = widget.rules.where((r) =>
        const ['exact_origin', 'bitwarden_default', 'wildcard', 'regex'].contains(r['match_mode']) && widget.bindings.where((b) =>
        (b['website_rule_ids'] as List).contains(r['id'])).length > 1).length;
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      LText('按网站关联 MFA', style: Theme.of(context).textTheme.titleMedium),
      const SizedBox(height: 8),
      const LText('每张卡片是一条不同的 MFA。展开「适用网站」可修改使用范围。'),
      for (var i = 0; i < widget.bindings.length; i++) _bindingCard(context, widget.bindings[i], i),
      if (sharedRules > 0) AppNotice('$sharedRules 条网站规则关联了多条 MFA。浏览器会提供多个候选，需要选择本次使用的验证器。'),
      if (available.isNotEmpty) Align(alignment: Alignment.centerLeft, child: TextButton.icon(
        onPressed: !widget.enabled ? null : () => setState(() {
          widget.bindings.add({'totp_id': available.first['id'], 'website_rule_ids': <String>[]});
        }),
        icon: const Icon(Icons.add), label: const LText('关联其他 MFA'),
      )),
      if (widget.mfas.isEmpty) const AppNotice('请先在 MFA / TOTP 页面添加验证码。'),
    ]);
  }
}
