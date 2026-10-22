import 'package:flutter/material.dart';
import 'app_ui.dart';

/// 账号仅选择关联的验证器；网站规则在 MFA 编辑器统一维护。
class MfaBindingsEditor extends StatefulWidget {
  const MfaBindingsEditor({super.key, required this.linkedIds, required this.mfas, required this.onEdit, this.enabled = true});
  final List<String> linkedIds;
  final List<Map<String, dynamic>> mfas;
  final Future<void> Function(Map<String, dynamic>) onEdit;
  final bool enabled;
  @override
  State<MfaBindingsEditor> createState() => _MfaBindingsEditorState();
}

class _MfaBindingsEditorState extends State<MfaBindingsEditor> {
  bool choosing = false;

  Future<void> _chooseMfa() async {
    if (choosing || !widget.enabled) return;
    final available = widget.mfas.where((m) => !widget.linkedIds.contains(m['id'])).toList();
    if (available.isEmpty) return;
    setState(() => choosing = true);
    try {
      final id = await showDialog<String>(context: context, builder: (ctx) => SimpleDialog(
        title: const LText('选择要关联的 MFA'),
        children: [
          for (final mfa in available) SimpleDialogOption(
            onPressed: () => Navigator.pop(ctx, mfa['id'].toString()),
            child: Padding(padding: const EdgeInsets.symmetric(vertical: 6), child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(mfa['issuer']?.toString().isNotEmpty == true ? mfa['issuer'].toString() : tr('未命名 MFA')),
                const SizedBox(height: 4),
                Text(mfa['account']?.toString().isNotEmpty == true ? mfa['account'].toString() : tr('未填写账号标签'),
                  style: Theme.of(ctx).textTheme.bodySmall),
              ],
            ))),
          TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('取消')),
        ],
      ));
      if (!mounted || !widget.enabled || id == null) return;
      if (!widget.linkedIds.contains(id) && widget.mfas.any((mfa) => mfa['id'] == id)) {
        setState(() => widget.linkedIds.add(id));
      }
    } finally {
      if (mounted) setState(() => choosing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final available = widget.mfas.where((m) => !widget.linkedIds.contains(m['id'])).toList();
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      LText('关联 MFA', style: Theme.of(context).textTheme.titleMedium),
      const SizedBox(height: 8),
      const LText('仅选择此账号使用的验证器。浏览器根据每条 MFA 自己的网站规则匹配，多条命中时可自行选择。'),
      for (var index = 0; index < widget.linkedIds.length; index++) _card(context, index),
      if (available.isNotEmpty) Align(alignment: Alignment.centerLeft, child: TextButton.icon(
        onPressed: !widget.enabled || choosing ? null : _chooseMfa,
        icon: const Icon(Icons.add), label: const LText('关联其他 MFA'))),
      if (widget.mfas.isEmpty) const AppNotice('请先在 MFA / TOTP 页面添加验证码。'),
    ]);
  }

  Widget _card(BuildContext context, int index) {
    final id = widget.linkedIds[index];
    final options = widget.mfas.where((m) => m['id'] == id || !widget.linkedIds.contains(m['id'])).toList();
    final matches = options.where((m) => m['id'] == id);
    final selected = matches.isEmpty ? null : matches.first;
    final rules = (selected?['website_rules'] as List? ?? []).cast<Map>();
    const modes = {'exact_origin': '精确来源', 'bitwarden_default': '精确来源', 'wildcard': '通配符', 'regex': '正则', 'never': '停用'};
    return Container(key: ValueKey(id), margin: const EdgeInsets.only(top: 12), padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(border: Border.all(color: AppColors.border), borderRadius: BorderRadius.circular(12)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          Expanded(child: DropdownButtonFormField<String>(
            isExpanded: true, value: selected == null ? null : id,
            decoration: InputDecoration(labelText: tr('验证器 ${index + 1}')),
            items: [for (final m in options) DropdownMenuItem(value: m['id'].toString(),
              child: Tooltip(message: '${m['issuer']} · ${m['account']}',
                child: Text('${m['issuer']} · ${m['account']}', maxLines: 1, overflow: TextOverflow.ellipsis)))],
            onChanged: !widget.enabled ? null : (v) { if (v != null) setState(() => widget.linkedIds[index] = v); })),
          IconButton(tooltip: tr('解除关联'), onPressed: !widget.enabled ? null : () => setState(() => widget.linkedIds.removeAt(index)),
            icon: const Icon(Icons.link_off_rounded)),
        ]),
        const SizedBox(height: 8),
        if (selected == null) const AppNotice('此 MFA 已不可用，请解除关联或重新选择。')
        else ...[
          if ((selected['pending_rule_count'] as num? ?? 0) > 0)
            const AppNotice('有旧的网站范围待确认，请编辑此 MFA。'),
          if (rules.isEmpty) const LText('未配置适用网站：仅能在 App 使用，浏览器不会填充。')
          else ...[
            const LText('适用网站（由此 MFA 统一管理）'),
            for (final rule in rules) Padding(padding: const EdgeInsets.only(top: 4),
              child: Text('${rule['uri']} · ${modes[rule['match_mode']] ?? '未启用'}')),
          ],
          Align(alignment: Alignment.centerLeft, child: TextButton.icon(
            onPressed: !widget.enabled ? null : () async {
              try { await widget.onEdit(selected); }
              catch (_) { if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('无法刷新 MFA，请重新打开登录编辑器'))); }
            }, icon: const Icon(Icons.edit_outlined), label: const LText('编辑 MFA 与适用网站'))),
        ],
      ]));
  }
}
