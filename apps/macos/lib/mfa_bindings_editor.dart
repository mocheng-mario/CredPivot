import 'package:flutter/material.dart';
import 'app_ui.dart';

/// 账号仅选择关联的验证器；网站规则在 MFA 编辑器统一维护。
class MfaBindingsEditor extends StatefulWidget {
  const MfaBindingsEditor({super.key, required this.linkedIds, required this.mfas, required this.onEdit, this.enabled = true, this.onChanged});
  final List<String> linkedIds;
  final List<Map<String, dynamic>> mfas;
  final Future<void> Function(Map<String, dynamic>) onEdit;
  final bool enabled;
  final VoidCallback? onChanged;
  @override
  State<MfaBindingsEditor> createState() => _MfaBindingsEditorState();
}

class _MfaBindingsEditorState extends State<MfaBindingsEditor> {
  bool choosing = false;

  Future<void> _chooseMfa() async {
    if (choosing || !widget.enabled) return;
    final available = widget.mfas.where((m) => !widget.linkedIds.contains(m['id'])).toList();
    setState(() => choosing = true);
    try {
      String? picked;
      final id = await showDialog<String>(context: context, builder: (ctx) => StatefulBuilder(builder: (ctx, setLocal) => SimpleDialog(
        title: const LText('mfaLinks.chooseMfa.text'),
        children: [
          Padding(padding: const EdgeInsets.symmetric(horizontal: 16), child: DropdownButtonFormField<String>(
            isExpanded: true,
            value: available.any((mfa) => mfa['id'] == picked) ? picked : null,
            decoration: InputDecoration(hintText: tr(available.isEmpty ? 'links.choose.empty' : 'links.choose')),
            items: [
              for (final mfa in available) DropdownMenuItem(value: mfa['id'].toString(), child: Text(
                '${mfa['issuer']?.toString().isNotEmpty == true ? mfa['issuer'] : tr('mfaLinks.chooseMfa.text.item2')} · ${mfa['account']?.toString().isNotEmpty == true ? mfa['account'] : tr('mfaLinks.chooseMfa.text.item3')}',
                maxLines: 1, overflow: TextOverflow.ellipsis)),
            ],
            onChanged: available.isEmpty ? null : (value) => setLocal(() => picked = value),
          )),
          OverflowBar(children: [
            TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.cancel')),
            FilledButton(onPressed: () => Navigator.pop(ctx, picked), child: const LText('mfa.links.add')),
          ]),
        ],
      )));
      if (!mounted || !widget.enabled || id == null) return;
      if (!widget.linkedIds.contains(id) && widget.mfas.any((mfa) => mfa['id'] == id)) {
        setState(() => widget.linkedIds.add(id));
        widget.onChanged?.call();
      }
    } finally {
      if (mounted) setState(() => choosing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      LText('mfa.links.add', style: Theme.of(context).textTheme.titleMedium),
      const SizedBox(height: 8),
      const LText('mfaLinks.build.text'),
      for (var index = 0; index < widget.linkedIds.length; index++) _card(context, index),
      Align(alignment: Alignment.centerLeft, child: TextButton.icon(
        onPressed: !widget.enabled || choosing ? null : _chooseMfa,
        icon: const Icon(Icons.add), label: const LText('mfa.links.addOther'))),
      if (widget.mfas.isEmpty) AppNotice(tr('mfaLinks.build.text.item2')),
    ]);
  }

  Widget _card(BuildContext context, int index) {
    final id = widget.linkedIds[index];
    final options = widget.mfas.where((m) => m['id'] == id || !widget.linkedIds.contains(m['id'])).toList();
    final matches = options.where((m) => m['id'] == id);
    final selected = matches.isEmpty ? null : matches.first;
    final rules = (selected?['website_rules'] as List? ?? []).cast<Map>();
    const modes = {'exact_origin': 'websiteRules.modes.exact', 'bitwarden_default': 'websiteRules.modes.exact', 'wildcard': 'mfaLinks.card.text', 'regex': 'mfaLinks.card.text.item2', 'never': 'mfaLinks.card.text.item3'};
    return Container(key: ValueKey(id), margin: const EdgeInsets.only(top: 12), padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(border: Border.all(color: AppColors.border), borderRadius: BorderRadius.circular(12)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          Expanded(child: AppFieldRow(label: tr('mfa.links.index', args: {'index': index + 1}), child: DropdownButtonFormField<String>(
            isExpanded: true, value: selected == null ? null : id,
            decoration: InputDecoration(),
            items: [for (final m in options) DropdownMenuItem(value: m['id'].toString(),
              child: Tooltip(message: '${m['issuer']} · ${m['account']}',
                child: Text('${m['issuer']} · ${m['account']}', maxLines: 1, overflow: TextOverflow.ellipsis)))],
            onChanged: !widget.enabled ? null : (v) { if (v != null) {
              setState(() => widget.linkedIds[index] = v);
              widget.onChanged?.call();
            } }))),
          IconButton(tooltip: tr('mfaLinks.card.text.item5'), onPressed: !widget.enabled ? null : () {
            setState(() => widget.linkedIds.removeAt(index));
            widget.onChanged?.call();
          },
            icon: const Icon(Icons.link_off_rounded)),
        ]),
        const SizedBox(height: 8),
        if (selected == null) AppNotice(tr('mfaLinks.card.text.item6'))
        else ...[
          if ((selected['pending_rule_count'] as num? ?? 0) > 0)
            AppNotice(tr('mfaLinks.card.text.item7')),
          if (rules.isEmpty) const LText('mfaLinks.card.text.item8')
          else ...[
            const LText('mfaLinks.card.text.item9'),
            for (final rule in rules) Padding(padding: const EdgeInsets.only(top: 4),
              child: Text('${rule['uri']} · ${tr(modes[rule['match_mode']] ?? 'mfaLinks.labels.text')}')),
          ],
          Align(alignment: Alignment.centerLeft, child: TextButton.icon(
            onPressed: !widget.enabled ? null : () async {
              try { await widget.onEdit(selected); }
              catch (_) { if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('mfaLinks.card.text.item10'))); }
            }, icon: const Icon(Icons.edit_outlined), label: const LText('mfaLinks.card.text.item11'))),
        ],
      ]));
  }
}
