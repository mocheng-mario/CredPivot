import 'package:flutter/material.dart';
import 'app_ui.dart';

/// 编辑窗口内统一选择关联；取消选择窗口时不修改表单。
class LinkChoice extends StatefulWidget {
  const LinkChoice({super.key, required this.title, required this.buttonLabel, required this.linkedIds,
    required this.options, this.enabled = true, this.onChanged});
  final String title, buttonLabel;
  final List<String> linkedIds;
  final List<LinkOption> options;
  final bool enabled;
  final VoidCallback? onChanged;

  @override
  State<LinkChoice> createState() => _LinkChoiceState();
}

class LinkOption {
  const LinkOption(this.id, this.title, this.subtitle);
  final String id, title, subtitle;
}

class _LinkChoiceState extends State<LinkChoice> {
  bool choosing = false;

  Future<void> choose() async {
    if (!widget.enabled || choosing) return;
    setState(() => choosing = true);
    final selected = widget.linkedIds.toSet();
    var query = '';
    try {
      final result = await showDialog<List<String>>(
        context: context,
        builder: (ctx) => StatefulBuilder(builder: (ctx, update) {
          final visible = widget.options.where((option) =>
              '${option.title} ${option.subtitle}'.toLowerCase().contains(query)).toList();
          return AlertDialog(
            title: Text(widget.title),
            content: SizedBox(
              width: appEditDialogWidth(ctx),
              height: MediaQuery.sizeOf(ctx).height * .5,
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                TextField(
                  decoration: InputDecoration(
                    hintText: tr('links.search'),
                    prefixIcon: const Icon(Icons.search),
                  ),
                  onChanged: (value) => update(() => query = value.trim().toLowerCase()),
                ),
                const SizedBox(height: 12),
                LText('links.selectedCount', args: {'count': selected.length}),
                const SizedBox(height: 8),
                Expanded(child: visible.isEmpty
                    ? Center(child: LText(widget.options.isEmpty ? 'links.choose.empty' : 'links.noMatches'))
                    : ListView.builder(
                        itemCount: visible.length,
                        itemBuilder: (_, index) {
                          final option = visible[index];
                          return CheckboxListTile(
                            contentPadding: EdgeInsets.zero,
                            value: selected.contains(option.id),
                            title: Text(option.title),
                            subtitle: option.subtitle.isEmpty ? null : Text(option.subtitle, maxLines: 2, overflow: TextOverflow.ellipsis),
                            onChanged: (checked) => update(() {
                              if (checked == true) {
                                selected.add(option.id);
                              } else {
                                selected.remove(option.id);
                              }
                            }),
                          );
                        },
                      )),
              ]),
            ),
            actions: [
              TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.cancel')),
              FilledButton(onPressed: () => Navigator.pop(ctx, selected.toList()), child: const LText('common.confirm')),
            ],
          );
        }),
      );
      if (!mounted || !widget.enabled || result == null) return;
      if (result.length == widget.linkedIds.length && result.every(widget.linkedIds.contains)) return;
      setState(() {
        widget.linkedIds
          ..clear()
          ..addAll(result);
      });
      widget.onChanged?.call();
    } finally {
      if (mounted) setState(() => choosing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Row(children: [
        Expanded(child: Text(widget.title, style: Theme.of(context).textTheme.titleMedium)),
        const SizedBox(width: 8),
        OutlinedButton.icon(
          onPressed: !widget.enabled || choosing ? null : choose,
          icon: const Icon(Icons.playlist_add_check),
          label: Text(widget.buttonLabel),
        ),
      ]),
      const SizedBox(height: 8),
      if (widget.linkedIds.isEmpty) const LText('common.notLinked'),
      for (final id in widget.linkedIds) _linked(context, id),
    ]);
  }

  Widget _linked(BuildContext context, String id) {
    final matches = widget.options.where((option) => option.id == id);
    final option = matches.isEmpty ? null : matches.first;
    return ListTile(
      contentPadding: EdgeInsets.zero,
      title: Text(option?.title ?? id, maxLines: 1, overflow: TextOverflow.ellipsis),
      subtitle: option == null || option.subtitle.isEmpty
          ? null : Text(option.subtitle, maxLines: 2, overflow: TextOverflow.ellipsis),
      trailing: IconButton(
        tooltip: tr('mfaLinks.card.text.item5'),
        onPressed: !widget.enabled || choosing ? null : () {
          setState(() => widget.linkedIds.remove(id));
          widget.onChanged?.call();
        },
        icon: const Icon(Icons.link_off_rounded),
      ),
    );
  }
}
