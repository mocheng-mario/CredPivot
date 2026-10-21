import 'package:flutter/material.dart';

import 'app_ui.dart';

Widget selectableCredentialTile({
  required BuildContext context,
  required bool selected,
  required Widget title,
  Widget? subtitle,
  VoidCallback? onTap,
  Widget? trailing,
  IconData icon = Icons.key_outlined,
}) {
  return Padding(
    padding: const EdgeInsets.only(bottom: 8),
    child: AnimatedContainer(
      duration: Duration(
          milliseconds: MediaQuery.disableAnimationsOf(context) ? 0 : 130),
      decoration: BoxDecoration(
        color: selected ? AppColors.selected : AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
            color: selected
                ? AppColors.primary.withValues(alpha: 0.55)
                : AppColors.border),
      ),
      child: Material(
        color: Colors.transparent,
        borderRadius: BorderRadius.circular(12),
        clipBehavior: Clip.antiAlias,
        child: ListTile(
          contentPadding:
              const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
          leading: Container(
            width: 38,
            height: 38,
            decoration: BoxDecoration(
                color: selected ? AppColors.surface : AppColors.background,
                borderRadius: BorderRadius.circular(10)),
            child: Icon(icon,
                size: 20,
                color: selected ? AppColors.primary : AppColors.muted),
          ),
          title: DefaultTextStyle.merge(
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
              child: title),
          subtitle: subtitle == null
              ? null
              : DefaultTextStyle.merge(
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(fontSize: 11, color: AppColors.muted),
                  child: subtitle),
          trailing: trailing ??
              (selected
                  ? Icon(Icons.chevron_right_rounded,
                      size: 18, color: AppColors.primary)
                  : null),
          onTap: onTap,
        ),
      ),
    ),
  );
}

/// 宽窗口将详情放在右侧；窄窗口只固定操作区，让列表保留可滚动空间。
class CredentialWorkspace extends StatelessWidget {
  const CredentialWorkspace(
      {super.key, required this.list, this.detail, this.actions});

  final Widget list;
  final Widget? detail;
  final Widget? actions;

  @override
  Widget build(BuildContext context) =>
      LayoutBuilder(builder: (context, constraints) {
        if (constraints.maxWidth >= 800) {
          return Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Expanded(child: list),
            const SizedBox(width: 20),
            SizedBox(
                width: 300,
                child: Card(
                  child: detail == null
                      ? const AppEmptyState(
                          icon: Icons.touch_app_outlined,
                          title: '选择一条凭据',
                          message: '在左侧选择，查看详情与可用操作。')
                      : SingleChildScrollView(
                          padding: const EdgeInsets.all(20),
                          child: Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                detail!,
                                if (actions != null) ...[
                                  const Divider(height: 32),
                                  actions!
                                ],
                              ])),
                )),
          ]);
        }
        return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Expanded(child: list),
              if (actions != null) ...[
                const SizedBox(height: 8),
                ConstrainedBox(
                  constraints:
                      BoxConstraints(maxHeight: constraints.maxHeight * 0.45),
                  child: SingleChildScrollView(
                      child: Card(
                          child: Padding(
                              padding: const EdgeInsets.all(12),
                              child: actions!))),
                ),
              ],
            ]);
      });
}

class CredentialDetails extends StatelessWidget {
  const CredentialDetails(
      {super.key,
      required this.title,
      required this.fields,
      this.icon = Icons.key_outlined});

  final String title;
  final Map<String, String> fields;
  final IconData icon;

  @override
  Widget build(BuildContext context) =>
      Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
              color: AppColors.background,
              borderRadius: BorderRadius.circular(14)),
          child: Icon(icon, size: 26, color: AppColors.primary),
        ),
        const SizedBox(height: 18),
        Text(title, style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 8),
        ...fields.entries.map((field) => Padding(
              padding: const EdgeInsets.only(top: 18),
              child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    LText(field.key,
                        style: Theme.of(context).textTheme.bodySmall),
                    const SizedBox(height: 5),
                    SelectableText(field.value.isEmpty ? tr('未填写') : field.value,
                        style: const TextStyle(fontSize: 13)),
                  ]),
            )),
      ]);
}
