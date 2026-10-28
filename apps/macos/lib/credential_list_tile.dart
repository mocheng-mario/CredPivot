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
                      ? AppEmptyState(
                          icon: Icons.touch_app_outlined,
                          title: tr('credentialsUi.build.title'),
                          message: tr('credentialsUi.build.message'))
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

/// 同一凭据的操作按用途分组，删除操作单独显示。
class CredentialActionSection extends StatelessWidget {
  const CredentialActionSection({
    super.key,
    required this.title,
    required this.children,
    this.dangerous = false,
  });

  final String title;
  final List<Widget> children;
  final bool dangerous;

  @override
  Widget build(BuildContext context) {
    final color = dangerous
        ? Theme.of(context).colorScheme.error
        : AppColors.muted;
    final actions = Wrap(spacing: 8, runSpacing: 8, children: children);
    return Padding(
      padding: const EdgeInsets.only(bottom: 18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (dangerous) const Divider(height: 20),
          LText(title,
              style: Theme.of(context).textTheme.labelMedium?.copyWith(
                  color: color, fontWeight: FontWeight.w600)),
          const SizedBox(height: 8),
          if (dangerous)
            OutlinedButtonTheme(
              data: OutlinedButtonThemeData(
                  style: OutlinedButton.styleFrom(
                      foregroundColor: color,
                      side: BorderSide(color: color.withValues(alpha: .4)))),
              child: actions,
            )
          else
            actions,
        ],
      ),
    );
  }
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
        appFieldRows([
          for (final field in fields.entries)
            AppFieldRow(label: tr(field.key),
              child: SelectableText(field.value.isEmpty ? tr('common.empty') : field.value,
                  style: Theme.of(context).textTheme.bodyMedium)),
        ]),
      ]);
}
