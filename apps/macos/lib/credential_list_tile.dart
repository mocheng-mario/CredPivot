import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';

import 'app_ui.dart';
import 'agent_bridge.dart';

class CredentialPreviewValue extends StatelessWidget {
  const CredentialPreviewValue(this.value, {super.key});
  final String value;

  Future<void> _copy(BuildContext context) async {
    try {
      final session = await AgentBridge.clipboardSession();
      if (!context.mounted) return;
      await AgentBridge.copyConcealed(value, session: session);
      if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: LText('common.copied')));
    } catch (e) {
      if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e is AgentException ? tr(e.message) : tr('common.operationFailed'))));
    }
  }

  @override
  Widget build(BuildContext context) => Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Expanded(child: SelectableText(value.isEmpty ? tr('common.empty') : value,
      style: Theme.of(context).textTheme.bodyMedium)),
    if (value.isNotEmpty) IconButton(
      tooltip: tr('common.copy'), visualDensity: VisualDensity.compact,
      icon: const Icon(Icons.copy_outlined, size: 16), onPressed: () => _copy(context)),
  ]);
}

Widget selectableCredentialTile({
  required BuildContext context,
  required bool selected,
  required Widget title,
  Widget? subtitle,
  VoidCallback? onTap,
  Widget? trailing,
  IconData icon = Icons.key_outlined,
}) {
  final mobile = defaultTargetPlatform == TargetPlatform.android;
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
              style: TextStyle(fontSize: mobile ? 14 : 13, fontWeight: FontWeight.w600),
              child: title),
          subtitle: subtitle == null
              ? null
              : DefaultTextStyle.merge(
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(fontSize: mobile ? 12 : 11, color: AppColors.muted),
                  child: subtitle),
          trailing: trailing ??
              (selected || (mobile && onTap != null)
                  ? Icon(Icons.chevron_right_rounded,
                      size: 18, color: selected ? AppColors.primary : AppColors.muted)
                  : null),
          onTap: onTap,
        ),
      ),
    ),
  );
}

/// Android 的标题、筛选随列表一起滚动，避免固定表头占满小屏。
class CredentialPanel extends StatelessWidget {
  const CredentialPanel({super.key, required this.header, required this.body,
    this.detailsOnly = false, this.detailNotice,
    this.desktopPadding = const EdgeInsets.fromLTRB(24, 12, 24, 20)});

  final List<Widget> header;
  final Widget body;
  final bool detailsOnly;
  final Widget? detailNotice;
  final EdgeInsetsGeometry desktopPadding;

  @override
  Widget build(BuildContext context) {
    final mobile = defaultTargetPlatform == TargetPlatform.android;
    return Padding(
      padding: mobile ? const EdgeInsets.fromLTRB(16, 8, 16, 8) : desktopPadding,
      child: detailsOnly
          ? Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              if (detailNotice != null) detailNotice!,
              Expanded(child: body),
            ])
          : mobile
              ? NestedScrollView(
                  headerSliverBuilder: (context, innerBoxIsScrolled) => [
                    SliverToBoxAdapter(child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch, children: header)),
                  ],
                  body: body,
                )
              : Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  ...header, Expanded(child: body),
                ]),
    );
  }
}

/// 复用原面板的编辑、验证和刷新流程，弹层状态与列表筛选互不干扰。
/// Android 上 ModalBottomSheet 在 Tab 内会出现仅有蒙层、正文高度为 0 的情况，改用全屏页。
Future<void> showCredentialDetailSheet(BuildContext context, Widget child) =>
    Navigator.of(context).push<void>(
      MaterialPageRoute<void>(
        builder: (pageContext) => Scaffold(
          backgroundColor: Theme.of(pageContext).colorScheme.surface,
          appBar: AppBar(
            automaticallyImplyLeading: false,
            scrolledUnderElevation: 0,
            actions: const [CloseButton()],
          ),
          body: child,
        ),
      ),
    );

/// 宽窗口将详情放在右侧；Android 在独立弹层中展示详情和操作。
class CredentialWorkspace extends StatelessWidget {
  const CredentialWorkspace(
      {super.key, required this.list, this.detail, this.actions, this.detailsOnly = false});

  final Widget list;
  final Widget? detail;
  final Widget? actions;
  final bool detailsOnly;

  @override
  Widget build(BuildContext context) =>
      LayoutBuilder(builder: (context, constraints) {
        if (detailsOnly) {
          return SingleChildScrollView(child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (detail == null) const Padding(
                padding: EdgeInsets.all(24), child: LText('common.noRecords')),
              if (detail != null) detail!,
              if (actions != null) ...[const Divider(height: 24), actions!],
            ],
          ));
        }
        if (defaultTargetPlatform == TargetPlatform.android) return list;
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
                              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                                if (actions != null) ...[
                                  actions!,
                                ],
                              ])))),
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
      this.copyableFields = const {},
      this.icon = Icons.key_outlined});

  final String title;
  final Map<String, String> fields;
  final Set<String> copyableFields;
  final IconData icon;

  Widget _value(BuildContext context, MapEntry<String, String> field) => copyableFields.contains(field.key)
    ? CredentialPreviewValue(field.value)
    : SelectableText(field.value.isEmpty ? tr('common.empty') : field.value,
        style: Theme.of(context).textTheme.bodyMedium);

  @override
  Widget build(BuildContext context) {
    final mobile = defaultTargetPlatform == TargetPlatform.android;
    if (mobile) {
      return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(color: AppColors.background, borderRadius: BorderRadius.circular(12)),
            child: Icon(icon, size: 24, color: AppColors.primary),
          ),
          const SizedBox(width: 12),
          Expanded(child: Text(title, style: Theme.of(context).textTheme.titleMedium)),
        ]),
        const SizedBox(height: 12),
        for (final field in fields.entries)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8),
            child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              SizedBox(width: 96, child: Text(field.key,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(color: AppColors.muted))),
              const SizedBox(width: 12),
              Expanded(child: _value(context, field)),
            ]),
          ),
      ]);
    }
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
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
              child: _value(context, field)),
        ]),
      ]);
  }
}
