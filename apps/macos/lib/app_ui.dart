import 'package:flutter/material.dart';
import 'app_presentation.dart';
export 'app_presentation.dart';

// 表单内容约占窗口一半；小窗口保证可读，大窗口避免单行过长。
double appEditDialogWidth(BuildContext context) {
  final width = MediaQuery.sizeOf(context).width;
  if (Theme.of(context).platform == TargetPlatform.android) return (width - 40).clamp(0.0, double.infinity).toDouble();
  if (width < 600) return (width - 80).clamp(0.0, double.infinity).toDouble();
  final desired = (width * .5).clamp(640.0, 860.0);
  final available = (width - 128).clamp(0.0, double.infinity);
  return desired.clamp(0.0, available).toDouble();
}

/// 长表单在 Android 使用完整页面；桌面继续使用原来的弹窗。
class AppEditDialog extends StatelessWidget {
  const AppEditDialog({super.key, required this.title, required this.content, required this.actions});
  final Widget title;
  final Widget content;
  final List<Widget> actions;

  @override
  Widget build(BuildContext context) {
    if (Theme.of(context).platform != TargetPlatform.android) {
      return AlertDialog(title: title, content: content, actions: actions);
    }
    return Dialog.fullscreen(child: Scaffold(
      resizeToAvoidBottomInset: true,
      body: SafeArea(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Padding(padding: const EdgeInsets.fromLTRB(20, 20, 20, 12),
          child: DefaultTextStyle(style: Theme.of(context).textTheme.titleLarge!, child: title)),
        const Divider(height: 1),
        Expanded(child: SingleChildScrollView(
          keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
          child: content)),
        const Divider(height: 1),
        // 按钮留在键盘上方，用户不必滚到长表单的末尾才能保存或取消。
        Padding(padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
          child: OverflowBar(spacing: 12, overflowSpacing: 8, alignment: MainAxisAlignment.end, children: actions)),
      ])),
    ));
  }
}

List<Widget> appFormFields(List<Widget> fields) => [
  for (var i = 0; i < fields.length; i++) ...[
    if (i > 0 && fields[i] is AppFieldRow && fields[i - 1] is AppFieldRow)
      const Divider(height: 1)
    else if (i > 0 && fields[i] is! SizedBox && fields[i - 1] is! SizedBox &&
        fields[i] is! AppFieldRow && fields[i - 1] is! AppFieldRow)
      const SizedBox(height: 16),
    fields[i],
  ],
];

// 全应用统一名称列和控件列；窄窗口改为上下排列，避免压缩输入区域。
class AppFieldRow extends StatelessWidget {
  const AppFieldRow({super.key, required this.label, required this.child, this.help});
  final String label;
  final String? help;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final help = this.help;
    return Padding(
      padding: EdgeInsets.symmetric(vertical: Theme.of(context).platform == TargetPlatform.android ? 12 : 16),
      child: LayoutBuilder(builder: (context, constraints) {
        final title = Row(children: [
          Expanded(child: Text('$label：',
              style: Theme.of(context).textTheme.titleSmall)),
          if (help != null && help.isNotEmpty) ...[
            const SizedBox(width: 8),
            Tooltip(
              message: help,
              triggerMode: TooltipTriggerMode.tap,
              child: Padding(
                padding: const EdgeInsets.all(4),
                child: Icon(Icons.info_outline_rounded, size: 17,
                    color: Theme.of(context).colorScheme.onSurfaceVariant),
              ),
            ),
          ],
        ]);
        final input = Semantics(label: label, child: child);
        if (constraints.maxWidth < 480) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [title, const SizedBox(height: 12), input],
          );
        }
        return Row(children: [
          SizedBox(width: 208, child: title),
          const SizedBox(width: 24),
          Expanded(child: input),
        ]);
      }),
    );
  }
}

Widget appFieldRows(List<Widget> rows) => Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        for (var i = 0; i < rows.length; i++) ...[
          if (i > 0) const Divider(height: 1),
          rows[i],
        ],
      ],
    );
abstract final class AppColors {
  static bool get dark => AppPresentation.instance.dark;
  static Color get surface => dark ? const Color(0xFF202637) : Colors.white;
  static Color get selected => primary.withValues(alpha: dark ? .18 : .08);
  static Color get background => dark ? const Color(0xFF151A26) : const Color(0xFFF5F6FA);
  static Color get sidebar => dark ? const Color(0xFF1B2130) : const Color(0xFFEEF0F6);
  static Color get ink => dark ? const Color(0xFFE5E9F3) : const Color(0xFF20283F);
  static Color get muted => dark ? const Color(0xFFAAB5CC) : const Color(0xFF69748A);
  static Color get border => dark ? const Color(0xFF384057) : const Color(0xFFE5E8F0);
  static Color get primary => AppPresentation.instance
      .schemeFor(dark ? Brightness.dark : Brightness.light).primary;
  static Color get green => dark ? const Color(0xFF66D3B4) : const Color(0xFF25856D);
}

ThemeData buildAppTheme({Brightness? brightness}) {
  final dark = (brightness ?? (AppColors.dark ? Brightness.dark : Brightness.light)) == Brightness.dark;
  final surface = dark ? const Color(0xFF202637) : Colors.white;
  final ink = dark ? const Color(0xFFE5E9F3) : const Color(0xFF20283F);
  final muted = dark ? const Color(0xFFAAB5CC) : const Color(0xFF69748A);
  final colors = AppPresentation.instance.schemeFor(dark ? Brightness.dark : Brightness.light);
  final primary = colors.primary;
  final border = dark ? const Color(0xFF384057) : const Color(0xFFE5E8F0);
  final scheme = colors.copyWith(
    surface: surface,
    onSurface: ink,
    onSurfaceVariant: muted,
    outlineVariant: border,
  );
  final base = ThemeData(useMaterial3: true, colorScheme: scheme);
  final shape = RoundedRectangleBorder(borderRadius: BorderRadius.circular(10));
  return base.copyWith(
    scaffoldBackgroundColor: dark ? const Color(0xFF151A26) : const Color(0xFFF5F6FA),
    // 合并字号与字重，保留基础文字颜色，避免卡片正文和详情值丢失前景色。
    textTheme: base.textTheme
        .apply(bodyColor: ink, displayColor: ink)
        .merge(TextTheme(
          headlineMedium: const TextStyle(
              fontSize: 27, fontWeight: FontWeight.w700, letterSpacing: -0.8),
          titleLarge: const TextStyle(
              fontSize: 20, fontWeight: FontWeight.w700, letterSpacing: -0.4),
          titleMedium:
              const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
          bodyMedium: const TextStyle(fontSize: 13, height: 1.55),
          bodySmall: TextStyle(
              fontSize: 12, height: 1.5, color: muted),
          labelLarge:
              const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        )),
    cardTheme: CardThemeData(
      color: surface,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(color: border),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: dark ? const Color(0xFF1A2030) : const Color(0xFFF8F9FC),
      isDense: true,
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 15),
      labelStyle: TextStyle(fontSize: 13, color: muted),
      hintStyle: TextStyle(fontSize: 13, color: muted),
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: BorderSide(color: border),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: BorderSide(color: primary, width: 1.5),
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
      minimumSize: const Size(0, 40),
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
      shape: shape,
    )),
    outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
      minimumSize: const Size(0, 40),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      foregroundColor: ink,
      side: BorderSide(color: border),
      shape: shape,
    )),
    textButtonTheme:
        TextButtonThemeData(style: TextButton.styleFrom(shape: shape)),
    iconButtonTheme: IconButtonThemeData(
        style: IconButton.styleFrom(
      foregroundColor: muted,
      iconSize: 19,
      shape: shape,
    )),
    dividerTheme: DividerThemeData(
        color: border, thickness: 1, space: 24),
    tabBarTheme: TabBarThemeData(
      labelColor: primary,
      unselectedLabelColor: muted,
      dividerColor: Colors.transparent,
      indicatorSize: TabBarIndicatorSize.tab,
      labelStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
      unselectedLabelStyle:
          const TextStyle(fontSize: 13, fontWeight: FontWeight.w500),
      indicator: BoxDecoration(
        color: surface,
        borderRadius: BorderRadius.circular(9),
        border: Border.all(color: border),
      ),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: surface,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
    ),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      backgroundColor: dark ? const Color(0xFF384057) : ink,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
    listTileTheme: ListTileThemeData(iconColor: muted),
  );
}

class AppPanel extends StatelessWidget {
  const AppPanel(
      {super.key,
      this.title,
      this.subtitle,
      this.icon,
      this.trailing,
      required this.child});

  final String? title;
  final String? subtitle;
  final IconData? icon;
  final Widget? trailing;
  final Widget child;

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            mainAxisSize: MainAxisSize.min,
            children: [
              if (title != null) ...[
                Row(children: [
                  if (icon != null) ...[
                    Icon(icon, size: 19, color: AppColors.primary),
                    const SizedBox(width: 10),
                  ],
                  Expanded(
                      child: LText(title!,
                          style: Theme.of(context).textTheme.titleMedium)),
                  if (trailing != null) trailing!,
                ]),
                if (subtitle != null) ...[
                  const SizedBox(height: 6),
                  LText(subtitle!, style: Theme.of(context).textTheme.bodySmall),
                ],
                const SizedBox(height: 18),
              ],
              child,
            ],
          ),
        ),
      );
}

class AppStatusBadge extends StatelessWidget {
  const AppStatusBadge(this.label, {super.key, this.color});

  final String label;
  final Color? color;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
            color: (color ?? AppColors.green).withValues(alpha: 0.08),
            borderRadius: BorderRadius.circular(20)),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Container(
              width: 6,
              height: 6,
              decoration: BoxDecoration(color: color ?? AppColors.green, shape: BoxShape.circle)),
          const SizedBox(width: 7),
          LText(label,
              style: TextStyle(
                  fontSize: 11, fontWeight: FontWeight.w600, color: color ?? AppColors.green)),
        ]),
      );
}

class AppEmptyState extends StatelessWidget {
  const AppEmptyState(
      {super.key,
      required this.icon,
      required this.title,
      required this.message,
      this.action});

  final IconData icon;
  final String title;
  final String message;
  final Widget? action;

  @override
  Widget build(BuildContext context) => Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 340),
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                    color: AppColors.primary.withValues(alpha: 0.07),
                    borderRadius: BorderRadius.circular(22)),
                child: Icon(icon, size: 34, color: AppColors.primary),
              ),
              const SizedBox(height: 20),
              LText(title,
                  style: Theme.of(context).textTheme.titleLarge,
                  textAlign: TextAlign.center),
              const SizedBox(height: 8),
              LText(message,
                  style: Theme.of(context).textTheme.bodySmall,
                  textAlign: TextAlign.center),
              if (action != null) ...[const SizedBox(height: 20), action!],
            ]),
          ),
        ),
      );
}

class AppSectionHeader extends StatelessWidget {
  const AppSectionHeader(
      {super.key,
      required this.title,
      required this.subtitle,
      required this.action,
      this.compact = false});

  final String title;
  final String subtitle;
  final Widget action;
  final bool compact;

  @override
  Widget build(BuildContext context) => Padding(
        padding: EdgeInsets.only(bottom: compact ? 12 : 16),
        child: LayoutBuilder(builder: (context, constraints) {
          final heading =
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            LText(title, style: compact ? Theme.of(context).textTheme.titleMedium : Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 4),
            LText(subtitle, style: Theme.of(context).textTheme.bodySmall),
          ]);
          if (!compact && constraints.maxWidth < 480) {
            return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [heading, const SizedBox(height: 12), action]);
          }
          return Row(children: [
            Expanded(child: heading),
            const SizedBox(width: 16),
            action
          ]);
        }),
      );
}

class AppNotice extends StatelessWidget {
  const AppNotice(this.message,
      {super.key, this.icon = Icons.info_outline_rounded, this.onDismiss});

  final String message;
  final IconData icon;
  final VoidCallback? onDismiss;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.all(12),
        margin: const EdgeInsets.symmetric(vertical: 8),
        decoration: BoxDecoration(
            color: AppColors.background,
            borderRadius: BorderRadius.circular(10)),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Icon(icon, size: 16, color: AppColors.muted),
          const SizedBox(width: 9),
          Expanded(
              child:
                  LText(message, style: Theme.of(context).textTheme.bodySmall)),
          if (onDismiss != null) ...[
            const SizedBox(width: 8),
            IconButton(
                onPressed: onDismiss,
                tooltip: tr('common.dismiss'),
                icon: const Icon(Icons.close_rounded, size: 16),
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 24, minHeight: 24)),
          ],
        ]),
      );
}

String displayDateTime(dynamic milliseconds) {
  final value = milliseconds is num
      ? milliseconds.toInt()
      : int.tryParse('$milliseconds');
  if (value == null || value <= 0) return tr('ui.displayDateTime.text');
  final time = DateTime.fromMillisecondsSinceEpoch(value);
  String two(int n) => n.toString().padLeft(2, '0');
  return '${time.year}/${two(time.month)}/${two(time.day)} ${two(time.hour)}:${two(time.minute)}';
}
