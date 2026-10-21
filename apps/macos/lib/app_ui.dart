import 'package:flutter/material.dart';

abstract final class AppColors {
  static const background = Color(0xFFF5F6FA);
  static const sidebar = Color(0xFFEEF0F6);
  static const ink = Color(0xFF20283F);
  static const muted = Color(0xFF69748A);
  static const border = Color(0xFFE5E8F0);
  static const primary = Color(0xFF565DD9);
  static const green = Color(0xFF25856D);
}

ThemeData buildAppTheme() {
  final scheme = ColorScheme.fromSeed(
    seedColor: AppColors.primary,
    brightness: Brightness.light,
    surface: Colors.white,
  ).copyWith(
    primary: AppColors.primary,
    onSurface: AppColors.ink,
    onSurfaceVariant: AppColors.muted,
    outlineVariant: AppColors.border,
  );
  final base = ThemeData(useMaterial3: true, colorScheme: scheme);
  final shape = RoundedRectangleBorder(borderRadius: BorderRadius.circular(10));
  return base.copyWith(
    scaffoldBackgroundColor: AppColors.background,
    // 合并字号与字重，保留基础文字颜色，避免卡片正文和详情值丢失前景色。
    textTheme: base.textTheme
        .apply(bodyColor: AppColors.ink, displayColor: AppColors.ink)
        .merge(TextTheme(
          headlineMedium: const TextStyle(
              fontSize: 27, fontWeight: FontWeight.w700, letterSpacing: -0.8),
          titleLarge: const TextStyle(
              fontSize: 20, fontWeight: FontWeight.w700, letterSpacing: -0.4),
          titleMedium:
              const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
          bodyMedium: const TextStyle(fontSize: 13, height: 1.55),
          bodySmall: const TextStyle(
              fontSize: 12, height: 1.5, color: AppColors.muted),
          labelLarge:
              const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        )),
    cardTheme: CardThemeData(
      color: Colors.white,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: AppColors.border),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: const Color(0xFFF8F9FC),
      isDense: true,
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 15),
      labelStyle: const TextStyle(fontSize: 13, color: AppColors.muted),
      hintStyle: const TextStyle(fontSize: 13, color: AppColors.muted),
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: const BorderSide(color: AppColors.border),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: const BorderSide(color: AppColors.primary, width: 1.5),
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
      foregroundColor: AppColors.ink,
      side: const BorderSide(color: AppColors.border),
      shape: shape,
    )),
    textButtonTheme:
        TextButtonThemeData(style: TextButton.styleFrom(shape: shape)),
    iconButtonTheme: IconButtonThemeData(
        style: IconButton.styleFrom(
      foregroundColor: AppColors.muted,
      iconSize: 19,
      shape: shape,
    )),
    dividerTheme: const DividerThemeData(
        color: AppColors.border, thickness: 1, space: 24),
    tabBarTheme: TabBarThemeData(
      labelColor: AppColors.primary,
      unselectedLabelColor: AppColors.muted,
      dividerColor: Colors.transparent,
      indicatorSize: TabBarIndicatorSize.tab,
      labelStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
      unselectedLabelStyle:
          const TextStyle(fontSize: 13, fontWeight: FontWeight.w500),
      indicator: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(9),
        border: Border.all(color: AppColors.border),
      ),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: Colors.white,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
    ),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      backgroundColor: AppColors.ink,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
    listTileTheme: const ListTileThemeData(iconColor: AppColors.muted),
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
                      child: Text(title!,
                          style: Theme.of(context).textTheme.titleMedium)),
                  if (trailing != null) trailing!,
                ]),
                if (subtitle != null) ...[
                  const SizedBox(height: 6),
                  Text(subtitle!, style: Theme.of(context).textTheme.bodySmall),
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
  const AppStatusBadge(this.label, {super.key, this.color = AppColors.green});

  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
            color: color.withValues(alpha: 0.08),
            borderRadius: BorderRadius.circular(20)),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Container(
              width: 6,
              height: 6,
              decoration: BoxDecoration(color: color, shape: BoxShape.circle)),
          const SizedBox(width: 7),
          Text(label,
              style: TextStyle(
                  fontSize: 11, fontWeight: FontWeight.w600, color: color)),
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
              Text(title,
                  style: Theme.of(context).textTheme.titleLarge,
                  textAlign: TextAlign.center),
              const SizedBox(height: 8),
              Text(message,
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
      required this.action});

  final String title;
  final String subtitle;
  final Widget action;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(bottom: 16),
        child: LayoutBuilder(builder: (context, constraints) {
          final heading =
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(title, style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 4),
            Text(subtitle, style: Theme.of(context).textTheme.bodySmall),
          ]);
          if (constraints.maxWidth < 480) {
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
                  Text(message, style: Theme.of(context).textTheme.bodySmall)),
          if (onDismiss != null) ...[
            const SizedBox(width: 8),
            IconButton(
                onPressed: onDismiss,
                tooltip: '关闭提示',
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
  if (value == null || value <= 0) return '尚未验证';
  final time = DateTime.fromMillisecondsSinceEpoch(value);
  String two(int n) => n.toString().padLeft(2, '0');
  return '${time.year}/${two(time.month)}/${two(time.day)} ${two(time.hour)}:${two(time.minute)}';
}
