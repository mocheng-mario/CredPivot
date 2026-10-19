import 'package:flutter/material.dart';

Widget selectableCredentialTile({
  required BuildContext context,
  required bool selected,
  required Widget title,
  Widget? subtitle,
  VoidCallback? onTap,
  Widget? trailing,
}) {
  final scheme = Theme.of(context).colorScheme;
  return Padding(
    padding: const EdgeInsets.symmetric(vertical: 2),
    child: Material(
      color: selected ? scheme.primaryContainer.withValues(alpha: 0.55) : scheme.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(8),
        side: BorderSide(
          color: selected ? scheme.primary : scheme.outlineVariant.withValues(alpha: 0.35),
          width: selected ? 2 : 1,
        ),
      ),
      child: ListTile(
        title: title,
        subtitle: subtitle,
        trailing: trailing,
        onTap: onTap,
      ),
    ),
  );
}
