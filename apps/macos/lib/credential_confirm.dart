import 'package:flutter/material.dart';
import 'app_presentation.dart';

/// 凭据模块危险操作二次确认。
Future<bool> confirmCredentialDanger(
  BuildContext context, {
  required String title,
  required String message,
  String confirmLabel = '确认删除',
}) async {
  final result = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(title),
      content: Text(message),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('取消')),
        FilledButton(
          style: FilledButton.styleFrom(
            backgroundColor: Theme.of(ctx).colorScheme.error,
            foregroundColor: Theme.of(ctx).colorScheme.onError,
          ),
          onPressed: () => Navigator.pop(ctx, true),
          child: Text(confirmLabel),
        ),
      ],
    ),
  );
  return result == true;
}
