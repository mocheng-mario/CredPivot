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
      title: LText(title),
      content: LText(message),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('取消')),
        FilledButton(
          style: FilledButton.styleFrom(
            backgroundColor: Theme.of(ctx).colorScheme.error,
            foregroundColor: Theme.of(ctx).colorScheme.onError,
          ),
          onPressed: () => Navigator.pop(ctx, true),
          child: LText(confirmLabel),
        ),
      ],
    ),
  );
  return result == true;
}

Future<bool> confirmDiscardChanges(BuildContext context) async =>
    await showDialog<bool>(context: context, builder: (ctx) => AlertDialog(
      title: const LText('放弃未保存的修改？'),
      content: const LText('当前修改尚未保存，返回编辑可继续保留草稿。'),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('返回编辑')),
        FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const LText('放弃修改')),
      ],
    )) == true;

/// 辅助表单统一保护取消/返回，并等退出动画结束后再让调用方释放输入控制器。
Future<T?> showDraftDialog<T>({
  required BuildContext context,
  required WidgetBuilder builder,
  required bool Function() hasChanges,
  bool Function()? isBusy,
}) async {
  ModalRoute<T>? route;
  try {
    return await showDialog<T>(context: context, barrierDismissible: false, builder: (ctx) {
      route = ModalRoute.of<T>(ctx);
      return _DraftGuard(hasChanges: hasChanges, isBusy: isBusy, child: builder(ctx));
    });
  } finally { await route?.completed; }
}

class _DraftGuard extends StatefulWidget {
  const _DraftGuard({required this.child, required this.hasChanges, this.isBusy});
  final Widget child;
  final bool Function() hasChanges;
  final bool Function()? isBusy;
  @override
  State<_DraftGuard> createState() => _DraftGuardState();
}

class _DraftGuardState extends State<_DraftGuard> {
  bool _confirming = false;
  Future<void> _cancel() async {
    if (_confirming || widget.isBusy?.call() == true) return;
    _confirming = true;
    try {
      if (widget.hasChanges() && !await confirmDiscardChanges(context)) return;
      if (mounted) Navigator.pop(context);
    } finally { _confirming = false; }
  }
  @override
  Widget build(BuildContext context) => PopScope(canPop: false,
      onPopInvokedWithResult: (didPop, _) { if (!didPop) _cancel(); }, child: widget.child);
}
