import 'package:flutter/material.dart';

import 'app_ui.dart';

const appPageTitles = ['保险库', '凭据', '浏览器连接', '安全中心', '诊断', '设置'];
const appPageDescriptions = [
  '管理保险库、主密码与备份',
  '让密码、验证码与服务器井然有序',
  '连接 Chrome，安全地保存与填充',
  '管理恢复码、备份与数据迁移',
  '查看运行日志、排查连接问题与重启应用',
  '按你的习惯管理安全策略与本机偏好',
];

class AppSidebar extends StatelessWidget {
  const AppSidebar({
    super.key,
    required this.selectedIndex,
    required this.onSelected,
    required this.compact,
    required this.agentReady,
    required this.unlocked,
    required this.footer,
  });

  final int selectedIndex;
  final ValueChanged<int> onSelected;
  final bool compact;
  final bool agentReady;
  final bool unlocked;
  final String footer;

  @override
  Widget build(BuildContext context) => Container(
        width: compact ? 76 : 216,
        padding:
            EdgeInsets.symmetric(horizontal: compact ? 12 : 16, vertical: 24),
        decoration: const BoxDecoration(
            color: AppColors.sidebar,
            border: Border(right: BorderSide(color: AppColors.border))),
        child:
            Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Row(
              mainAxisAlignment:
                  compact ? MainAxisAlignment.center : MainAxisAlignment.start,
              children: [
                Container(
                  width: 38,
                  height: 38,
                  decoration: BoxDecoration(
                      color: AppColors.primary,
                      borderRadius: BorderRadius.circular(12)),
                  child: const Icon(Icons.shield_outlined,
                      color: Colors.white, size: 23),
                ),
                if (!compact) ...[
                  const SizedBox(width: 10),
                  const Text('CredPivot',
                      style: TextStyle(
                          fontSize: 19,
                          fontWeight: FontWeight.w700,
                          letterSpacing: -0.6)),
                ],
              ]),
          const SizedBox(height: 34),
          if (!compact)
            const Padding(
              padding: EdgeInsets.only(left: 12, bottom: 12),
              child: Text('工作空间',
                  style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                      color: AppColors.muted,
                      letterSpacing: 1)),
            ),
          Expanded(
              child: ListView(padding: EdgeInsets.zero, children: [
            _item(context, 0, Icons.grid_view_rounded),
            _item(context, 1, Icons.key_outlined),
            _item(context, 2, Icons.language_rounded),
            const Padding(
                padding: EdgeInsets.symmetric(horizontal: 12),
                child: Divider(height: 30)),
            _item(context, 3, Icons.verified_user_outlined),
            _item(context, 4, Icons.monitor_heart_outlined),
            _item(context, 5, Icons.settings_outlined),
          ])),
          if (compact)
            Tooltip(
              message:
                  agentReady ? (unlocked ? '保险库已解锁' : '保险库已锁定') : 'Agent 未就绪',
              child: Icon(
                  unlocked
                      ? Icons.lock_open_rounded
                      : Icons.lock_outline_rounded,
                  size: 20,
                  color: AppColors.muted),
            )
          else
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.65),
                  borderRadius: BorderRadius.circular(12)),
              child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(children: [
                      Icon(
                          unlocked
                              ? Icons.lock_open_rounded
                              : Icons.lock_outline_rounded,
                          size: 15,
                          color: AppColors.muted),
                      const SizedBox(width: 7),
                      const Text('本机保险库',
                          style: TextStyle(
                              fontSize: 12, fontWeight: FontWeight.w600)),
                    ]),
                    const SizedBox(height: 8),
                    AppStatusBadge(agentReady ? 'Agent 已就绪' : 'Agent 未就绪',
                        color: agentReady ? AppColors.green : AppColors.muted),
                    const SizedBox(height: 8),
                    Text(footer,
                        style: const TextStyle(
                            fontSize: 10, height: 1.6, color: AppColors.muted)),
                  ]),
            ),
        ]),
      );

  Widget _item(BuildContext context, int index, IconData icon) {
    final selected = selectedIndex == index;
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Tooltip(
        message: compact ? appPageTitles[index] : '',
        child: Semantics(
          selected: selected,
          child: AnimatedContainer(
            duration: Duration(
                milliseconds:
                    MediaQuery.disableAnimationsOf(context) ? 0 : 150),
            curve: Curves.easeOut,
            decoration: BoxDecoration(
                color: selected ? Colors.white : Colors.transparent,
                borderRadius: BorderRadius.circular(11)),
            child: Material(
              color: Colors.transparent,
              child: InkWell(
                borderRadius: BorderRadius.circular(11),
                onTap: () => onSelected(index),
                child: Padding(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 13),
                  child: Row(
                      mainAxisAlignment: compact
                          ? MainAxisAlignment.center
                          : MainAxisAlignment.start,
                      children: [
                        Icon(icon,
                            size: 21,
                            color:
                                selected ? AppColors.primary : AppColors.muted),
                        if (!compact) ...[
                          const SizedBox(width: 12),
                          Expanded(
                              child: Text(appPageTitles[index],
                                  style: TextStyle(
                                    fontSize: 13,
                                    fontWeight: selected
                                        ? FontWeight.w600
                                        : FontWeight.w500,
                                    color: selected
                                        ? AppColors.primary
                                        : AppColors.ink,
                                  ))),
                          if (selected)
                            Container(
                                width: 5,
                                height: 5,
                                decoration: const BoxDecoration(
                                    color: AppColors.primary,
                                    shape: BoxShape.circle)),
                        ],
                      ]),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
