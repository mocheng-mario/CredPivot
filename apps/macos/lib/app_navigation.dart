import 'package:flutter/material.dart';

import 'app_ui.dart';

const appPageTitles = ['navigation.vault.title', 'navigation.credentials.title', 'navigation.browser.title', 'navigation.security.title', 'navigation.diagnostics.title', 'navigation.settings.title', 'navigation.shortcuts.title', 'navigation.sync.title', 'partitions.manage'];
const appPageDescriptions = [
  'navigation.vault.description',
  'navigation.credentials.description',
  'navigation.browser.description',
  'navigation.security.description',
  'navigation.diagnostics.description',
  'navigation.settings.description',
  'navigation.shortcuts.description',
  'navigation.sync.description',
  'partitions.description',
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
    required this.partitions,
    required this.selectedPartitionId,
    required this.onPartitionSelected,
  });

  final int selectedIndex;
  final ValueChanged<int> onSelected;
  final bool compact;
  final bool agentReady;
  final bool unlocked;
  final String footer;
  final List<Map<String, dynamic>> partitions;
  final String selectedPartitionId;
  final ValueChanged<String> onPartitionSelected;

  @override
  Widget build(BuildContext context) => Container(
        width: compact ? 76 : 216,
        padding:
            EdgeInsets.symmetric(horizontal: compact ? 12 : 16, vertical: 24),
        decoration: BoxDecoration(
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
                  child: Icon(Icons.shield_outlined,
                      color: AppColors.surface, size: 23),
                ),
                if (!compact) ...[
                  const SizedBox(width: 10),
                  const LText('CredPivot',
                      style: TextStyle(
                          fontSize: 19,
                          fontWeight: FontWeight.w700,
                          letterSpacing: -0.6)),
                ],
              ]),
          const SizedBox(height: 34),
          if (!compact)
            Padding(
              padding: EdgeInsets.only(left: 12, bottom: 12),
              child: LText('navigation.workspace',
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
            for (final partition in partitions)
              Padding(padding: EdgeInsets.only(left: compact ? 0 : 12), child: _item(context, 1, Icons.folder_outlined,
                title: partition['name'].toString(), active: selectedIndex == 1 && selectedPartitionId == partition['id'],
                onTap: () => onPartitionSelected(partition['id'].toString()))),
            _item(context, 8, Icons.folder_copy_outlined),
            _item(context, 2, Icons.language_rounded),
            _item(context, 7, Icons.cloud_sync_outlined),
            const Padding(
                padding: EdgeInsets.symmetric(horizontal: 12),
                child: Divider(height: 30)),
            _item(context, 3, Icons.verified_user_outlined),
            _item(context, 4, Icons.monitor_heart_outlined),
            _item(context, 5, Icons.settings_outlined),
            _item(context, 6, Icons.keyboard_outlined),
          ])),
          if (compact)
            Tooltip(
              message:
                  agentReady ? (unlocked ? tr('vault.status.unlocked') : tr('vault.status.locked')) : tr('agent.status.notReady'),
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
                  color: AppColors.surface.withValues(alpha: 0.65),
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
                      const LText('navigation.localVault',
                          style: TextStyle(
                              fontSize: 12, fontWeight: FontWeight.w600)),
                    ]),
                    const SizedBox(height: 8),
                    AppStatusBadge(agentReady ? tr('agent.status.ready') : tr('agent.status.notReady'),
                        color: agentReady ? AppColors.green : AppColors.muted),
                    const SizedBox(height: 8),
                    Text(footer,
                        style: TextStyle(
                            fontSize: 10, height: 1.6, color: AppColors.muted)),
                  ]),
            ),
        ]),
      );

  Widget _item(BuildContext context, int index, IconData icon, {String? title, bool? active, VoidCallback? onTap}) {
    final selected = active ?? (selectedIndex == index && (index != 1 || partitions.isEmpty));
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Tooltip(
        message: title ?? (compact ? tr(appPageTitles[index]) : ''),
        child: Semantics(
          selected: selected,
          child: AnimatedContainer(
            duration: Duration(
                milliseconds:
                    MediaQuery.disableAnimationsOf(context) ? 0 : 150),
            curve: Curves.easeOut,
            decoration: BoxDecoration(
                color: selected ? AppColors.surface : Colors.transparent,
                borderRadius: BorderRadius.circular(11)),
            child: Material(
              color: Colors.transparent,
              child: InkWell(
                borderRadius: BorderRadius.circular(11),
                onTap: onTap ?? () => onSelected(index),
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
                              child: Text(title ?? tr(appPageTitles[index]), maxLines: 1, overflow: TextOverflow.ellipsis,
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
                                decoration: BoxDecoration(
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
