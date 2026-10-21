import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';

class DiagnosticsTab extends StatefulWidget {
  const DiagnosticsTab({super.key, this.onOpenSettings, this.active = true,
    this.busy = false, required this.onRestartAgent, required this.onRelaunchApp});

  final VoidCallback? onOpenSettings;
  final bool active;
  final bool busy;
  final Future<void> Function() onRestartAgent;
  final Future<void> Function() onRelaunchApp;

  @override
  State<DiagnosticsTab> createState() => _DiagnosticsTabState();
}

class _DiagnosticsTabState extends State<DiagnosticsTab> {
  static const _logLevels = ['debug', 'info', 'warn', 'error'];
  String _logText = '';
  String _logPath = '';
  String _logLevel = 'info';
  String _recordLevel = 'info';
  bool _loading = false;
  bool _repairing = false;
  bool get _busy => widget.busy || _loading || _repairing;
  String _repairMsg = '';

  String get _filteredLogText {
    final minimumLevel = _logLevels.indexOf(_logLevel);
    return _logText.split('\n').where((line) {
      if (line.isEmpty) return false;
      // Agent 的事件格式为「时间\t级别\t来源\t事件」，按级别列过滤，避免误判事件文案。
      final fields = line.split('\t');
      if (fields.length < 2) return true;
      final level = _logLevels.indexOf(fields[1].toLowerCase());
      // 读取失败、暂无日志等状态提示不属于事件，仍需展示。
      return level < 0 || level >= minimumLevel;
    }).join('\n');
  }

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  @override
  void didUpdateWidget(covariant DiagnosticsTab oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.active && !oldWidget.active && !_busy) _refresh();
  }

  Future<void> _repairAgentAndHost() async {
    if (_busy) return;
    setState(() {
      _repairing = true;
      _repairMsg = '';
    });
    try {
      final restarted = await AgentBridge.restartAgent();
      if (!mounted) return;
      if (!restarted) {
        setState(() => _repairMsg = 'Agent 重启失败，请完全退出 App 后重开');
        return;
      }
      final host = await AgentBridge.chromeHostStatus();
      if (!mounted) return;
      final extId = host['stored_extension_id']?.toString() ?? '';
      if (extId.isEmpty) {
        setState(
            () => _repairMsg = 'Agent 已重启。请在「设置」页保存扩展 ID，再到「浏览器连接」更新 Native Host。');
      } else {
        final r = await AgentBridge.installChromeHost(extId);
        if (!mounted) return;
        setState(
            () => _repairMsg = r['message']?.toString() ?? '已尝试重装 Native Host');
      }
      await _refresh();
    } catch (e) {
      if (mounted)
        setState(() => _repairMsg =
            '修复失败：${e is AgentException ? AgentBridge.diagnosticMessage(e) : '操作失败，请查看诊断日志'}');
    } finally {
      if (mounted) setState(() => _repairing = false);
    }
  }

  Future<void> _refresh() async {
    if (!mounted) return;
    setState(() => _loading = true);
    try {
      final data = await AgentBridge.fetchDiagnosticLog();
      if (!mounted) return;
      setState(() {
        _logPath = data['path']?.toString() ?? '';
        final level = data['level'];
        if (_logLevels.contains(level)) {
          _recordLevel = level as String;
        }
        _logText = data['text']?.toString() ?? '';
        if (_logText.isEmpty) {
          _logText = '（暂无日志，Agent 启动后会写入 ~/.credpivot/logs/agent.log）';
        }
      });
    } catch (_) {
      if (mounted) setState(() => _logText = '读取日志失败，请确认 Agent 已就绪');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final path = _logPath.isEmpty ? '~/.credpivot/logs/agent.log' : _logPath;
    final filteredLogText = _filteredLogText;
    return ListView(
      padding: const EdgeInsets.fromLTRB(24, 6, 24, 24),
      children: [
        Card(
          child: ExpansionTile(
            initiallyExpanded: true,
            shape: const Border(),
            collapsedShape: const Border(),
            leading: Icon(Icons.build_outlined, color: AppColors.primary),
            title: const LText('故障排查'),
            subtitle: const LText('连接异常时使用；重启后可能需要重新解锁和验证浏览器。'),
            childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
            children: [
              Align(
                alignment: Alignment.centerLeft,
                child: Wrap(spacing: 10, runSpacing: 10, children: [
                  OutlinedButton.icon(
                    onPressed: _busy ? null : widget.onRestartAgent,
                    icon: const Icon(Icons.restart_alt_rounded),
                    label: const LText('重启后台（Agent）')),
                  OutlinedButton.icon(
                    onPressed: _busy ? null : widget.onRelaunchApp,
                    icon: const Icon(Icons.refresh_rounded),
                    label: const LText('重新打开 App')),
                  Tooltip(
                    message: '重启 Agent 并按已保存的扩展 ID 重装 Native Host，完成后请在 Chrome 重新加载扩展。',
                    child: OutlinedButton.icon(
                      onPressed: _busy ? null : _repairAgentAndHost,
                      icon: const Icon(Icons.build_outlined),
                      label: LText(_repairing ? '修复中…' : '修复本机连接'))),
                ]),
              ),
            ],
          ),
        ),
        if (_repairMsg.isNotEmpty) AppNotice(_repairMsg),
        const SizedBox(height: 16),
        Card(
          child: ExpansionTile(
            title: const LText('运行日志'),
            subtitle: const LText('展开查看日志、筛选级别或复制运行记录'),
            leading: Icon(Icons.article_outlined, color: AppColors.primary),
            shape: const Border(),
            collapsedShape: const Border(),
            initiallyExpanded: false,
            childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            children: [
              AppSectionHeader(
                title: '日志记录',
                subtitle: '本地记录 · 用于排查 Agent 与浏览器连接问题',
                action: Wrap(spacing: 8, runSpacing: 8, children: [
                  OutlinedButton.icon(
                    onPressed: filteredLogText.isEmpty
                        ? null
                        : () {
                            Clipboard.setData(ClipboardData(text: filteredLogText));
                            ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(content: LText('已复制当前筛选日志')));
                          },
                    icon: const Icon(Icons.copy_outlined),
                    label: const LText('复制'),
                  ),
                  FilledButton.icon(
                      onPressed: _busy ? null : _refresh,
                      icon: const Icon(Icons.refresh_rounded),
                      label: const LText('刷新')),
                ]),
              ),
              Card(
                  child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                child: Wrap(
                    spacing: 16,
                    runSpacing: 8,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      Row(mainAxisSize: MainAxisSize.min, children: [
                        Icon(Icons.filter_list_rounded,
                            size: 18, color: AppColors.muted),
                        const SizedBox(width: 8),
                        LText('查看级别', style: TextStyle(color: AppColors.ink)),
                        const SizedBox(width: 12),
                        DropdownButtonHideUnderline(
                            child: DropdownButton<String>(
                          value: _logLevel,
                          isDense: true,
                          dropdownColor: AppColors.surface,
                          style: TextStyle(
                              color: AppColors.ink,
                              fontSize: 12,
                              fontWeight: FontWeight.w600),
                          items: _logLevels
                              .map((level) => DropdownMenuItem(
                                  value: level, child: Text(level.toUpperCase())))
                              .toList(),
                          onChanged: _busy ? null : (level) {
                            if (level != null) setState(() => _logLevel = level);
                          },
                        )),
                        const SizedBox(width: 8),
                        Tooltip(
                            message:
                                '仅筛选下方已读取的日志，不改变记录级别，也不会补回之前未记录的事件。',
                            child: Icon(Icons.info_outline_rounded,
                                size: 16, color: AppColors.muted)),
                      ]),
                      TextButton(
                          onPressed: widget.onOpenSettings,
                          child: LText('记录级别 ${_recordLevel.toUpperCase()} · 前往设置')),
                    ]),
              )),
              const SizedBox(height: 16),
              SizedBox(
                  height: 360,
                  child: Container(
                clipBehavior: Clip.antiAlias,
                decoration: BoxDecoration(
                    color: const Color(0xFF202637),
                    borderRadius: BorderRadius.circular(14)),
                child:
                    Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    decoration: BoxDecoration(
                        border: Border(bottom: BorderSide(color: Color(0xFF343B4C)))),
                    child: Row(children: [
                      const Icon(Icons.terminal_rounded,
                          size: 16, color: Color(0xFF99A4BD)),
                      const SizedBox(width: 10),
                      Expanded(
                          child: Tooltip(
                              message: path,
                              child: Text(path,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: const TextStyle(
                                      fontFamily: 'monospace',
                                      fontSize: 11,
                                      color: Color(0xFFB7C1D8))))),
                    ]),
                  ),
                  if (_busy)
                    const LinearProgressIndicator(minHeight: 2)
                  else
                    const SizedBox(height: 2),
                  Expanded(
                      child: SingleChildScrollView(
                    padding: const EdgeInsets.all(16),
                    child: SelectableText(
                        _logText.isEmpty
                            ? '正在读取运行日志…'
                            : (filteredLogText.isEmpty
                                ? '暂无 ${_logLevel.toUpperCase()} 及以上级别的日志'
                                : filteredLogText),
                        style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 12,
                            height: 1.8,
                            color: Color(0xFFD5DDF0))),
                  )),
                ]),
              )),
            ],
          ),
        ),
      ],
    );
  }
}
