import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';
import 'component_versions.dart';

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
  String? _selectedLog;
  String _activeLog = '';
  List<String> _logFiles = [];
  bool _logNewestFirst = false;
  String _logLevel = 'info';
  String _recordLevel = 'info';
  final _logScroll = ScrollController();
  bool _loading = false;
  bool _repairing = false;
  bool get _busy => widget.busy || _loading || _repairing;
  String _repairMsg = '';

  String get _filteredLogText {
    final minimumLevel = _logLevels.indexOf(_logLevel);
    final lines = _logText.split('\n').where((line) {
      if (line.isEmpty) return false;
      // Agent 的事件格式为「时间\t级别\t来源\t事件」，按级别列过滤，避免误判事件文案。
      final fields = line.split('\t');
      if (fields.length < 2) return true;
      final level = _logLevels.indexOf(fields[1].toLowerCase());
      // 读取失败、暂无日志等状态提示不属于事件，仍需展示。
      return level < 0 || level >= minimumLevel;
    }).toList();
    // 新接口已倒序；旧接口未标明顺序时仅在界面反转一次，避免两层反转回正序。
    return (_logNewestFirst ? lines : lines.reversed).join('\n');
  }

  void _showNewestLog() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && _logScroll.hasClients) _logScroll.jumpTo(0);
    });
  }

  @override
  void dispose() {
    _logScroll.dispose();
    super.dispose();
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
        setState(() => _repairMsg = tr('agent.errors.restartFailed'));
        return;
      }
      final host = await AgentBridge.chromeHostStatus();
      if (!mounted) return;
      final extId = host['stored_extension_id']?.toString() ?? '';
      if (extId.isEmpty) {
        setState(
            () => _repairMsg = tr('diagnostics.repairAgentAndHost.text'));
      } else {
        final r = await AgentBridge.installChromeHost(extId);
        if (!mounted) return;
        setState(
            () => _repairMsg = r['message']?.toString() ?? tr('diagnostics.repairAgentAndHost.text.item2'));
      }
      await _refresh();
    } catch (e) {
      if (mounted)
        setState(() => _repairMsg =
            tr('diagnostics.errors.repair', args: {'error': e is AgentException ? AgentBridge.diagnosticMessage(e) : tr('diagnostics.labels.text')}));
    } finally {
      if (mounted) setState(() => _repairing = false);
    }
  }

  Future<void> _refresh() async {
    if (!mounted) return;
    setState(() => _loading = true);
    try {
      final data = await AgentBridge.fetchDiagnosticLog(file: _selectedLog);
      if (!mounted) return;
      setState(() {
        _logPath = data['path']?.toString() ?? '';
        _activeLog = data['file']?.toString() ?? '';
        _logFiles = (data['files'] as List? ?? []).whereType<String>().toList();
        _logNewestFirst = data['order'] == 'newest_first';
        final level = data['level'];
        if (_logLevels.contains(level)) {
          _recordLevel = level as String;
        }
        _logText = data['text']?.toString() ?? '';
        if (_logText.isEmpty) {
          _logText = tr('diagnostics.refresh.text');
        }
      });
    } catch (_) {
      if (mounted) setState(() {
        if (_selectedLog != null) _activeLog = _selectedLog!;
        _logPath = '';
        _logText = tr('diagnostics.refresh.text.item2');
      });
    } finally {
      if (mounted) {
        setState(() => _loading = false);
        _showNewestLog();
      }
    }
  }

  String _logFileLabel(String file) {
    if (file == 'agent.log') return tr('diagnostics.log.legacyFile');
    if (file.startsWith('agent.log.')) {
      return tr('diagnostics.log.legacyPart', args: {'part': file.substring(10)});
    }
    final parts = file.substring(6).split('.log');
    return parts.length > 1 && parts[1].startsWith('.')
        ? tr('diagnostics.log.datePart', args: {'date': parts[0], 'part': parts[1].substring(1)})
        : parts[0];
  }

  @override
  Widget build(BuildContext context) {
    final path = _logPath.isEmpty ? '~/.credpivot/logs/' : _logPath;
    final filteredLogText = _filteredLogText;
    return ListView(
      padding: const EdgeInsets.fromLTRB(24, 6, 24, 24),
      children: [
        const ComponentVersions(),
        const SizedBox(height:16),
        Card(
          child: ExpansionTile(
            initiallyExpanded: true,
            shape: const Border(),
            collapsedShape: const Border(),
            leading: Icon(Icons.build_outlined, color: AppColors.primary),
            title: const LText('diagnostics.build.text'),
            subtitle: const LText('diagnostics.build.text.item2'),
            childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
            children: [
              Align(
                alignment: Alignment.centerLeft,
                child: Wrap(spacing: 10, runSpacing: 10, children: [
                  OutlinedButton.icon(
                    onPressed: _busy ? null : widget.onRestartAgent,
                    icon: const Icon(Icons.restart_alt_rounded),
                    label: const LText('diagnostics.build.text.item3')),
                  OutlinedButton.icon(
                    onPressed: _busy ? null : widget.onRelaunchApp,
                    icon: const Icon(Icons.refresh_rounded),
                    label: const LText('diagnostics.build.text.item4')),
                  Tooltip(
                    message: tr('diagnostics.build.message'),
                    child: OutlinedButton.icon(
                      onPressed: _busy ? null : _repairAgentAndHost,
                      icon: const Icon(Icons.build_outlined),
                      label: LText(_repairing ? tr('diagnostics.build.text.item5') : tr('diagnostics.build.text.item6')))),
                ]),
              ),
            ],
          ),
        ),
        if (_repairMsg.isNotEmpty) AppNotice(_repairMsg),
        const SizedBox(height: 16),
        Card(
          child: ExpansionTile(
            title: const LText('diagnostics.build.text.item7'),
            subtitle: const LText('diagnostics.build.text.item8'),
            leading: Icon(Icons.article_outlined, color: AppColors.primary),
            shape: const Border(),
            collapsedShape: const Border(),
            initiallyExpanded: false,
            childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            children: [
              AppSectionHeader(
                title: tr('diagnostics.build.title'),
                subtitle: tr('diagnostics.build.description'),
                action: Wrap(spacing: 8, runSpacing: 8, children: [
                  OutlinedButton.icon(
                    onPressed: filteredLogText.isEmpty
                        ? null
                        : () {
                            Clipboard.setData(ClipboardData(text: filteredLogText));
                            ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(content: LText('diagnostics.build.text.item9')));
                          },
                    icon: const Icon(Icons.copy_outlined),
                    label: const LText('common.copy'),
                  ),
                  FilledButton.icon(
                      onPressed: _busy ? null : _refresh,
                      icon: const Icon(Icons.refresh_rounded),
                      label: const LText('common.refresh')),
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
                      SizedBox(
                        width: 250,
                        child: AppFieldRow(label: tr('diagnostics.log.dateFile'), child: DropdownButtonFormField<String>(
                          key: ValueKey(_activeLog),
                          initialValue: _logFiles.contains(_activeLog) ? _activeLog : null,
                          isExpanded: true,
                          dropdownColor: AppColors.surface,
                          style: TextStyle(color: AppColors.ink, fontSize: 12),
                          decoration: InputDecoration(),
                          items: _logFiles.map((file) => DropdownMenuItem(
                            value: file,
                            child: Text(_logFileLabel(file), maxLines: 1, overflow: TextOverflow.ellipsis),
                          )).toList(),
                          onChanged: _busy ? null : (file) {
                            if (file == null) return;
                            _selectedLog = file;
                            _refresh();
                          },
                        )),
                      ),
                      TextButton(
                        onPressed: _busy ? null : () {
                          _selectedLog = null;
                          _refresh();
                        },
                        child: const LText('diagnostics.log.today'),
                      ),
                      Row(mainAxisSize: MainAxisSize.min, children: [
                        Icon(Icons.filter_list_rounded,
                            size: 18, color: AppColors.muted),
                        const SizedBox(width: 8),
                        LText('diagnostics.build.text.item10', style: TextStyle(color: AppColors.ink)),
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
                            if (level != null) {
                              setState(() => _logLevel = level);
                              _showNewestLog();
                            }
                          },
                        )),
                        const SizedBox(width: 8),
                        Tooltip(
                            message:
                                tr('diagnostics.build.message.item2'),
                            child: Icon(Icons.info_outline_rounded,
                                size: 16, color: AppColors.muted)),
                      ]),
                      TextButton(
                          onPressed: widget.onOpenSettings,
                          child: LText('diagnostics.log.recordLevel', args: {'level': _recordLevel.toUpperCase()})),
                    ]),
              )),
              const SizedBox(height: 8),
              LText('diagnostics.log.tailHint', style: TextStyle(color: AppColors.muted, fontSize: 12)),
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
                      const SizedBox(width: 10),
                      const LText('diagnostics.log.newestFirst',
                          style: TextStyle(fontSize: 11, color: Color(0xFFB7C1D8))),
                    ]),
                  ),
                  if (_busy)
                    const LinearProgressIndicator(minHeight: 2)
                  else
                    const SizedBox(height: 2),
                  Expanded(
                      child: SingleChildScrollView(
                    controller: _logScroll,
                    padding: const EdgeInsets.all(16),
                    child: SelectableText(
                        _logText.isEmpty
                            ? tr('diagnostics.build.text.item12')
                            : (filteredLogText.isEmpty
                                ? tr('diagnostics.log.noMatchingEntries', args: {'level': _logLevel.toUpperCase()})
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
