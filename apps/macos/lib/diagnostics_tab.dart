import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';

class DiagnosticsTab extends StatefulWidget {
  const DiagnosticsTab({super.key});

  @override
  State<DiagnosticsTab> createState() => _DiagnosticsTabState();
}

class _DiagnosticsTabState extends State<DiagnosticsTab> {
  static const _logLevels = ['debug', 'info', 'warn', 'error'];
  String _logText = '';
  String _logPath = '';
  String _logLevel = 'info';
  bool _loading = false;
  bool _repairing = false;
  bool get _busy => _loading || _repairing;
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
            () => _repairMsg = 'Agent 已重启。请在「浏览器连接」页填写扩展 ID 并更新 Native Host。');
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
          _logLevel = level as String;
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

  Future<void> _setLogLevel(String? level) async {
    if (level == null || level == _logLevel || _busy) return;
    setState(() {
      _loading = true;
      _repairMsg = '';
    });
    try {
      await AgentBridge.setDiagnosticLogLevel(level);
      if (!mounted) return;
      setState(() => _logLevel = level);
      await _refresh();
    } catch (_) {
      if (mounted) setState(() => _repairMsg = '日志级别保存失败，请重试');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final path = _logPath.isEmpty ? '~/.credpivot/logs/agent.log' : _logPath;
    final filteredLogText = _filteredLogText;
    return Padding(
      padding: const EdgeInsets.fromLTRB(24, 6, 24, 24),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        AppSectionHeader(
          title: '运行日志',
          subtitle: '本地记录 · 用于排查 Agent 与浏览器连接问题',
          action: Wrap(spacing: 8, runSpacing: 8, children: [
            OutlinedButton.icon(
              onPressed: filteredLogText.isEmpty
                  ? null
                  : () {
                      Clipboard.setData(ClipboardData(text: filteredLogText));
                      ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('已复制当前筛选日志')));
                    },
              icon: const Icon(Icons.copy_outlined),
              label: const Text('复制'),
            ),
            FilledButton.icon(
                onPressed: _busy ? null : _refresh,
                icon: const Icon(Icons.refresh_rounded),
                label: const Text('刷新')),
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
                  const Icon(Icons.filter_list_rounded,
                      size: 18, color: AppColors.muted),
                  const SizedBox(width: 8),
                  const Text('日志级别', style: TextStyle(color: AppColors.ink)),
                  const SizedBox(width: 12),
                  DropdownButtonHideUnderline(
                      child: DropdownButton<String>(
                    value: _logLevel,
                    isDense: true,
                    dropdownColor: Colors.white,
                    style: const TextStyle(
                        color: AppColors.ink,
                        fontSize: 12,
                        fontWeight: FontWeight.w600),
                    items: _logLevels
                        .map((level) => DropdownMenuItem(
                            value: level, child: Text(level.toUpperCase())))
                        .toList(),
                    onChanged: _busy ? null : _setLogLevel,
                  )),
                  const SizedBox(width: 8),
                  const Tooltip(
                      message:
                          '记录所选级别及更严重的事件，并筛选下方已读取的日志；立即生效，重启后保留。降低级别不会补回之前未记录的日志。',
                      child: Icon(Icons.info_outline_rounded,
                          size: 16, color: AppColors.muted)),
                ]),
                Tooltip(
                  message:
                      '重启 Agent 并按已保存的扩展 ID 重装 Native Host，完成后请在 Chrome 重新加载扩展。',
                  child: TextButton.icon(
                      onPressed: _busy ? null : _repairAgentAndHost,
                      icon: const Icon(Icons.build_outlined, size: 17),
                      label: Text(_repairing ? '修复中…' : '修复本机连接')),
                ),
              ]),
        )),
        if (_repairMsg.isNotEmpty)
          ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 86),
            child: SingleChildScrollView(child: AppNotice(_repairMsg)),
          ),
        const SizedBox(height: 16),
        Expanded(
            child: Container(
          clipBehavior: Clip.antiAlias,
          decoration: BoxDecoration(
              color: const Color(0xFF202637),
              borderRadius: BorderRadius.circular(14)),
          child:
              Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              decoration: const BoxDecoration(
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
      ]),
    );
  }
}
