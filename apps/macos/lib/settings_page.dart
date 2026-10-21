import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';
import 'terminal_settings.dart';
import 'touch_id_gate.dart';

class SettingsPage extends StatefulWidget {
  const SettingsPage(
      {super.key,
      required this.active,
      required this.onSaved,
      required this.onOpenVault,
      required this.onConfigureSsh,
      required this.onRemoveSsh,
      this.busy = false});

  final bool active;
  final bool busy;
  final Future<void> Function() onSaved;
  final Future<void> Function() onOpenVault;
  final Future<void> Function()? onConfigureSsh;
  final Future<void> Function() onRemoveSsh;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final _form = GlobalKey<FormState>();
  final _numbers = <String, TextEditingController>{};
  final _terminal = TextEditingController();
  final _extensionId = TextEditingController();
  Map<String, dynamic> _saved = {};
  Map<String, dynamic> _draft = {};
  Map<String, dynamic> _defaults = {};
  Map<String, dynamic> _login = {};
  String _path = '';
  String _vaultPath = '';
  String _warning = '';
  String _message = '';
  String _backupPath = '';
  String _sshMessage = '';
  bool? _sshConfigured;
  bool _loading = false;
  bool _saving = false;
  bool _restoringDefaults = false;
  bool _updatingSsh = false;
  bool _dirty = false;
  bool get _busy => widget.busy || _loading || _saving ||
      _restoringDefaults || _updatingSsh;
  bool get _loginNeedsApply =>
      _login['supported'] == true &&
      ((_draft['launch_at_login'] == true) != (_login['enabled'] == true) ||
          _login['requires_approval'] == true);

  static const _numericKeys = [
    'vault_idle_seconds',
    'sensitive_auth_seconds',
    'browser_idle_seconds',
    'clipboard_clear_seconds',
    'master_password_days',
    'master_password_idle_hours',
    'restore_interval_hours',
    'restore_keep_count',
    'log_max_mb',
    'log_backup_count',
  ];

  @override
  void initState() {
    super.initState();
    for (final key in _numericKeys) {
      _numbers[key] = TextEditingController();
    }
    _load();
  }

  @override
  void didUpdateWidget(covariant SettingsPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.active && !oldWidget.active && !_busy) {
      if (_dirty) {
        _refreshSshStatus();
      } else {
        _load();
      }
    }
  }

  @override
  void dispose() {
    for (final controller in _numbers.values) {
      controller.dispose();
    }
    _terminal.dispose();
    _extensionId.dispose();
    super.dispose();
  }

  void _populate(Map<String, dynamic> settings) {
    _draft = Map<String, dynamic>.from(settings);
    for (final key in _numericKeys) {
      final value = (settings[key] as num).toInt();
      _numbers[key]!.text =
          (key == 'vault_idle_seconds' || key == 'browser_idle_seconds'
                  ? value ~/ 60
                  : value)
              .toString();
    }
    _terminal.text = settings['terminal_app_path']?.toString() ?? '';
    _extensionId.text = settings['chrome_extension_id']?.toString() ?? '';
    _draft['launch_at_login'] = settings['launch_at_login'] == true;
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final payload = await AgentBridge.fetchAppSettings();
      final login = await AgentBridge.loginItemStatus();
      await _refreshSshStatus();
      if (!mounted) return;
      setState(() {
        _saved = Map<String, dynamic>.from(payload['settings'] as Map);
        _defaults = Map<String, dynamic>.from(payload['defaults'] as Map);
        _populate(_saved);
        _path = payload['path']?.toString() ?? '';
        _vaultPath = payload['vault_path']?.toString() ?? '';
        _warning = payload['warning']?.toString() ?? '';
        _login = login;
        _dirty = false;
      });
    } catch (_) {
      if (mounted) setState(() => _message = '配置读取失败，请重试');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _reload() async {
    if (_dirty) {
      final discard = await showDialog<bool>(
          context: context,
          builder: (ctx) => AlertDialog(
                title: const Text('放弃未保存的修改？'),
                content: const Text('重新加载将恢复当前已保存的配置。'),
                actions: [
                  TextButton(
                      onPressed: () => Navigator.pop(ctx, false),
                      child: const Text('取消')),
                  FilledButton(
                      onPressed: () => Navigator.pop(ctx, true),
                      child: const Text('重新加载')),
                ],
              ));
      if (discard != true || !mounted) return;
    }
    await _load();
  }

  Future<void> _pickTerminal() async {
    final selected = await AgentBridge.pickTerminalApplication();
    if (!mounted || selected == null) return;
    setState(() {
      _terminal.text = selected['path']?.toString() ?? '';
      _dirty = true;
    });
  }

  Future<void> _refreshSshStatus() async {
    if (!mounted) return;
    setState(() {
      _sshConfigured = null;
      _sshMessage = '正在读取 SSH 接入状态…';
    });
    try {
      final status = await AgentBridge.sshIdentityAgentStatus();
      if (!mounted) return;
      setState(() {
        _sshConfigured = status['ok'] == true && status['configured'] is bool
            ? status['configured'] as bool
            : null;
        _sshMessage = _sshConfigured == null
            ? status['message']?.toString() ?? '读取 SSH 接入状态失败，请刷新重试'
            : _sshConfigured!
                ? '已写入 CredPivot SSH IdentityAgent 配置'
                : '尚未配置 CredPivot SSH IdentityAgent';
      });
    } catch (_) {
      if (mounted) setState(() => _sshMessage = '读取 SSH 接入状态失败，请刷新重试');
    }
  }

  Future<void> _changeSshConfiguration({required bool remove}) async {
    if (_busy || (remove ? _sshConfigured != true : _sshConfigured != false)) return;
    final action = remove ? widget.onRemoveSsh : widget.onConfigureSsh;
    if (action == null) return;
    setState(() => _updatingSsh = true);
    try {
      await action();
    } catch (_) {
      if (mounted) setState(() => _message = 'SSH 配置操作未完成，请核对接入状态后重试。');
    } finally {
      // 以落盘状态更新按钮，不能把操作失败当成状态切换成功。
      await _refreshSshStatus();
      if (mounted) setState(() => _updatingSsh = false);
    }
  }

  Future<void> _restoreDefaults() async {
    if (_busy) return;
    setState(() => _restoringDefaults = true);
    try {
      final backup = await AgentBridge.backupAppSettings();
      if (!mounted) return;
      setState(() {
        _backupPath = backup ?? '';
        _populate({
          ..._defaults,
          'terminal_app_path': '',
          'chrome_extension_id': '',
          'launch_at_login': false,
          'vault_directory': _saved['vault_directory'],
        });
        _dirty = true;
        _message = '${backup == null ? '当前没有配置文件，无需备份。' : '当前配置已备份。'}'
            '已载入默认配置，点击「保存配置」后生效。';
      });
    } catch (_) {
      if (mounted) setState(() => _message = '配置备份失败，未恢复默认值，请检查配置目录权限后重试。');
    } finally {
      if (mounted) setState(() => _restoringDefaults = false);
    }
  }

  Future<void> _save() async {
    if (_busy || !(_form.currentState?.validate() ?? false)) return;
    setState(() {
      _saving = true;
      _message = '';
    });
    try {
      final current = await AgentBridge.fetchAppSettings();
      if (!mounted) return;
      if (jsonEncode(current['settings']) != jsonEncode(_saved)) {
        setState(() => _message = '配置已在其他位置更新，请重新加载后再保存。');
        return;
      }
      if (current['vault_exists'] == true) {
        if (!await requireTouchId(context, reason: '保存应用配置')) return;
      } else {
        final confirmed = await showDialog<bool>(
            context: context,
            builder: (ctx) => AlertDialog(
                  title: const Text('保存应用配置？'),
                  content: const Text('修改将应用于本机；减少日志保留数量会清理多余的旧日志。'),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(ctx, false),
                        child: const Text('取消')),
                    FilledButton(
                        onPressed: () => Navigator.pop(ctx, true),
                        child: const Text('保存')),
                  ],
                ));
        if (confirmed != true) return;
      }
      if (!mounted) return;
      final next = Map<String, dynamic>.from(_draft);
      for (final key in _numericKeys) {
        final value = int.parse(_numbers[key]!.text);
        next[key] = key == 'vault_idle_seconds' || key == 'browser_idle_seconds'
            ? value * 60
            : value;
      }
      next['terminal_app_path'] = _terminal.text.trim();
      next['chrome_extension_id'] = _extensionId.text.trim();
      final result = await AgentBridge.saveAppSettings(next);
      await widget.onSaved();
      if (!mounted) return;
      await _load();
      if (!mounted) return;
      final notice = result['platform_notice']?.toString() ?? '';
      setState(() => _message = notice.isEmpty ? '配置已保存并生效' : notice);
    } on AgentException catch (e) {
      if (mounted)
        setState(() => _message =
            e.code == 'bad_settings' || e.code == 'settings_write'
                ? e.message
                : AgentBridge.diagnosticMessage(e));
    } catch (_) {
      if (mounted) setState(() => _message = '配置保存未完成，请重新加载确认当前状态');
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Widget _number(String key, String label, String hint, String unit, int min,
          int max) =>
      Padding(
        padding: const EdgeInsets.only(bottom: 16),
        child: TextFormField(
          controller: _numbers[key],
          keyboardType: TextInputType.number,
          inputFormatters: [FilteringTextInputFormatter.digitsOnly],
          decoration: InputDecoration(
              labelText: label,
              helperText: hint,
              helperMaxLines: 3,
              suffixText: unit),
          onChanged: (_) => setState(() => _dirty = true),
          validator: (text) {
            final value = int.tryParse(text ?? '');
            return value == null || value < min || value > max
                ? '请输入 $min～$max 之间的整数'
                : null;
          },
        ),
      );

  @override
  Widget build(BuildContext context) {
    if (_draft.isEmpty) {
      return Center(
          child: _loading
              ? const CircularProgressIndicator()
              : Column(mainAxisSize: MainAxisSize.min, children: [
                  Text(_message.isEmpty ? '配置尚未加载' : _message),
                  TextButton(onPressed: _load, child: const Text('重试')),
                ]));
    }
    return AbsorbPointer(
        absorbing: _busy,
        child: Form(
            key: _form,
            child: ListView(
              padding: const EdgeInsets.fromLTRB(24, 6, 24, 24),
              children: [
                Row(children: [
                  Expanded(
                      child: Text(
                          _warning.isNotEmpty
                              ? '配置需要修复'
                              : _dirty
                                  ? '有未保存的修改'
                                  : '所有更改已保存',
                          style: Theme.of(context).textTheme.bodySmall)),
                  TextButton(onPressed: _reload, child: const Text('重新加载')),
                  TextButton(
                      onPressed: _restoreDefaults,
                      child: const Text('恢复默认')),
                  const SizedBox(width: 8),
                  FilledButton.icon(
                      onPressed:
                          _dirty || _warning.isNotEmpty || _loginNeedsApply
                              ? _save
                              : null,
                      icon: const Icon(Icons.check_rounded),
                      label: Text(_saving ? '保存中…' : '保存配置')),
                ]),
                if (_busy) const LinearProgressIndicator(),
                if (_warning.isNotEmpty) AppNotice(_warning),
                if (_message.isNotEmpty)
                  AppNotice(_message,
                      onDismiss: () => setState(() => _message = '')),
                if (_backupPath.isNotEmpty)
                  AppPanel(
                    title: '恢复默认前的配置备份',
                    child: SelectableText(_backupPath)),
                const SizedBox(height: 16),
                AppPanel(
                    title: '安全与解锁',
                    subtitle: '每次敏感操作仍需确认；重启、锁屏与睡眠后的验证始终保留。',
                    icon: Icons.lock_outline_rounded,
                    child: Column(children: [
                      _number('vault_idle_seconds', '保险库空闲锁定',
                          '1～30 分钟。凭据操作计为活动，后台状态轮询不会延长时间。', '分钟', 1, 30),
                      _number('sensitive_auth_seconds', '敏感操作验证复用',
                          '0～300 秒。0 表示每次验证；复用窗口不会随操作延长。', '秒', 0, 300),
                      _number('browser_idle_seconds', '浏览器空闲授权到期',
                          '1～30 分钟。保险库锁定或浏览器重开后仍须重新验证。', '分钟', 1, 30),
                      _number('clipboard_clear_seconds', '敏感剪贴板自动清除',
                          '5～300 秒。只清除本次复制的内容，不覆盖后来复制的其他内容。', '秒', 5, 300),
                      _number('master_password_days', '主密码验证周期',
                          '1～7 天，达到周期后必须输入主密码。', '天', 1, 7),
                      _number('master_password_idle_hours', '长时间未解锁后验证主密码',
                          '1～24 小时。从上次成功解锁计算，浏览或复制不会延长。', '小时', 1, 24),
                    ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: '自动恢复点',
                    icon: Icons.history_rounded,
                    child: Column(children: [
                      _number('restore_interval_hours', '自动恢复点间隔',
                          '1～24 小时。有变更且已解锁时创建，危险操作前仍强制创建。', '小时', 1, 24),
                      _number('restore_keep_count', '恢复点保留数量',
                          '1～100 份。减少后会在下次创建恢复点时清理旧副本。', '份', 1, 100),
                    ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: '日志记录',
                    subtitle: '查看日志和处理连接问题，请前往「诊断」。',
                    icon: Icons.article_outlined,
                    child: Column(children: [
                      DropdownButtonFormField<String>(
                        key: ValueKey(_draft['log_level']),
                        value: _draft['log_level'] as String,
                        isExpanded: true,
                        decoration: const InputDecoration(
                            labelText: '日志记录级别',
                            helperText: '记录此级别及更严重的事件；诊断页的查看筛选独立设置。',
                            helperMaxLines: 2),
                        items: ['debug', 'info', 'warn', 'error']
                            .map((level) => DropdownMenuItem(
                                value: level, child: Text(level.toUpperCase())))
                            .toList(),
                        onChanged: (value) {
                          if (value != null)
                            setState(() {
                              _draft['log_level'] = value;
                              _dirty = true;
                            });
                        },
                      ),
                      const SizedBox(height: 16),
                      _number('log_max_mb', '单个日志文件大小',
                          '1～100 MB。达到上限后轮转；日志脱敏始终开启。', 'MB', 1, 100),
                      _number('log_backup_count', '旧日志保留数量',
                          '1～10 份，不含当前日志。减少后会清理多余的旧日志。', '份', 1, 10),
                    ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: '保险库位置',
                    icon: Icons.folder_outlined,
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Text('当前保险库',
                              style: Theme.of(context).textTheme.titleSmall),
                          const SizedBox(height: 6),
                          SelectableText(_vaultPath,
                              style: Theme.of(context).textTheme.bodySmall),
                          Align(
                              alignment: Alignment.centerLeft,
                              child: TextButton.icon(
                                onPressed: _dirty
                                    ? null
                                    : () async {
                                        await widget.onOpenVault();
                                        if (mounted) await _load();
                                      },
                                icon: const Icon(Icons.folder_open_outlined),
                                label: const Text('切换保险库（会锁定当前保险库）'),
                              )),
                        ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: '通用',
                    icon: Icons.desktop_mac_outlined,
                    child: Column(children: [
                      SwitchListTile.adaptive(
                        contentPadding: EdgeInsets.zero,
                        title: const Text('登录系统时启动'),
                        subtitle: Text(_login['supported'] != true
                            ? '当前系统不支持，需要 macOS 13 或更新版本'
                            : _login['requires_approval'] == true
                                ? '系统状态：等待登录项批准'
                                : _login['enabled'] == true
                                    ? '系统状态：已启用'
                                    : '系统状态：未启用'),
                        value: _draft['launch_at_login'] == true,
                        onChanged: _login['supported'] == true
                            ? (value) => setState(() {
                                  _draft['launch_at_login'] = value;
                                  _dirty = true;
                                })
                            : null,
                      ),
                    ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: 'SSH 与终端',
                    subtitle: '终端选择随配置保存；SSH 接入与撤销立即生效。',
                    icon: Icons.terminal_rounded,
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Row(children: [
                            Expanded(
                              child: Tooltip(
                                message: _terminal.text.isEmpty ? '未选择终端应用' : _terminal.text,
                                child: InputDecorator(
                                  decoration: const InputDecoration(labelText: 'SSH 终端应用'),
                                  child: Text(
                                    terminalDisplayName({'path': _terminal.text}),
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis)))),
                            const SizedBox(width: 12),
                            OutlinedButton.icon(
                                  onPressed: _pickTerminal,
                                  icon: const Icon(Icons.folder_open_outlined),
                                  label: const Text('选择终端')),
                          ]),
                          const SizedBox(height: 16),
                          Row(children: [
                            Expanded(child: Text(_sshMessage,
                                style: Theme.of(context).textTheme.bodySmall)),
                            IconButton(
                                onPressed: _busy ? null : _refreshSshStatus,
                                tooltip: '刷新 SSH 接入状态',
                                icon: const Icon(Icons.refresh_rounded)),
                          ]),
                          Wrap(spacing: 10, runSpacing: 10, children: [
                            OutlinedButton(
                                onPressed: _sshConfigured == false && widget.onConfigureSsh != null
                                    ? () => _changeSshConfiguration(remove: false) : null,
                                child: const Text('配置 SSH IdentityAgent')),
                            OutlinedButton(
                                onPressed: _sshConfigured == true
                                    ? () => _changeSshConfiguration(remove: true) : null,
                                child: const Text('撤销 SSH IdentityAgent')),
                          ]),
                        ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: '浏览器',
                    subtitle: '管理 Chrome 扩展标识；安装和连接状态请前往「浏览器连接」。',
                    icon: Icons.language_rounded,
                    child: Column(children: [
                      TextFormField(
                        controller: _extensionId,
                        decoration: const InputDecoration(
                            labelText: 'Chrome 扩展 ID',
                            helperText:
                                '从 chrome://extensions 复制 32 位 ID。保存后更新本机连接；清空则停用。',
                            helperMaxLines: 3),
                        onChanged: (_) => setState(() => _dirty = true),
                        validator: (value) =>
                            (value ?? '').trim().isEmpty ||
                                    RegExp(r'^[a-p]{32}$')
                                        .hasMatch(value!.trim())
                                ? null
                                : '请输入由 a～p 组成的 32 位扩展 ID',
                      ),
                    ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: '配置文件',
                    subtitle:
                        'JSON 格式，不包含主密码、密钥或指纹解锁材料。页面保存会应用配置；手动编辑文件后请重新启动 App。',
                    icon: Icons.data_object_rounded,
                    child: SelectableText(_path,
                        style: Theme.of(context).textTheme.bodySmall)),
              ],
            )));
  }
}
