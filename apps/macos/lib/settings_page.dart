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
    'password_history_limit',
    'password_reminder_days',
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

  Future<void> _importLanguage() async {
    try {
      final locale = await AppPresentation.instance.importPack();
      if (locale != null && mounted) {
        setState(() {
          _draft['language'] = locale;
          _dirty = true;
          _message = tr('settings.build.status');
        });
      }
    } catch (error) {
      if (mounted) setState(() => _message = AppPresentation.instance.errorMessage(error));
    }
  }

  Future<void> _exportLanguage({required bool template}) async {
    try {
      final path = template
          ? await AppPresentation.instance.exportTemplate()
          : await AppPresentation.instance.exportPack(_draft['language']?.toString() ?? 'zh-CN');
      if (path != null && mounted) setState(() => _message = tr('language.status.exported', args: {'path': path}));
    } catch (_) {
      if (mounted) setState(() => _message = tr('language.errors.exportFailed'));
    }
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
      if (mounted) setState(() => _message = tr('settings.load.status'));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _reload() async {
    if (_dirty) {
      final discard = await showDialog<bool>(
          context: context,
          builder: (ctx) => AlertDialog(
                title: const LText('confirmation.confirmDiscardChanges.text'),
                content: const LText('settings.reload.text'),
                actions: [
                  TextButton(
                      onPressed: () => Navigator.pop(ctx, false),
                      child: const LText('common.cancel')),
                  FilledButton(
                      onPressed: () => Navigator.pop(ctx, true),
                      child: const LText('common.reload')),
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
      _sshMessage = tr('settings.refreshSshStatus.text');
    });
    try {
      final status = await AgentBridge.sshIdentityAgentStatus();
      if (!mounted) return;
      setState(() {
        _sshConfigured = status['ok'] == true && status['configured'] is bool
            ? status['configured'] as bool
            : null;
        _sshMessage = _sshConfigured == null
            ? status['message']?.toString() ?? tr('settings.refreshSshStatus.text.item2')
            : _sshConfigured!
                ? tr('settings.refreshSshStatus.text.item3')
                : tr('settings.refreshSshStatus.text.item4');
      });
    } catch (_) {
      if (mounted) setState(() => _sshMessage = tr('settings.refreshSshStatus.text.item2'));
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
      if (mounted) setState(() => _message = tr('settings.changeSshConfiguration.status'));
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
        _message = tr('settings.defaults.loaded', args: {'backupStatus': backup == null ? tr('settings.labels.text') : tr('settings.labels.text.item2')});
      });
    } catch (_) {
      if (mounted) setState(() => _message = tr('settings.restoreDefaults.status.item2'));
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
      Map<String, dynamic> general(Map<String, dynamic> value) => Map<String, dynamic>.from(value)..removeWhere((key, _) => key.startsWith('shortcut_'));
      if (jsonEncode(general(Map<String, dynamic>.from(current['settings'] as Map))) != jsonEncode(general(_saved))) {
        setState(() => _message = tr('settings.save.status'));
        return;
      }
      if (current['vault_exists'] == true) {
        if (!await requireTouchId(context, reason: tr('settings.save.reason'))) return;
      } else {
        final confirmed = await showDialog<bool>(
            context: context,
            builder: (ctx) => AlertDialog(
                  title: const LText('settings.save.text'),
                  content: const LText('settings.save.text.item2'),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(ctx, false),
                        child: const LText('common.cancel')),
                    FilledButton(
                        onPressed: () => Navigator.pop(ctx, true),
                        child: const LText('common.save')),
                  ],
                ));
        if (confirmed != true) return;
      }
      if (!mounted) return;
      final next = Map<String, dynamic>.from(current['settings'] as Map);
      for (final entry in _draft.entries) {
        if (!entry.key.startsWith('shortcut_')) next[entry.key] = entry.value;
      }
      for (final key in _numericKeys) {
        final value = int.parse(_numbers[key]!.text);
        next[key] = key == 'vault_idle_seconds' || key == 'browser_idle_seconds'
            ? value * 60
            : value;
      }
      next['terminal_app_path'] = _terminal.text.trim();
      next['chrome_extension_id'] = _extensionId.text.trim();
      final result = await AgentBridge.saveAppSettings(next);
      AppPresentation.instance.apply(next);
      await widget.onSaved();
      if (!mounted) return;
      await _load();
      if (!mounted) return;
      final notice = result['platform_notice']?.toString() ?? '';
      setState(() => _message = notice.isEmpty ? tr('settings.save.text.item3') : notice);
    } on AgentException catch (e) {
      if (mounted)
        setState(() => _message =
            e.code == 'bad_settings' || e.code == 'settings_write'
                ? e.message
                : AgentBridge.diagnosticMessage(e));
    } catch (_) {
      if (mounted) setState(() => _message = tr('settings.save.status.item2'));
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
              labelText: tr(label),
              helperText: tr(hint),
              helperMaxLines: 3,
              suffixText: tr(unit)),
          onChanged: (_) => setState(() => _dirty = true),
          validator: (text) {
            final value = int.tryParse(text ?? '');
            return value == null || value < min || value > max
                ? tr('settings.number.text', args: {'min': min, 'max': max})
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
                  LText(_message.isEmpty ? tr('settings.build.text') : _message),
                  TextButton(onPressed: _load, child: const LText('common.retry')),
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
                      child: LText(
                          _warning.isNotEmpty
                              ? tr('settings.build.text.item2')
                              : _dirty
                                  ? tr('settings.build.text.item3')
                                  : tr('settings.build.text.item4'),
                          style: Theme.of(context).textTheme.bodySmall)),
                  TextButton(onPressed: _reload, child: const LText('common.reload')),
                  TextButton(
                      onPressed: _restoreDefaults,
                      child: const LText('common.restoreDefaults')),
                  const SizedBox(width: 8),
                  FilledButton.icon(
                      onPressed:
                          _dirty || _warning.isNotEmpty || _loginNeedsApply
                              ? _save
                              : null,
                      icon: const Icon(Icons.check_rounded),
                      label: LText(_saving ? tr('common.saving') : tr('settings.build.text.item5'))),
                ]),
                if (_busy) const LinearProgressIndicator(),
                if (_warning.isNotEmpty) AppNotice(_warning),
                if (_message.isNotEmpty)
                  AppNotice(_message,
                      onDismiss: () => setState(() => _message = '')),
                if (_backupPath.isNotEmpty)
                  AppPanel(
                    title: tr('settings.build.title'),
                    child: SelectableText(_backupPath)),
                const SizedBox(height: 16),
                AppPanel(
                    title: tr('settings.build.title.item2'),
                    subtitle: tr('settings.build.description'),
                    icon: Icons.lock_outline_rounded,
                    child: Column(children: [
                      _number('vault_idle_seconds', tr('settings.build.text.item6'),
                          tr('settings.build.text.item7'), tr('common.units.minutes'), 1, 30),
                      _number('sensitive_auth_seconds', tr('settings.build.text.item8'),
                          tr('settings.build.text.item9'), tr('common.units.seconds'), 0, 300),
                      _number('browser_idle_seconds', tr('settings.build.text.item10'),
                          tr('settings.build.text.item11'), tr('common.units.minutes'), 1, 30),
                      _number('clipboard_clear_seconds', tr('settings.build.text.item12'),
                          tr('settings.build.text.item13'), tr('common.units.seconds'), 5, 300),
                      _number('master_password_days', tr('settings.build.text.item14'),
                          tr('settings.build.text.item15'), tr('common.units.days'), 1, 7),
                      _number('master_password_idle_hours', tr('settings.build.text.item16'),
                          tr('settings.build.text.item17'), tr('common.units.hours'), 1, 24),
                    ])),
                const SizedBox(height: 16),
                AppPanel(title: tr('settings.build.title.item3'), icon: Icons.security_outlined, child: Column(children: [
                  DropdownButtonFormField<String>(
                    value: _draft['ssh_sign_policy']?.toString() ?? 'session',
                    decoration: InputDecoration(labelText: tr('settings.build.text.item18')),
                    items: const [DropdownMenuItem(value:'session',child:LText('settings.build.text.item19')),DropdownMenuItem(value:'confirm',child:LText('settings.build.text.item20')),DropdownMenuItem(value:'biometric',child:LText('settings.build.text.item21'))],
                    onChanged: (v) => setState(() { _draft['ssh_sign_policy'] = v; _dirty = true; })),
                  const SizedBox(height: 12),
                  const LText('settings.build.text.item22'),
                ])),
                const SizedBox(height: 16),
                AppPanel(title: tr('settings.build.title.item4'), icon: Icons.tune_rounded, child: Column(children: [
                  _number('password_history_limit', tr('settings.build.text.item23'), tr('settings.build.text.item24'), tr('common.units.items'), 0, 50),
                  _number('password_reminder_days', tr('settings.build.text.item25'), tr('settings.build.text.item26'), tr('common.units.days'), 0, 3650),
                  DropdownButtonFormField<String>(value: _draft['theme']?.toString() ?? 'system', decoration: InputDecoration(labelText: tr('settings.theme.label')), items: const [DropdownMenuItem(value:'system',child:LText('settings.theme.system')),DropdownMenuItem(value:'light',child:LText('settings.theme.light')),DropdownMenuItem(value:'dark',child:LText('settings.theme.dark'))],onChanged:(v)=>setState((){_draft['theme']=v;_dirty=true;})),
                  const SizedBox(height:16),
                  DropdownButtonFormField<String>(key:ValueKey(_draft['language']),value:AppPresentation.instance.names.containsKey(_draft['language'])?_draft['language'].toString():'zh-CN',decoration:InputDecoration(labelText: tr('settings.language.label')),items:AppPresentation.instance.names.entries.map((v)=>DropdownMenuItem(value:v.key,child:Text(v.value))).toList(),onChanged:(v)=>setState((){_draft['language']=v;_dirty=true;})),
                  const SizedBox(height:8),
                  const LText('language.help'),
                  Text(AppPresentation.instance.coverage(_draft['language']?.toString() ?? 'zh-CN')),
                  for (final warning in AppPresentation.instance.loadWarnings) AppNotice(warning),
                  Wrap(spacing: 8, runSpacing: 8, children: [
                    TextButton.icon(onPressed: _importLanguage,
                      icon: const Icon(Icons.file_upload_outlined), label: const LText('language.actions.import')),
                    TextButton.icon(onPressed: () => _exportLanguage(template: true),
                      icon: const Icon(Icons.translate), label: const LText('language.actions.exportTemplate')),
                    TextButton.icon(onPressed: () => _exportLanguage(template: false),
                      icon: const Icon(Icons.file_download_outlined), label: const LText('language.actions.exportCurrent')),
                  ]),
                ])),
                const SizedBox(height:16),
                AppPanel(
                    title: tr('settings.build.title.item5'),
                    icon: Icons.history_rounded,
                    child: Column(children: [
                      _number('restore_interval_hours', tr('settings.build.text.item28'),
                          tr('settings.build.text.item29'), tr('common.units.hours'), 1, 24),
                      _number('restore_keep_count', tr('settings.build.text.item30'),
                          tr('settings.build.text.item31'), tr('common.units.copies'), 1, 100),
                    ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: tr('diagnostics.build.title'),
                    subtitle: tr('settings.build.description.item2'),
                    icon: Icons.article_outlined,
                    child: Column(children: [
                      DropdownButtonFormField<String>(
                        key: ValueKey(_draft['log_level']),
                        value: _draft['log_level'] as String,
                        isExpanded: true,
                        decoration: InputDecoration(
                            labelText: tr('settings.build.text.item32'),
                            helperText: tr('settings.build.text.item33'),
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
                      _number('log_max_mb', tr('settings.build.text.item34'),
                          tr('settings.build.text.item35'), 'MB', 1, 100),
                      _number('log_backup_count', tr('settings.build.text.item36'),
                          tr('settings.build.text.item37'), tr('common.units.copies'), 1, 10),
                    ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: tr('settings.build.title.item6'),
                    icon: Icons.folder_outlined,
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          LText('settings.build.text.item38',
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
                                label: const LText('settings.build.text.item39'),
                              )),
                        ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: tr('settings.build.title.item7'),
                    icon: Icons.desktop_mac_outlined,
                    child: Column(children: [
                      SwitchListTile.adaptive(
                        contentPadding: EdgeInsets.zero,
                        title: const LText('settings.build.text.item40'),
                        subtitle: LText(_login['supported'] != true
                            ? tr('settings.build.text.item41')
                            : _login['requires_approval'] == true
                                ? tr('settings.build.text.item42')
                                : _login['enabled'] == true
                                    ? tr('settings.build.text.item43')
                                    : tr('settings.build.text.item44')),
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
                    title: tr('settings.build.title.item8'),
                    subtitle: tr('settings.build.description.item3'),
                    icon: Icons.terminal_rounded,
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Row(children: [
                            Expanded(
                              child: Tooltip(
                                message: _terminal.text.isEmpty ? tr('settings.build.text.item45') : _terminal.text,
                                child: InputDecorator(
                                  decoration: InputDecoration(labelText: tr('settings.build.text.item46')),
                                  child: Text(
                                    terminalDisplayName({'path': _terminal.text}),
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis)))),
                            const SizedBox(width: 12),
                            OutlinedButton.icon(
                                  onPressed: _pickTerminal,
                                  icon: const Icon(Icons.folder_open_outlined),
                                  label: const LText('settings.build.text.item47')),
                          ]),
                          const SizedBox(height: 16),
                          Row(children: [
                            Expanded(child: Text(_sshMessage,
                                style: Theme.of(context).textTheme.bodySmall)),
                            IconButton(
                                onPressed: _busy ? null : _refreshSshStatus,
                                tooltip: tr('settings.build.text.item48'),
                                icon: const Icon(Icons.refresh_rounded)),
                          ]),
                          Wrap(spacing: 10, runSpacing: 10, children: [
                            OutlinedButton(
                                onPressed: _sshConfigured == false && widget.onConfigureSsh != null
                                    ? () => _changeSshConfiguration(remove: false) : null,
                                child: const LText('settings.build.text.item49')),
                            OutlinedButton(
                                onPressed: _sshConfigured == true
                                    ? () => _changeSshConfiguration(remove: true) : null,
                                child: const LText('settings.build.text.item50')),
                          ]),
                        ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: tr('settings.build.title.item9'),
                    subtitle: tr('settings.build.description.item4'),
                    icon: Icons.language_rounded,
                    child: Column(children: [
                      TextFormField(
                        controller: _extensionId,
                        decoration: InputDecoration(
                            labelText: tr('browser.build.text.item9'),
                            helperText: tr('settings.build.text.item51'),
                            helperMaxLines: 3),
                        onChanged: (_) => setState(() => _dirty = true),
                        validator: (value) =>
                            (value ?? '').trim().isEmpty ||
                                    RegExp(r'^[a-p]{32}$')
                                        .hasMatch(value!.trim())
                                ? null
                                : tr('settings.build.text.item52'),
                      ),
                    ])),
                const SizedBox(height: 16),
                AppPanel(
                    title: tr('settings.build.title.item10'),
                    subtitle:
                        tr('settings.build.description.item5'),
                    icon: Icons.data_object_rounded,
                    child: SelectableText(_path,
                        style: Theme.of(context).textTheme.bodySmall)),
              ],
            )));
  }
}
