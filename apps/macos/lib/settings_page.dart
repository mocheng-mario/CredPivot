import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';
import 'terminal_settings.dart';
import 'touch_id_gate.dart';
import 'theme_color_picker.dart';
import 'ssh_git_ui.dart';

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
  final _search = TextEditingController();
  final _settingsScroll = ScrollController();
  final _sectionKeys = {for (final id in _sections.keys) id: GlobalKey()};
  String? _selectedSection;
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
    'git_ssh_auth_seconds',
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

  static const _accentPresets = {
    '#565DD9': 'theme.colors.indigo',
    '#2563EB': 'theme.colors.blue',
    '#0F766E': 'theme.colors.teal',
    '#15803D': 'theme.colors.green',
    '#B45309': 'theme.colors.amber',
    '#BE185D': 'theme.colors.rose',
  };

  // 只索引配置名称、说明和配置键，不把用户填写的值加入搜索。
  static const _sections = {
    'security': (title: 'settings.build.title.item2', icon: Icons.lock_outline_rounded, terms: [
      'settings.build.description', 'settings.security.autoUnlockOnWake', 'settings.security.autoUnlockOnWakeHelp',
      'settings.build.text.item6', 'settings.build.text.item7', 'settings.build.text.item8', 'settings.build.text.item9',
      'settings.build.text.item10', 'settings.build.text.item11', 'settings.build.text.item12', 'settings.build.text.item13',
      'settings.build.text.item14', 'settings.build.text.item15', 'settings.build.text.item16', 'settings.build.text.item17',
      'auto_unlock_on_wake', 'vault_idle_seconds', 'sensitive_auth_seconds', 'browser_idle_seconds',
      'clipboard_clear_seconds', 'master_password_days', 'master_password_idle_hours',
    ]),
    'ssh': (title: 'settings.build.title.item3', icon: Icons.security_outlined, terms: [
      'settings.build.text.item18', 'settings.build.text.item19', 'settings.build.text.item20',
      'settings.build.text.item21', 'settings.build.text.item22', 'ssh.git.authorization.reuseSetting',
      'ssh.git.authorization.reuseHelp', 'ssh_sign_policy', 'git_ssh_auth_seconds',
    ]),
    'general': (title: 'settings.build.title.item4', icon: Icons.tune_rounded, terms: [
      'settings.build.text.item23', 'settings.build.text.item24', 'settings.build.text.item25', 'settings.build.text.item26',
      'settings.theme.label', 'settings.theme.system', 'settings.theme.light', 'settings.theme.dark',
      'settings.language.label', 'settings.language.packActions', 'language.help', 'language.actions.import',
      'language.actions.exportTemplate', 'language.actions.exportCurrent', 'password_history_limit', 'password_reminder_days', 'theme', 'language',
    ]),
    'appearance': (title: 'theme.colors.title', icon: Icons.palette_outlined, terms: [
      'theme.colors.help', 'theme.colors.recommended', 'theme.colors.custom', 'theme.colors.openPicker', 'theme.colors.preview',
      'theme.colors.indigo', 'theme.colors.blue', 'theme.colors.teal', 'theme.colors.green', 'theme.colors.amber', 'theme.colors.rose', 'accent_color',
    ]),
    'recovery': (title: 'settings.build.title.item5', icon: Icons.history_rounded, terms: [
      'settings.build.text.item28', 'settings.build.text.item29', 'settings.build.text.item30', 'settings.build.text.item31',
      'restore_interval_hours', 'restore_keep_count',
    ]),
    'logs': (title: 'diagnostics.build.title', icon: Icons.article_outlined, terms: [
      'settings.build.description.item2', 'settings.build.text.item32', 'settings.build.text.item33',
      'settings.build.text.item34', 'settings.build.text.item35', 'settings.build.text.item36', 'settings.build.text.item37',
      'log_level', 'log_max_mb', 'log_backup_count', 'debug', 'info', 'warn', 'error',
    ]),
    'vault': (title: 'settings.build.title.item6', icon: Icons.folder_outlined, terms: [
      'settings.build.text.item38', 'settings.build.text.item39', 'vault_directory',
    ]),
    'startup': (title: 'settings.build.title.item7', icon: Icons.desktop_mac_outlined, terms: [
      'settings.build.text.item40', 'settings.build.text.item41', 'settings.build.text.item42',
      'settings.build.text.item43', 'settings.build.text.item44', 'launch_at_login',
    ]),
    'terminal': (title: 'settings.build.title.item8', icon: Icons.terminal_rounded, terms: [
      'settings.build.description.item3', 'settings.build.text.item46', 'settings.build.text.item47',
      'settings.ssh.identityAgent', 'settings.build.text.item49', 'settings.build.text.item50',
      'ssh.git.settings', 'ssh.git.integrationHelp', 'ssh.git.bindings', 'terminal_app_path', 'IdentityAgent',
    ]),
    'browser': (title: 'settings.build.title.item9', icon: Icons.language_rounded, terms: [
      'settings.build.description.item4', 'browser.build.text.item9', 'settings.build.text.item51', 'chrome_extension_id',
    ]),
    'config': (title: 'settings.build.title.item10', icon: Icons.data_object_rounded, terms: [
      'settings.build.description.item5', 'settings.json',
    ]),
  };

  bool _matchesSection(String id) {
    final query = _search.text.trim().toLowerCase();
    if (query.isEmpty) return true;
    final section = _sections[id]!;
    final text = [id, tr(section.title), for (final term in section.terms) ...[term, tr(term)]].join(' ').toLowerCase();
    return query.split(RegExp(r'\s+')).every(text.contains);
  }

  void _selectSection(String? id) {
    _search.clear();
    setState(() => _selectedSection = id);
    if (_settingsScroll.hasClients) _settingsScroll.jumpTo(0);
  }

  Widget _section(String id, Widget child) => Visibility(
    key: _sectionKeys[id],
    visible: (_selectedSection == null || _selectedSection == id) && _matchesSection(id),
    // 隐藏分区仍保留表单状态，避免切换导航后丢失输入或跳过保存校验。
    maintainState: true,
    child: Padding(padding: const EdgeInsets.only(bottom: 16), child: child),
  );

  Widget _navigation({required bool compact}) {
    if (compact) {
      return InputDecorator(decoration: InputDecoration(labelText: tr('settings.navigation.title')),
        child: DropdownButtonHideUnderline(child: DropdownButton<String>(
          value: _selectedSection ?? '', isExpanded: true, isDense: true,
          items: [DropdownMenuItem(value: '', child: LText('settings.navigation.all')),
            for (final entry in _sections.entries) DropdownMenuItem(value: entry.key, child: LText(entry.value.title))],
          onChanged: (value) { if (value != null) _selectSection(value.isEmpty ? null : value); },
        )));
    }
    return Card(child: ListView(padding: const EdgeInsets.all(8), children: [
      Padding(padding: const EdgeInsets.all(12), child: LText('settings.navigation.title', style: Theme.of(context).textTheme.titleSmall)),
      ListTile(dense: true, selected: _selectedSection == null, leading: const Icon(Icons.grid_view_rounded, size: 20),
        selectedTileColor: Theme.of(context).colorScheme.primaryContainer,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        title: const LText('settings.navigation.all'), onTap: () => _selectSection(null)),
      for (final entry in _sections.entries) ListTile(dense: true, selected: _selectedSection == entry.key,
        selectedTileColor: Theme.of(context).colorScheme.primaryContainer,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        leading: Icon(entry.value.icon, size: 20), title: LText(entry.value.title), onTap: () => _selectSection(entry.key)),
    ]));
  }

  Future<void> _pickAccentColor() async {
    final picked = await showThemeColorPicker(context,
        _draft['accent_color']?.toString() ?? AppPresentation.defaultAccentColor);
    if (!mounted || picked == null) return;
    setState(() {
      _draft['accent_color'] = picked;
      _dirty = true;
    });
  }

  Widget _themeColors() {
    final hex = _draft['accent_color']?.toString().toUpperCase() ?? AppPresentation.defaultAccentColor;
    final seed = Color(int.parse('FF${hex.substring(1)}', radix: 16));
    final scheme = ColorScheme.fromSeed(seedColor: seed,
        brightness: Theme.of(context).brightness);
    return AppPanel(
      title: tr('theme.colors.title'),
      subtitle: tr('theme.colors.help'),
      icon: Icons.palette_outlined,
      child: appFieldRows([
        AppFieldRow(label: tr('theme.colors.recommended'), child: Wrap(
          spacing: 10, runSpacing: 10,
          children: _accentPresets.entries.map((entry) {
            final color = Color(int.parse('FF${entry.key.substring(1)}', radix: 16));
            return Tooltip(message: entry.key, child: ChoiceChip(
              avatar: CircleAvatar(backgroundColor: color, radius: 9),
              label: LText(entry.value),
              selected: hex == entry.key,
              checkmarkColor: color.computeLuminance() > .5 ? Colors.black : Colors.white,
              onSelected: (_) => setState(() {
                _draft['accent_color'] = entry.key;
                _dirty = true;
              }),
            ));
          }).toList(),
        )),
        AppFieldRow(label: tr('theme.colors.custom'), child: Wrap(
          spacing: 12, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            OutlinedButton.icon(onPressed: _pickAccentColor,
                icon: const Icon(Icons.colorize_rounded),
                label: const LText('theme.colors.openPicker')),
            SelectableText(hex, style: Theme.of(context).textTheme.bodySmall),
          ],
        )),
        AppFieldRow(label: tr('theme.colors.preview'), child: Wrap(
          spacing: 12, runSpacing: 8,
          children: [
            Chip(label: const LText('theme.colors.primaryAction'),
                backgroundColor: scheme.primary,
                labelStyle: TextStyle(color: scheme.onPrimary), side: BorderSide.none),
            Chip(label: const LText('theme.colors.selectedItem'),
                avatar: Icon(Icons.check_rounded, size: 16, color: scheme.onPrimaryContainer),
                backgroundColor: scheme.primaryContainer,
                labelStyle: TextStyle(color: scheme.onPrimaryContainer), side: BorderSide.none),
          ],
        )),
      ]),
    );
  }

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
    _search.dispose();
    _settingsScroll.dispose();
    super.dispose();
  }

  void _populate(Map<String, dynamic> settings) {
    _draft = Map<String, dynamic>.from(settings);
    for (final key in _numericKeys) {
      final value = (settings[key] as num).toInt();
      _numbers[key]!.text =
          (key == 'vault_idle_seconds' || key == 'browser_idle_seconds' || key == 'git_ssh_auth_seconds'
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
    if (_busy || _form.currentState == null) return;
    final invalid = _form.currentState!.validateGranularly();
    if (invalid.isNotEmpty) {
      final field = invalid.first;
      String? section;
      field.context.visitAncestorElements((element) {
        for (final entry in _sectionKeys.entries) {
          if (element.widget.key == entry.value) { section = entry.key; return false; }
        }
        return true;
      });
      // 保存时也校验被搜索隐藏的配置，并展开错误所在分区，避免无提示地失败。
      _search.clear();
      setState(() { _selectedSection = section; _message = ''; });
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted && field.mounted) Scrollable.ensureVisible(field.context,
          alignment: .2, duration: const Duration(milliseconds: 200));
      });
      return;
    }
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
        next[key] = key == 'vault_idle_seconds' || key == 'browser_idle_seconds' || key == 'git_ssh_auth_seconds'
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
      AppFieldRow(label: label,
        help: hint,
        child: TextFormField(
          controller: _numbers[key],
          keyboardType: TextInputType.number,
          inputFormatters: [FilteringTextInputFormatter.digitsOnly],
          decoration: InputDecoration(
              hintText: tr('settings.number.text', args: {'min': min, 'max': max}),
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
    final actions = Wrap(
      spacing: 8,
      runSpacing: 8,
      children: [
        TextButton(onPressed: _reload, child: const LText('common.reload')),
        TextButton(onPressed: _restoreDefaults,
            child: const LText('common.restoreDefaults')),
        FilledButton.icon(
          onPressed: _dirty || _warning.isNotEmpty || _loginNeedsApply ? _save : null,
          icon: const Icon(Icons.check_rounded),
          label: LText(_saving ? tr('common.saving') : tr('settings.build.text.item5')),
        ),
      ],
    );
    final content = Scrollbar(controller: _settingsScroll, thumbVisibility: true,
      child: SingleChildScrollView(controller: _settingsScroll,
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        if (_warning.isNotEmpty) AppNotice(_warning),
        if (_message.isNotEmpty)
          AppNotice(_message,
              onDismiss: () => setState(() => _message = '')),
        if (_backupPath.isNotEmpty)
          AppPanel(
            title: tr('settings.build.title'),
            child: SelectableText(_backupPath)),
                _section('security', AppPanel(
                    title: tr('settings.build.title.item2'),
                    subtitle: tr('settings.build.description'),
                    icon: Icons.lock_outline_rounded,
                    child: appFieldRows([
                      AppFieldRow(label: tr('settings.security.autoUnlockOnWake'),
                        help: tr('settings.security.autoUnlockOnWakeHelp'),
                        child: Align(
                          alignment: Alignment.centerLeft,
                          child: Switch(
                            value: _draft['auto_unlock_on_wake'] == true,
                            onChanged: (value) => setState(() {
                              _draft['auto_unlock_on_wake'] = value;
                              _dirty = true;
                            }),
                          ),
                        ),
                      ),
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
                    ]))),
                _section('ssh', AppPanel(
                    title: tr('settings.build.title.item3'),
                    icon: Icons.security_outlined,
                    child: appFieldRows([
                      AppFieldRow(label: tr('settings.build.text.item18'),
                        help: tr('settings.build.text.item22'),
                        child: DropdownButtonFormField<String>(
                          value: _draft['ssh_sign_policy']?.toString() ?? 'session',
                          isExpanded: true,
                          items: const [
                            DropdownMenuItem(value: 'session', child: LText('settings.build.text.item19')),
                            DropdownMenuItem(value: 'confirm', child: LText('settings.build.text.item20')),
                            DropdownMenuItem(value: 'biometric', child: LText('settings.build.text.item21')),
                          ],
                          onChanged: (value) => setState(() {
                            _draft['ssh_sign_policy'] = value;
                            _dirty = true;
                          }),
                        ),
                      ),
                      _number('git_ssh_auth_seconds', tr('ssh.git.authorization.reuseSetting'),
                          tr('ssh.git.authorization.reuseHelp'), tr('common.units.minutes'), 0, 30),
                    ]))),
                _section('general', AppPanel(
                    title: tr('settings.build.title.item4'),
                    icon: Icons.tune_rounded,
                    child: appFieldRows([
                      _number('password_history_limit', tr('settings.build.text.item23'),
                          tr('settings.build.text.item24'), tr('common.units.items'), 0, 50),
                      _number('password_reminder_days', tr('settings.build.text.item25'),
                          tr('settings.build.text.item26'), tr('common.units.days'), 0, 3650),
                      AppFieldRow(label: tr('settings.theme.label'),
                        child: DropdownButtonFormField<String>(
                          value: _draft['theme']?.toString() ?? 'system',
                          isExpanded: true,
                          items: const [
                            DropdownMenuItem(value: 'system', child: LText('settings.theme.system')),
                            DropdownMenuItem(value: 'light', child: LText('settings.theme.light')),
                            DropdownMenuItem(value: 'dark', child: LText('settings.theme.dark')),
                          ],
                          onChanged: (value) => setState(() {
                            _draft['theme'] = value;
                            _dirty = true;
                          }),
                        ),
                      ),
                      AppFieldRow(label: tr('settings.language.label'),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            DropdownButtonFormField<String>(
                              key: ValueKey(_draft['language']),
                              value: AppPresentation.instance.names.containsKey(_draft['language'])
                                  ? _draft['language'].toString() : 'zh-CN',
                              isExpanded: true,
                              items: AppPresentation.instance.names.entries
                                  .map((entry) => DropdownMenuItem(value: entry.key, child: Text(entry.value)))
                                  .toList(),
                              onChanged: (value) => setState(() {
                                _draft['language'] = value;
                                _dirty = true;
                              }),
                            ),
                            const SizedBox(height: 8),
                            Text(AppPresentation.instance.coverage(_draft['language']?.toString() ?? 'zh-CN'),
                                style: Theme.of(context).textTheme.bodySmall),
                          ],
                        ),
                      ),
                      AppFieldRow(label: tr('settings.language.packActions'),
                        help: tr('language.help'),
                        child: Wrap(spacing: 8, runSpacing: 8, children: [
                          TextButton.icon(onPressed: _importLanguage,
                            icon: const Icon(Icons.file_upload_outlined), label: const LText('language.actions.import')),
                          TextButton.icon(onPressed: () => _exportLanguage(template: true),
                            icon: const Icon(Icons.translate), label: const LText('language.actions.exportTemplate')),
                          TextButton.icon(onPressed: () => _exportLanguage(template: false),
                            icon: const Icon(Icons.file_download_outlined), label: const LText('language.actions.exportCurrent')),
                        ]),
                      ),
                      for (final warning in AppPresentation.instance.loadWarnings) AppNotice(warning),
                    ]))),
                _section('appearance', _themeColors()),
                _section('recovery', AppPanel(
                    title: tr('settings.build.title.item5'),
                    icon: Icons.history_rounded,
                    child: appFieldRows([
                      _number('restore_interval_hours', tr('settings.build.text.item28'),
                          tr('settings.build.text.item29'), tr('common.units.hours'), 1, 24),
                      _number('restore_keep_count', tr('settings.build.text.item30'),
                          tr('settings.build.text.item31'), tr('common.units.copies'), 1, 100),
                    ]))),
                _section('logs', AppPanel(
                    title: tr('diagnostics.build.title'),
                    subtitle: tr('settings.build.description.item2'),
                    icon: Icons.article_outlined,
                    child: appFieldRows([
                      AppFieldRow(label: tr('settings.build.text.item32'),
                        help: tr('settings.build.text.item33'),
                        child: DropdownButtonFormField<String>(
                          key: ValueKey(_draft['log_level']),
                          value: _draft['log_level'] as String,
                          isExpanded: true,
                          items: ['debug', 'info', 'warn', 'error']
                              .map((level) => DropdownMenuItem(
                                  value: level, child: Text(level.toUpperCase())))
                              .toList(),
                          onChanged: (value) {
                            if (value != null) {
                              setState(() {
                                _draft['log_level'] = value;
                                _dirty = true;
                              });
                            }
                          },
                        ),
                      ),
                      _number('log_max_mb', tr('settings.build.text.item34'),
                          tr('settings.build.text.item35'), 'MB', 1, 100),
                      _number('log_backup_count', tr('settings.build.text.item36'),
                          tr('settings.build.text.item37'), tr('common.units.copies'), 1, 10),
                    ]))),
                _section('vault', AppPanel(
                    title: tr('settings.build.title.item6'),
                    icon: Icons.folder_outlined,
                    child: appFieldRows([
                      AppFieldRow(label: tr('settings.build.text.item38'),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            SelectableText(_vaultPath,
                                style: Theme.of(context).textTheme.bodySmall),
                            const SizedBox(height: 8),
                            Align(
                              alignment: Alignment.centerLeft,
                              child: TextButton.icon(
                                onPressed: _dirty ? null : () async {
                                  await widget.onOpenVault();
                                  if (mounted) await _load();
                                },
                                icon: const Icon(Icons.folder_open_outlined),
                                label: const LText('settings.build.text.item39'),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ]))),
                _section('startup', AppPanel(
                    title: tr('settings.build.title.item7'),
                    icon: Icons.desktop_mac_outlined,
                    child: appFieldRows([
                      AppFieldRow(label: tr('settings.build.text.item40'),
                        child: Row(children: [
                          Switch(
                            value: _draft['launch_at_login'] == true,
                            onChanged: _login['supported'] == true
                                ? (value) => setState(() {
                                      _draft['launch_at_login'] = value;
                                      _dirty = true;
                                    })
                                : null,
                          ),
                          const SizedBox(width: 12),
                          Expanded(child: LText(
                            _login['supported'] != true
                                ? 'settings.build.text.item41'
                                : _login['requires_approval'] == true
                                    ? 'settings.build.text.item42'
                                    : _login['enabled'] == true
                                        ? 'settings.build.text.item43'
                                        : 'settings.build.text.item44',
                            style: Theme.of(context).textTheme.bodySmall,
                          )),
                        ]),
                      ),
                    ]))),
                _section('terminal', AppPanel(
                    title: tr('settings.build.title.item8'),
                    subtitle: tr('settings.build.description.item3'),
                    icon: Icons.terminal_rounded,
                    child: appFieldRows([
                      AppFieldRow(label: tr('settings.build.text.item46'),
                        child: LayoutBuilder(builder: (context, constraints) {
                          final name = Tooltip(
                              message: _terminal.text.isEmpty ? tr('settings.build.text.item45') : _terminal.text,
                              child: InputDecorator(
                                decoration: const InputDecoration(),
                                child: Text(terminalDisplayName({'path': _terminal.text}),
                                    maxLines: 1, overflow: TextOverflow.ellipsis),
                              ),
                          );
                          final pick = OutlinedButton.icon(
                            onPressed: _pickTerminal,
                            icon: const Icon(Icons.folder_open_outlined),
                            label: const LText('settings.build.text.item47'));
                          if (constraints.maxWidth < 320) {
                            return Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [name, const SizedBox(height: 8), pick],
                            );
                          }
                          return Row(children: [Expanded(child: name), const SizedBox(width: 12), pick]);
                        }),
                      ),
                      AppFieldRow(label: tr('ssh.git.settings'), child: OutlinedButton.icon(
                        onPressed: _busy ? null : () => showGitSshSettings(context),
                        icon: const Icon(Icons.settings_ethernet), label: const LText('ssh.git.settings'))),
                      AppFieldRow(label: tr('settings.ssh.identityAgent'),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            Row(children: [
                              Expanded(child: Text(_sshMessage,
                                  style: Theme.of(context).textTheme.bodySmall)),
                              IconButton(
                                onPressed: _busy ? null : _refreshSshStatus,
                                tooltip: tr('settings.build.text.item48'),
                                icon: const Icon(Icons.refresh_rounded)),
                            ]),
                            const SizedBox(height: 8),
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
                          ],
                        ),
                      ),
                    ]))),
                _section('browser', AppPanel(
                    title: tr('settings.build.title.item9'),
                    subtitle: tr('settings.build.description.item4'),
                    icon: Icons.language_rounded,
                    child: appFieldRows([
                      AppFieldRow(label: tr('browser.build.text.item9'),
                        help: tr('settings.build.text.item51'),
                        child: TextFormField(
                          controller: _extensionId,
                          decoration: InputDecoration(
                              hintText: tr('settings.build.text.item51'), hintMaxLines: 2),
                          onChanged: (_) => setState(() => _dirty = true),
                          validator: (value) =>
                              (value ?? '').trim().isEmpty ||
                                      RegExp(r'^[a-p]{32}$').hasMatch(value!.trim())
                                  ? null : tr('settings.build.text.item52'),
                        ),
                      ),
                    ]))),
                _section('config', AppPanel(
                    title: tr('settings.build.title.item10'),
                    subtitle: tr('settings.build.description.item5'),
                    icon: Icons.data_object_rounded,
                    child: SelectableText(_path,
                        style: Theme.of(context).textTheme.bodySmall))),
        if (_search.text.trim().isNotEmpty && !_sections.keys.any(_matchesSection))
          AppPanel(title: 'settings.search.emptyTitle', subtitle: 'settings.search.emptyHelp',
            child: Align(alignment: Alignment.centerLeft, child: TextButton.icon(
              onPressed: () => _selectSection(null), icon: const Icon(Icons.clear_rounded),
              label: const LText('settings.search.clear')))),
      ])));
    return AbsorbPointer(absorbing: _busy, child: Form(key: _form,
      child: Padding(padding: const EdgeInsets.fromLTRB(24, 6, 24, 24), child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        LayoutBuilder(builder: (context, constraints) {
          final status = LText(
              _warning.isNotEmpty
                  ? tr('settings.build.text.item2')
                  : _dirty
                      ? tr('settings.build.text.item3')
                      : tr('settings.build.text.item4'),
              style: Theme.of(context).textTheme.bodySmall);
          if (constraints.maxWidth < 600) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [status, const SizedBox(height: 12), actions],
            );
          }
          return Row(children: [Expanded(child: status), actions]);
        }),
        if (_busy) const LinearProgressIndicator(),
        const SizedBox(height: 12),
        TextField(controller: _search, decoration: InputDecoration(
          hintText: tr('settings.search.hint'), prefixIcon: const Icon(Icons.search_rounded),
          suffixIcon: _search.text.isEmpty ? null : IconButton(
            tooltip: tr('settings.search.clear'), icon: const Icon(Icons.close_rounded),
            onPressed: () => _selectSection(null))),
          onChanged: (_) {
            setState(() => _selectedSection = null);
            if (_settingsScroll.hasClients) _settingsScroll.jumpTo(0);
          }),
        if (_search.text.trim().isNotEmpty) Padding(padding: const EdgeInsets.only(top: 8),
          child: LText('settings.search.results', args: {'count': _sections.keys.where(_matchesSection).length},
            style: Theme.of(context).textTheme.bodySmall)),
        const SizedBox(height: 12),
        Expanded(child: LayoutBuilder(builder: (context, constraints) {
          if (constraints.maxWidth >= 980) {
            return Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              SizedBox(width: 200, child: _navigation(compact: false)),
              const SizedBox(width: 16), Expanded(child: content),
            ]);
          }
          return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            _navigation(compact: true), const SizedBox(height: 12), Expanded(child: content),
          ]);
        })),
      ]))));
  }
}
