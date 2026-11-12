import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'credential_partitions.dart';
import 'credentials_page.dart';
import 'touch_id_gate.dart';
import 'vault_lock_coordinator.dart';
import 'webdav_sync.dart';
import 'theme_color_picker.dart';
import 'android_diagnostics.dart';
import 'vault_setup.dart';
import 'webdav_bootstrap.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try { await AppPresentation.instance.loadCatalog(); }
  catch (_) {
    runApp(const MaterialApp(home: Scaffold(body: Center(child: Text('语言资源加载失败，请重新安装 CredPivot。')))));
    return;
  }
  runApp(const CredPivotAndroidApp());
}

class CredPivotAndroidApp extends StatelessWidget {
  const CredPivotAndroidApp({super.key});
  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: AppPresentation.instance,
    builder: (context, _) => MaterialApp(
      navigatorKey: vaultRootNavigatorKey,
      title: 'CredPivot',
      theme: buildAppTheme(brightness: Brightness.light),
      darkTheme: buildAppTheme(brightness: Brightness.dark),
      themeMode: AppPresentation.instance.mode,
      home: const _AndroidHome(),
    ),
  );
}

class _AndroidHome extends StatefulWidget {
  const _AndroidHome();
  @override
  State<_AndroidHome> createState() => _AndroidHomeState();
}

class _AndroidHomeState extends State<_AndroidHome> {
  static const channel = MethodChannel('credpivot/agent');
  final password = TextEditingController();
  final partitions = CredentialPartitions.instance;
  Map<String, dynamic> status = {};
  String home = '', message = '';
  String transferTitle = '', transferStage = '';
  int page = 0, generation = 0;
  bool initializing = true, busy = false;
  Future<void>? statusRefresh;
  bool skippedSetup = false, openingRemote = false;
  bool get unlocked => status['unlocked'] == true;
  bool get exists => status['vault_exists'] == true;
  Timer? timer;

  @override
  void initState() {
    super.initState();
    partitions.start();
    installVaultLockCoordinator(_locked);
    AgentBridge.installVaultLockHandler(notifyVaultLocked);
    AgentBridge.onAppForeground = _foreground;
    WebDavSync.instance.start();
    WebDavSync.instance.onFailure = (text) async { if (mounted && unlocked) await _notice(tr('android.sync.failureTitle'), text); };
    timer = Timer.periodic(const Duration(seconds: 2), (_) { if (!initializing) refresh(); });
    initialize();
  }

  Future<void> initialize() async {
    setState(() { initializing = true; message = ''; });
    try {
      if (!await AgentBridge.ensureAgentReady()) throw StateError(tr('android.agent.startFailed'));
      // Agent 已驻留时 ensureAgentReady 不会再调用 startAgent，也必须恢复缺失的本机策略。
      await channel.invokeMethod<bool>('androidRestoreUnlockPolicy');
      final paths = await channel.invokeMapMethod<String, dynamic>('androidPaths') ?? {};
      home = paths['home'] as String;
      AppPresentation.instance.homeDirectory = home;
      await AppPresentation.instance.load();
      await refresh();
      if (mounted) {
        setState(() => initializing = false);
        if (exists && !unlocked) await _automaticUnlock();
      }
    } catch (error) {
      if (mounted) setState(() { initializing = false; message = error is AgentException ? error.message : tr('android.startup.failed'); });
    }
  }

  void _locked() {
    generation++;
    clearSensitiveAuthGrace();
    password.clear();
    partitions.setUnlocked(false);
    WebDavSync.instance.setUnlocked(false);
    if (mounted) setState(() { status = {...status, 'unlocked': false}; page = 0; });
    refresh();
  }

  Future<void> refresh() {
    if (!mounted) return Future<void>.value();
    // 启动/唤醒必须等到真实状态，不能因周期轮询正在执行就提前返回旧状态。
    return statusRefresh ??= _refreshStatus().whenComplete(() => statusRefresh = null);
  }

  Future<void> _refreshStatus() async {
    final epoch = generation;
    try {
      final next = AgentBridge.payloadOf(await AgentBridge.request({'type': 'status'}));
      if (!mounted || epoch != generation) return;
      if (unlocked && next['unlocked'] != true) notifyVaultLocked();
      setState(() => status = next);
      partitions.setUnlocked(unlocked);
      WebDavSync.instance.setUnlocked(unlocked && !openingRemote);
    } catch (_) { if (unlocked) notifyVaultLocked(); }
  }

  Future<void> _foreground() async {
    if (initializing || !mounted) return;
    try {
      await refresh();
      final settings = AgentBridge.payloadOf(await AgentBridge.request({'type': 'app_settings_get'}));
      if ((settings['settings'] as Map?)?['auto_unlock_on_wake'] == true) await _automaticUnlock();
    } catch (_) { if (unlocked) notifyVaultLocked(); }
  }

  Future<void> _automaticUnlock() async {
    if (busy || unlocked || status['local_unlock_configured'] != true || status['master_password_required'] != false) return;
    await _run(() async { await AgentBridge.unlockWithTouchId(); await refresh(); });
  }

  Future<void> _run(Future<void> Function() action) async {
    if (busy) return;
    setState(() { busy = true; message = ''; });
    try { await action(); }
    catch (error) {
      if (mounted) setState(() => message = error is AgentException ? tr(error.message) : error is PlatformException ? error.message ?? tr('common.operationFailed') : tr('android.operation.failed'));
    } finally { if (mounted) setState(() => busy = false); }
  }

  Future<void> _notice(String title, String text) => showDialog<void>(context: context, barrierDismissible: false,
    builder: (ctx) => AlertDialog(title: Text(title), content: SingleChildScrollView(child: SelectableText(text)),
      actions: [FilledButton(onPressed: () => Navigator.pop(ctx), child: const LText('sync.errors.acknowledge'))]));

  void _backupStage(String key) {
    if (mounted) setState(() => transferStage = key);
  }

  Future<void> _backupOperation(String title, Future<void> Function() action) async {
    // 从文件选择开始占用操作，防止重复点击打开多个选择器或恢复流程。
    if (busy || !mounted) return;
    setState(() { busy = true; message = ''; transferTitle = title; transferStage = 'android.backup.stage.prepare'; });
    try { await action(); }
    catch (error) {
      final detail = error is AgentException ? tr(error.message) : error is PlatformException
          ? error.message ?? tr('common.operationFailed') : tr('common.operationFailed');
      if (mounted) await _notice(tr('android.backup.failed'), tr('android.backup.failureDetail',
        args: {'operation': tr(title), 'stage': tr(transferStage), 'detail': detail}));
    } finally {
      if (mounted) setState(() { busy = false; transferTitle = ''; transferStage = ''; });
    }
  }

  Future<String?> _askPassword(String title, {bool confirm = false}) async {
    final first = TextEditingController(), second = TextEditingController();
    String? error;
    ModalRoute<String>? route;
    try {
      return await showDialog<String>(context: context, barrierDismissible: false, builder: (ctx) {
        route = ModalRoute.of<String>(ctx);
        return StatefulBuilder(
        builder: (ctx, update) => AlertDialog(title: Text(title), content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
          TextField(controller: first, obscureText: true, enableSuggestions: false, autocorrect: false, autofocus: true, enableIMEPersonalizedLearning: false,
            decoration: InputDecoration(hintText: tr('android.password.title'))),
          if (confirm) ...[const SizedBox(height: 16), TextField(controller: second, obscureText: true, enableSuggestions: false, autocorrect: false, enableIMEPersonalizedLearning: false,
            decoration: InputDecoration(hintText: tr('android.password.repeat')))],
          if (error != null) Text(error!, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
        ])), actions: [TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.cancel')),
          FilledButton(onPressed: () {
            if (first.text.isEmpty || (confirm && first.text != second.text)) { update(() => error = confirm ? tr('android.password.mismatch') : tr('android.password.required')); return; }
            Navigator.pop(ctx, first.text);
          }, child: const LText('common.continue'))],
      )); });
    } finally { await route?.completed; first.dispose(); second.dispose(); }
  }

  Future<void> _create() async {
    final secret = await _askPassword(tr('android.vault.create'), confirm: true);
    if (secret == null || !mounted) return;
    await _run(() async {
      final recovery = await AgentBridge.vaultCreate(secret);
      await refresh();
      if (mounted) await _notice(tr('android.vault.recoveryTitle'), tr('android.vault.recoveryBody', args: {'key': recovery}));
    });
  }

  Future<void> _openRemote() async {
    if (busy) return;
    WebDavBootstrapOutcome? outcome;
    setState(() { busy = true; openingRemote = true; message = ''; });
    try { outcome = await openWebDavBootstrap(context); }
    catch (problem) { if (mounted) setState(() => message = problem is AgentException ? tr(problem.message) : tr('common.operationFailed')); }
    finally {
      openingRemote = false;
      await refresh();
      if (mounted) setState(() => busy = false);
    }
    if (mounted && outcome == WebDavBootstrapOutcome.createNew) await _create();
  }

  Future<void> _restore() => _backupOperation('android.backup.restore', () async {
    _backupStage('android.backup.stage.chooseFile');
    final file = await AgentBridge.pickOpenFile();
    if (file == null) return;
    try {
      if (!mounted) return;
      _backupStage('android.backup.stage.password');
      final secret = await _askPassword(tr('android.vault.restorePassword'));
      if (secret == null || !mounted) return;
      if (unlocked) {
        _backupStage('android.backup.stage.authorize');
        if (!await requireTouchId(context, reason: tr('android.backup.restore')) || !mounted) return;
      }
      final target = '$home/.credpivot/restored-${DateTime.now().microsecondsSinceEpoch}-${Random.secure().nextInt(1 << 30)}';
      _backupStage('android.backup.stage.recover');
      await AgentBridge.vaultRecoverOvb(ovbPath: file, targetDir: target, password: secret);
      _backupStage('android.backup.stage.open');
      notifyVaultLocked();
      await AgentBridge.lockVault();
      await AgentBridge.vaultOpenDir(target);
      await AgentBridge.unlockWithPassword(secret);
      await refresh();
    } finally { if (await File(file).exists()) await File(file).delete(); }
    if (mounted) await _notice(tr('android.restore.done'), tr('android.restore.doneHelp'));
  });

  Future<void> _export() => _backupOperation('android.backup.exportReason', () async {
    _backupStage('android.backup.stage.password');
    final secret = await _askPassword(tr('android.backup.exportPassword'));
    if (secret == null || !mounted) return;
    _backupStage('android.backup.stage.authorize');
    if (!await requireTouchId(context, reason: tr('android.backup.exportReason')) || !mounted) return;
    final paths = await channel.invokeMapMethod<String, dynamic>('androidPaths') ?? {};
    final path = '${paths['cache']}/backup-${DateTime.now().microsecondsSinceEpoch}.ovb';
    String? saved;
    try {
      _backupStage('android.backup.stage.verify');
      await AgentBridge.request({'type': 'verify_master_password', 'password': secret});
      _backupStage('android.backup.stage.encrypt');
      await AgentBridge.vaultExportOvb(path, secret);
      _backupStage('android.backup.stage.save');
      saved = await channel.invokeMethod<String>('androidExportDocument', {'path': path, 'name': 'CredPivot-${DateTime.now().toIso8601String().split('T').first}.ovb'});
    } finally { if (await File(path).exists()) await File(path).delete(); }
    if (saved != null && mounted) await _notice(tr('android.backup.exportedTitle'), tr('android.backup.exportedBody'));
  });

  Future<void> _changePassword() async {
    final old = await _askPassword(tr('android.password.current'));
    if (old == null || !mounted) return;
    final next = await _askPassword(tr('android.password.new'), confirm: true);
    if (next == null || !mounted || !await requireTouchId(context, reason: tr('android.password.change')) || !mounted) return;
    await _run(() async {
      await AgentBridge.vaultChangePassword(old, next);
      await refresh();
      if (mounted) await _notice(tr('android.password.changed'), tr('android.password.changedHelp'));
    });
  }

  Future<void> _restorePoint() => _backupOperation('android.restore.points', () async {
    _backupStage('android.backup.stage.choosePoint');
    final points = await AgentBridge.listRestorePoints();
    if (!mounted) return;
    final selected = await showDialog<Map<String, dynamic>>(context: context, builder: (ctx) => SimpleDialog(
      title: const LText('android.restore.points'), children: points.isEmpty ? [Padding(padding: const EdgeInsets.all(24), child: const LText('android.restore.empty'))] : points.map((point) =>
        SimpleDialogOption(onPressed: () => Navigator.pop(ctx, point), child: Text(DateTime.fromMillisecondsSinceEpoch((point['created_at_ms'] as num).toInt()).toLocal().toString()))).toList()));
    if (selected == null || !mounted) return;
    final requiresBackupPassword = selected['requires_password'] == true;
    _backupStage('android.backup.stage.password');
    final secret = await _askPassword(tr(requiresBackupPassword ? 'android.vault.restorePassword' : 'android.password.current'));
    if (secret == null || !mounted) return;
    _backupStage('android.backup.stage.authorize');
    if (!await requireTouchId(context, reason: tr('android.restore.points')) || !mounted) return;
    if (!requiresBackupPassword) {
      // 同代际恢复保留当前主密码槽；必须先验证，不能切换活动库后才发现密码错误。
      _backupStage('android.backup.stage.verify');
      await AgentBridge.request({'type': 'verify_master_password', 'password': secret});
    }
    final target = '$home/.credpivot/restored-${DateTime.now().microsecondsSinceEpoch}-${Random.secure().nextInt(1 << 30)}';
    _backupStage('android.backup.stage.recover');
    // 跨代际副本的密码由恢复接口校验，校验成功后才会继续切换。
    await AgentBridge.recoverRestorePoint((selected['created_at_ms'] as num).toInt(), target,
      password: requiresBackupPassword ? secret : null);
    _backupStage('android.backup.stage.open');
    notifyVaultLocked();
    await AgentBridge.lockVault();
    await AgentBridge.vaultOpenDir(target);
    await AgentBridge.unlockWithPassword(secret);
    await refresh();
    if (mounted) await _notice(tr('android.restore.done'), tr('android.restore.doneHelp'));
  });

  Future<void> _hostName() async {
    final info = await AgentBridge.syncHostInfo();
    if (!mounted) return;
    final controller = TextEditingController(text: info['sync_host_name_override']?.toString() ?? '');
    ModalRoute<String>? route;
    String? value;
    try {
      value = await showDialog<String>(context: context, builder: (ctx) {
        route = ModalRoute.of<String>(ctx);
        return AlertDialog(title: const LText('android.sync.hostName'), content: TextField(controller: controller, maxLength: 128,
          decoration: InputDecoration(hintText: info['computer_name']?.toString() ?? ''), autofocus: true),
          actions: [TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.cancel')),
            FilledButton(onPressed: () => Navigator.pop(ctx, controller.text.trim()), child: const LText('common.save'))]);
      });
    } finally { await route?.completed; controller.dispose(); }
    if (value == null || !mounted || !await requireTouchId(context, reason: tr('android.sync.hostName')) || !mounted) return;
    await _run(() async { await AgentBridge.setSyncHostName(value!); if (mounted) setState(() {}); });
  }

  @override
  void dispose() {
    timer?.cancel(); password.dispose();
    partitions.stop(); WebDavSync.instance.stop(); WebDavSync.instance.onFailure = null;
    AgentBridge.onAppForeground = null;
    installVaultLockCoordinator(() {});
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => PopScope(canPop: transferTitle.isEmpty, child: Scaffold(
    appBar: AppBar(
      title: unlocked && page == 0
          ? ListenableBuilder(listenable: partitions, builder: (context, _) => DropdownButtonHideUnderline(
              child: DropdownButton<String>(
                isExpanded: true,
                value: partitions.items.any((p) => p['id'] == AgentBridge.activePartitionId) ? AgentBridge.activePartitionId : null,
                hint: const LText('android.partitions.select'),
                items: partitions.items.map((p) => DropdownMenuItem(
                  value: p['id'].toString(),
                  child: Text(p['name'].toString(), maxLines: 1, overflow: TextOverflow.ellipsis),
                )).toList(),
                onChanged: busy ? null : (value) { if (value != null) setState(() { AgentBridge.activePartitionId = value; }); },
              )))
          : const Text('CredPivot'),
      actions: [
      if (unlocked && page == 0) IconButton(
        tooltip: tr('android.partitions.manage'),
        icon: const Icon(Icons.folder_outlined),
        onPressed: busy ? null : () => Navigator.push(context, MaterialPageRoute<void>(builder: (_) => Scaffold(
          appBar: AppBar(title: const LText('android.partitions.manage')),
          body: const SafeArea(child: PartitionManagementPage()),
        )))),
      if (unlocked) IconButton(tooltip: tr('android.vault.lock'), icon: const Icon(Icons.lock_outline), onPressed: busy ? null : () async {
        notifyVaultLocked(); await AgentBridge.lockVault();
      }),
    ]),
    body: Stack(children: [Positioned.fill(child: SafeArea(child: initializing ? const Center(child: CircularProgressIndicator()) : !exists ?
      (skippedSetup ? UnconfiguredVaultPage(onSetup: () => setState(() => skippedSetup = false)) : Column(children: [
        if (message.isNotEmpty) Padding(padding: const EdgeInsets.all(16), child: AppNotice(message)),
        Expanded(child: VaultSetupChoices(busy: busy, onCreate: _create, onWebDav: _openRemote, onRestore: _restore,
          onSkip: () => setState(() => skippedSetup = true))),
      ])) : !unlocked ? _unlockView() : Column(children: [
      if (message.isNotEmpty) Padding(padding: const EdgeInsets.symmetric(horizontal: 16), child: AppNotice(message)),
      Expanded(child: switch (page) {
        0 => CredentialsTab(key: ValueKey(AgentBridge.activePartitionId), unlocked: true, mobile: true),
        1 => const WebDavSyncPage(),
        2 => _backupView(),
        _ => const _AndroidSettings(),
      }),
    ]))),
      if (transferTitle.isNotEmpty) ...[
        const Positioned.fill(child: ModalBarrier(dismissible: false, color: Colors.black38)),
        Positioned.fill(child: Center(child: Padding(padding: const EdgeInsets.all(24), child: Card(
          child: Padding(padding: const EdgeInsets.all(24), child: Column(mainAxisSize: MainAxisSize.min, children: [
            const CircularProgressIndicator(), const SizedBox(height: 20),
            LText(transferTitle, style: Theme.of(context).textTheme.titleMedium, textAlign: TextAlign.center),
            const SizedBox(height: 12), LText(transferStage, textAlign: TextAlign.center),
          ])),
        )))),
      ],
    ]),
    bottomNavigationBar: unlocked ? NavigationBar(height: 64, selectedIndex: page, onDestinationSelected: busy ? null : (value) => setState(() => page = value),
      destinations: [NavigationDestination(icon: const Icon(Icons.key_outlined), label: tr('android.navigation.credentials')),
        NavigationDestination(icon: const Icon(Icons.sync), label: tr('android.navigation.sync')),
        NavigationDestination(icon: const Icon(Icons.inventory_2_outlined), label: tr('android.navigation.vault')),
        NavigationDestination(icon: const Icon(Icons.settings_outlined), label: tr('android.navigation.settings'))]) : null,
  ));

  Widget _unlockView() => Center(child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 480),
    child: ListView(shrinkWrap: true, padding: const EdgeInsets.all(24), children: [
      const Icon(Icons.shield_outlined, size: 64), const SizedBox(height: 24),
      Text(exists ? tr('android.vault.unlock') : tr('android.vault.welcome'), style: Theme.of(context).textTheme.headlineSmall, textAlign: TextAlign.center),
      const SizedBox(height: 16),
      if (message.isNotEmpty) AppNotice(message),
      if (status['local_unlock_reason'] is String)
        Padding(padding: const EdgeInsets.only(bottom: 16), child: AppNotice(tr(
          const {'not_configured': 'android.unlock.reason.notConfigured', 'policy_missing': 'android.unlock.reason.policyMissing',
            'policy_mismatch': 'android.unlock.reason.policyMismatch', 'policy_unavailable': 'android.unlock.reason.policyUnavailable',
            'policy_save_failed': 'android.unlock.reason.policySaveFailed', 'key_unavailable': 'android.unlock.reason.keyUnavailable',
            'clock_changed': 'android.unlock.reason.clockChanged', 'master_period': 'android.unlock.reason.masterPeriod',
            'unlock_idle': 'android.unlock.reason.unlockIdle'}[status['local_unlock_reason']] ?? 'android.unlock.reason.policyUnavailable'))),
      if (exists) ...[
        TextField(controller: password, obscureText: true, enableSuggestions: false, autocorrect: false,
          enabled: !busy, decoration: InputDecoration(hintText: tr('android.password.title')),
          onSubmitted: (_) => _unlockPassword()),
        const SizedBox(height: 16),
        FilledButton(onPressed: busy ? null : _unlockPassword, child: const LText('android.unlock.password')),
        if (status['local_unlock_configured'] == true && status['master_password_required'] == false)
          OutlinedButton.icon(onPressed: busy ? null : _automaticUnlock, icon: const Icon(Icons.fingerprint), label: const LText('android.unlock.biometric')),
      ] else FilledButton(onPressed: busy ? null : _create, child: const LText('android.vault.create')),
      TextButton(onPressed: busy ? null : _restore, child: const LText('android.unlock.restore')),
      if (home.isEmpty) TextButton(onPressed: busy ? null : initialize, child: const LText('android.startup.retry')),
      if (busy) const Center(child: Padding(padding: EdgeInsets.all(12), child: CircularProgressIndicator())),
    ])));

  Future<void> _unlockPassword() => _run(() async {
    final value = password.text; password.clear();
    await AgentBridge.unlockWithPassword(value); await refresh();
  });

  Widget _backupView() => ListView(padding: const EdgeInsets.all(20), children: [
    AppPanel(title: tr('android.backup.title'), icon: Icons.inventory_2_outlined,
      subtitle: tr('android.backup.description'), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        FilledButton.icon(onPressed: busy ? null : _export, icon: const Icon(Icons.file_download_outlined), label: const LText('android.backup.exportReason')),
        const SizedBox(height: 12), OutlinedButton.icon(onPressed: busy ? null : _restore, icon: const Icon(Icons.restore), label: const LText('android.backup.restore')),
        const SizedBox(height: 12), OutlinedButton.icon(onPressed: busy ? null : _restorePoint, icon: const Icon(Icons.history), label: const LText('android.restore.points')),
        const SizedBox(height: 12), OutlinedButton.icon(onPressed: busy ? null : _changePassword, icon: const Icon(Icons.password), label: const LText('android.password.change')),
      ])),
    const SizedBox(height: 16), AppPanel(title: tr('android.sync.hostName'), icon: Icons.phone_android, child: FutureBuilder<Map<String, dynamic>>(
      future: AgentBridge.syncHostInfo(), builder: (context, snapshot) => ListTile(contentPadding: EdgeInsets.zero,
        title: Text(snapshot.data?['sync_host_name']?.toString() ?? ''), trailing: IconButton(onPressed: busy ? null : _hostName, icon: const Icon(Icons.edit_outlined))))),
  ]);
}

class _AndroidSettings extends StatefulWidget {
  const _AndroidSettings();
  @override
  State<_AndroidSettings> createState() => _AndroidSettingsState();
}

class _AndroidSettingsState extends State<_AndroidSettings> with WidgetsBindingObserver {
  static const channel = MethodChannel('credpivot/agent');
  Map<String, dynamic> settings = {};
  Map<String, dynamic> defaults = {};
  bool busy = false, biometric = false;
  bool changingBiometric = false;
  String biometricMessage = '';
  String message = '';
  final controllers = <String, TextEditingController>{};
  final search = TextEditingController();
  String section = 'all', query = '';
  bool? autofillEnabled, passkeyEnabled;
  bool passkeySupported = false, refreshingIntegration = false;
  static const sections = {
    'all': 'android.settings.category.all',
    'integration': 'android.settings.category.integration',
    'appearance': 'android.settings.appearance',
    'security': 'android.settings.security',
    'backup': 'android.settings.category.backup',
    'passwords': 'android.settings.category.passwords',
    'diagnostics': 'android.diagnostics.title',
    'reset': 'localReset.section',
  };
  static const fieldSections = {
    'vault_idle_seconds': 'security', 'sensitive_auth_seconds': 'security',
    'clipboard_clear_seconds': 'security', 'master_password_days': 'security',
    'master_password_idle_hours': 'security', 'restore_interval_hours': 'backup',
    'restore_keep_count': 'backup', 'password_history_limit': 'passwords',
    'password_reminder_days': 'passwords', 'log_max_mb': 'diagnostics', 'log_backup_count': 'diagnostics',
  };
  static const fields = {
    'vault_idle_seconds': 'android.settings.vaultIdle',
    'sensitive_auth_seconds': 'android.settings.sensitiveReuse',
    'clipboard_clear_seconds': 'android.settings.clipboardClear',
    'master_password_days': 'android.settings.masterPeriod',
    'master_password_idle_hours': 'android.settings.masterIdle',
    'restore_interval_hours': 'android.settings.restoreInterval',
    'restore_keep_count': 'android.settings.restoreCount',
    'password_history_limit': 'android.settings.passwordHistory',
    'password_reminder_days': 'android.settings.passwordReminder',
    'log_max_mb': 'android.settings.logSize',
    'log_backup_count': 'android.settings.logCount',
  };
  static const limits = {
    'vault_idle_seconds': (60, 1800), 'sensitive_auth_seconds': (0, 300),
    'clipboard_clear_seconds': (5, 300), 'master_password_days': (1, 7),
    'master_password_idle_hours': (1, 24), 'restore_interval_hours': (1, 24),
    'restore_keep_count': (1, 100), 'password_history_limit': (0, 50),
    'password_reminder_days': (0, 3650), 'log_max_mb': (1, 100), 'log_backup_count': (1, 10),
  };
  @override
  void initState() { super.initState(); WidgetsBinding.instance.addObserver(this); load(); }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) refreshIntegrationStatus();
  }

  Future<void> refreshIntegrationStatus() async {
    if (refreshingIntegration) return;
    refreshingIntegration = true;
    try {
      final autofill = await channel.invokeMethod<bool>('androidAutofillStatus').catchError((Object _) => null);
      final supported = await channel.invokeMethod<bool>('androidPasskeySupported').catchError((Object _) => false) ?? false;
      final provider = supported ? await channel.invokeMethod<bool>('androidPasskeyStatus').catchError((Object _) => null) : null;
      if (mounted) setState(() { autofillEnabled = autofill; passkeySupported = supported; passkeyEnabled = provider; });
    } finally { refreshingIntegration = false; }
  }

  Future<void> configureIntegration(String method, String helpKey) async {
    if (busy) return;
    setState(() { busy = true; message = ''; });
    try {
      final outcome = await channel.invokeMethod<String>(method);
      if (!mounted || outcome != 'manual') return;
      // 直达不可用或已启用时给出明确引导，不把“打开设置”当成启用成功。
      final open = await showDialog<bool>(context: context, builder: (ctx) => AlertDialog(
        title: const LText('android.integration.manualTitle'),
        content: SingleChildScrollView(child: LText(helpKey)),
        actions: [TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('common.cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const LText('android.integration.openSettings'))]));
      if (open == true && mounted) await channel.invokeMethod<void>('androidSystemSettings');
    } catch (error) {
      if (mounted) setState(() => message = error is PlatformException ? error.message ?? tr('common.operationFailed') : tr('common.operationFailed'));
    } finally { if (mounted) setState(() => busy = false); }
  }

  Future<void> load() async {
    try {
      final result = await AgentBridge.fetchAppSettings();
      final paths = await channel.invokeMapMethod<String, dynamic>('androidPaths') ?? {};
      await refreshIntegrationStatus();
      if (!mounted) return;
      setState(() {
        settings = Map<String, dynamic>.from(result['settings'] as Map); biometric = paths['biometric'] == true;
        defaults = Map<String, dynamic>.from(result['defaults'] as Map);
        for (final key in fields.keys) { controllers[key] ??= TextEditingController(); controllers[key]!.text = settings[key].toString(); }
      });
    } catch (_) { if (mounted) setState(() => message = tr('android.settings.loadFailed')); }
  }
  Future<void> save() async {
    for (final entry in limits.entries) {
      final value = int.tryParse(controllers[entry.key]?.text ?? '');
      if (value == null || value < entry.value.$1 || value > entry.value.$2 || (entry.key == 'vault_idle_seconds' && value % 60 != 0)) {
        setState(() {
          section = fieldSections[entry.key]!; query = ''; search.clear();
          message = tr('android.settings.range', args: {'field': tr(fields[entry.key]!), 'minimum': entry.value.$1, 'maximum': entry.value.$2});
        }); return;
      }
    }
    if (busy || !await requireTouchId(context, reason: tr('android.settings.saveReason')) || !mounted) return;
    setState(() { busy = true; message = ''; });
    try {
      final next = {...settings};
      for (final key in fields.keys) { next[key] = int.parse(controllers[key]!.text); }
      final response = await AgentBridge.saveAppSettings(next);
      AppPresentation.instance.apply(Map<String, dynamic>.from(response['settings'] as Map));
      if (mounted) setState(() => message = tr('android.settings.saved'));
    } catch (error) {
      if (mounted) setState(() => message = error is AgentException ? error.message : tr('android.settings.invalid'));
    } finally { if (mounted) setState(() => busy = false); }
  }
  Future<void> toggleBiometric() async {
    if (busy) return;
    final enable = !biometric;
    setState(() { busy = true; message = ''; biometricMessage = ''; });
    try {
      ModalRoute<bool>? confirmationRoute;
      final accepted = await showDialog<bool>(context: context, builder: (ctx) {
        confirmationRoute = ModalRoute.of<bool>(ctx);
        return AlertDialog(title: LText(enable ? 'android.biometric.setup.enableTitle' : 'android.biometric.setup.disableTitle'),
          content: SingleChildScrollView(child: LText(enable ? 'android.biometric.setup.enableConfirm' : 'android.biometric.setup.disableConfirm')),
          actions: [TextButton(onPressed: () => Navigator.pop(ctx, false), child: const LText('common.cancel')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const LText('android.biometric.setup.continue'))]);
      });
      await confirmationRoute?.completed;
      if (!mounted) return;
      if (accepted != true) { setState(() => biometricMessage = tr('android.biometric.setup.cancelled')); return; }
      setState(() => changingBiometric = true);
      if (enable) {
        // 录入本身必须经过系统生物识别；不再先调用一遍通用指纹验证。
        bool enabled;
        try { enabled = await channel.invokeMethod<bool>('enableBiometric') == true; }
        on PlatformException catch (error) {
          if (error.code != 'biometric_retry' || !mounted) rethrow;
          // 原生已验证主密码后，继续同一次设置；取消不会返回此错误，不能自动重弹。
          enabled = await channel.invokeMethod<bool>('enableBiometric') == true;
        }
        if (!mounted) return;
        if (!enabled) { setState(() => biometricMessage = tr('android.biometric.setup.cancelled')); return; }
      } else {
        if (!await requireTouchId(context, reason: tr('android.biometric.disable'), confirmed: true) || !mounted) {
          if (mounted) setState(() => biometricMessage = tr('android.biometric.setup.cancelled'));
          return;
        }
        await channel.invokeMethod<void>('disableBiometric');
      }
      final paths = await channel.invokeMapMethod<String, dynamic>('androidPaths') ?? {};
      if (mounted) setState(() {
        biometric = paths['biometric'] == true;
        biometricMessage = tr(biometric != enable ? 'android.biometric.failed' : enable
          ? 'android.biometric.setup.enabled' : 'android.biometric.setup.disabled');
      });
    } on PlatformException catch (error) {
      if (mounted) setState(() => biometricMessage = error.code == 'biometric_unavailable'
          ? tr('android.biometric.setup.unavailable') : error.message ?? tr('android.biometric.failed'));
    } finally { if (mounted) setState(() { busy = false; changingBiometric = false; }); }
  }
  @override
  void dispose() { WidgetsBinding.instance.removeObserver(this); search.dispose(); for (final controller in controllers.values) { controller.dispose(); } super.dispose(); }

  bool matches(String category, Iterable<String> keys) => (section == 'all' || section == category) &&
    (query.isEmpty || [sections[category]!, ...keys].any((key) => tr(key).toLowerCase().contains(query) || key.toLowerCase().contains(query)));

  List<Widget> numericFields(String category) => [
    for (final field in fields.entries)
      if (fieldSections[field.key] == category && matches(category, [field.value]))
        AppFieldRow(label: tr(field.value), child: TextField(controller: controllers[field.key], enabled: !busy,
          keyboardType: TextInputType.number, inputFormatters: [FilteringTextInputFormatter.digitsOnly],
          decoration: InputDecoration(hintText: '${limits[field.key]!.$1}–${limits[field.key]!.$2}',
            helperText: field.key == 'vault_idle_seconds' ? tr('android.settings.minuteStep') : null))),
  ];

  Future<void> resetLocal(String scope) async {
    if (busy) return;
    setState(() { busy = true; message = ''; });
    try {
      final notice = await AgentBridge.runLocalReset(context, scope);
      if (mounted && notice != null) setState(() => message = notice);
    } catch (error) {
      if (mounted) setState(() => message = error is AgentException ? error.message : tr('localReset.failed'));
    } finally { if (mounted) setState(() => busy = false); }
  }

  Future<void> resetDefaults() async {
    if (busy || !await requireTouchId(context, reason: tr('android.settings.reset')) || !mounted) return;
    setState(() { busy = true; message = ''; });
    try {
      final backup = AgentBridge.payloadOf(await AgentBridge.request({'type': 'app_settings_backup'}));
      final next = {...settings};
      // 只恢复本页配置，不改变保险库位置、WebDAV 接入或设备名称。
      for (final key in [...fields.keys, 'theme', 'language', 'accent_color', 'auto_unlock_on_wake']) { next[key] = defaults[key]; }
      final response = await AgentBridge.saveAppSettings(next);
      final saved = Map<String, dynamic>.from(response['settings'] as Map);
      AppPresentation.instance.apply(saved);
      if (mounted) setState(() {
        settings = saved;
        for (final key in fields.keys) { controllers[key]!.text = saved[key].toString(); }
      });
      if (mounted) await showDialog<void>(context: context, builder: (ctx) => AlertDialog(title: const LText('android.settings.resetDone'),
        content: SelectableText(tr('android.settings.backupPath', args: {'path': backup['path'] ?? tr('android.settings.noPreviousFile')})),
        actions: [FilledButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.close'))]));
    } catch (_) { if (mounted) setState(() => message = tr('android.settings.resetFailed')); }
    finally { if (mounted) setState(() => busy = false); }
  }
  @override
  Widget build(BuildContext context) {
    if (settings.isEmpty) return Center(child: message.isEmpty ? const CircularProgressIndicator() :
      Column(mainAxisSize: MainAxisSize.min, children: [AppNotice(message), TextButton(onPressed: load, child: const LText('android.startup.retry'))]));
    final panels = <Widget>[
      if (matches('integration', ['android.autofill.title', 'android.autofill.help', 'android.passkey.title']))
      AppPanel(title: tr('android.autofill.title'), icon: Icons.password_outlined,
        subtitle: tr('android.autofill.help'), child: appFieldRows([
          AppFieldRow(label: tr('android.autofill.status'), child: Row(children: [Expanded(child: LText(autofillEnabled == null
              ? 'android.integration.statusUnknown' : autofillEnabled! ? 'android.autofill.enabled' : 'android.autofill.disabled')),
            IconButton(tooltip: tr('android.autofill.refresh'), onPressed: busy ? null : refreshIntegrationStatus, icon: const Icon(Icons.refresh))])),
          FilledButton(onPressed: busy ? null : () => configureIntegration('androidAutofillEnable', 'android.integration.autofillManual'),
            child: const LText('android.autofill.configure')),
          AppFieldRow(label: tr('android.passkey.title'), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            LText(passkeySupported ? 'android.passkey.help' : 'android.passkey.unsupported'),
            if (passkeySupported) ...[
              const SizedBox(height: 12), LText('android.integration.providerStatus', args: {'status': tr(passkeyEnabled == null
                ? 'android.integration.statusUnknown' : passkeyEnabled! ? 'android.autofill.enabled' : 'android.autofill.disabled')}),
              TextButton(onPressed: busy ? null : () => configureIntegration('androidPasskeyEnable', 'android.integration.providerManual'),
                child: const LText('android.passkey.configure')),
            ],
          ])),
        ])),
      if (matches('appearance', ['android.settings.theme', 'android.settings.language', 'theme.colors.title', 'android.language.import', 'android.language.export']))
      AppPanel(title: tr('android.settings.appearance'), icon: Icons.palette_outlined, child: Column(children: [
        AppFieldRow(label: tr('android.settings.theme'), child: DropdownButtonFormField<String>(initialValue: settings['theme'] as String,
          items: const [DropdownMenuItem(value: 'system', child: LText('android.theme.system')), DropdownMenuItem(value: 'light', child: LText('android.theme.light')), DropdownMenuItem(value: 'dark', child: LText('android.theme.dark'))],
          onChanged: busy ? null : (value) { if (value != null) setState(() => settings['theme'] = value); })),
        AppFieldRow(label: tr('android.settings.language'), child: DropdownButtonFormField<String>(initialValue: settings['language'] as String,
          items: AppPresentation.instance.names.entries.map((entry) => DropdownMenuItem(value: entry.key, child: Text(entry.value))).toList(),
          onChanged: busy ? null : (value) { if (value != null) setState(() => settings['language'] = value); })),
        AppFieldRow(label: tr('theme.colors.title'), child: Wrap(spacing: 8, runSpacing: 8, children: [
          for (final hex in ['#565DD9', '#2563EB', '#0F766E', '#15803D', '#B45309', '#BE185D'])
            ChoiceChip(label: Text(hex), avatar: CircleAvatar(radius: 8, backgroundColor: Color(int.parse('FF${hex.substring(1)}', radix: 16))),
              selected: settings['accent_color'] == hex, onSelected: busy ? null : (_) => setState(() => settings['accent_color'] = hex)),
          OutlinedButton.icon(onPressed: busy ? null : () async {
            final color = await showThemeColorPicker(context, settings['accent_color']?.toString() ?? AppPresentation.defaultAccentColor);
            if (mounted && color != null) setState(() => settings['accent_color'] = color);
          }, icon: const Icon(Icons.colorize), label: const LText('theme.colors.openPicker')),
        ])),
        Wrap(spacing: 8, runSpacing: 8, children: [
          TextButton(onPressed: busy ? null : () async {
            try {
              final imported = await AppPresentation.instance.importPack();
              if (mounted && imported != null) setState(() {
                settings['language'] = imported.locale;
                if (imported.skipped > 0) message = tr('language.status.skippedKeys', args: {'count': imported.skipped});
              });
            } catch (error) { if (mounted) setState(() => message = AppPresentation.instance.errorMessage(error)); }
          }, child: const LText('android.language.import')),
          TextButton(onPressed: busy ? null : () async {
            try { await AppPresentation.instance.exportTemplate(); }
            catch (_) { if (mounted) setState(() => message = tr('android.language.exportFailed')); }
          }, child: const LText('android.language.export')),
        ]),
      ])),
      if (matches('security', ['android.settings.wakeAuth', 'android.unlock.biometric', 'android.biometric.setup.title', 'android.settings.backgroundLock',
        for (final entry in fields.entries) if (fieldSections[entry.key] == 'security') entry.value]))
      AppPanel(title: tr('android.settings.security'), icon: Icons.security_outlined, child: Column(children: [
        if (matches('security', ['android.unlock.biometric', 'android.biometric.setup.title']))
        AppFieldRow(label: tr('android.biometric.setup.title'), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Align(alignment: Alignment.centerLeft, child: Chip(avatar: Icon(biometric ? Icons.fingerprint : Icons.lock_outline, size: 18),
            label: LText(biometric ? 'android.autofill.enabled' : 'android.autofill.disabled'))),
          const SizedBox(height: 8), LText(biometric ? 'android.biometric.setup.enabledHelp' : 'android.biometric.setup.disabledHelp'),
          const SizedBox(height: 12),
          if (changingBiometric) ...[
            const LinearProgressIndicator(), const SizedBox(height: 8), const LText('android.biometric.setup.verifying'),
          ] else if (biometric)
            OutlinedButton.icon(onPressed: busy ? null : toggleBiometric, icon: const Icon(Icons.fingerprint), label: const LText('android.biometric.setup.disableAction'))
          else FilledButton.icon(onPressed: busy ? null : toggleBiometric, icon: const Icon(Icons.fingerprint), label: const LText('android.biometric.setup.enableAction')),
          if (biometricMessage.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 12), child: AppNotice(biometricMessage)),
        ])),
        if (matches('security', ['android.settings.wakeAuth']))
        SwitchListTile(contentPadding: EdgeInsets.zero, title: const LText('android.settings.wakeAuth'),
          subtitle: const LText('android.biometric.setup.wakeHelp'), value: settings['auto_unlock_on_wake'] == true,
          onChanged: busy ? null : (value) => setState(() => settings['auto_unlock_on_wake'] = value)),
        ...numericFields('security'),
        if (matches('security', ['android.settings.backgroundLock']))
        const LText('android.settings.backgroundLock'),
      ])),
      if (matches('backup', [for (final entry in fields.entries) if (fieldSections[entry.key] == 'backup') entry.value]))
        AppPanel(title: tr('android.settings.category.backup'), icon: Icons.inventory_2_outlined,
          child: Column(children: numericFields('backup'))),
      if (matches('passwords', [for (final entry in fields.entries) if (fieldSections[entry.key] == 'passwords') entry.value]))
        AppPanel(title: tr('android.settings.category.passwords'), icon: Icons.password,
          child: Column(children: numericFields('passwords'))),
      if (matches('diagnostics', ['android.diagnostics.title', 'android.settings.logSize', 'android.settings.logCount']))
        AppPanel(title: tr('android.diagnostics.title'), icon: Icons.receipt_long, child: Column(children: [
          ...numericFields('diagnostics'),
          OutlinedButton.icon(onPressed: busy ? null : () => Navigator.push(context,
            MaterialPageRoute<void>(builder: (_) => const AndroidDiagnosticsPage())), icon: const Icon(Icons.receipt_long), label: const LText('android.diagnostics.title')),
        ])),
      if (matches('reset', ['localReset.vault.title', 'localReset.app.title', 'localReset.section']))
        AppPanel(title: tr('localReset.section'), icon: Icons.restart_alt, child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            OutlinedButton(onPressed: busy ? null : () => resetLocal('vault'), child: const LText('localReset.vault.title')),
            const SizedBox(height: 8),
            OutlinedButton(onPressed: busy ? null : () => resetLocal('app'), child: const LText('localReset.app.title')),
          ],
        )),
    ];
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Padding(padding: const EdgeInsets.fromLTRB(16, 12, 16, 0), child: TextField(controller: search,
        decoration: InputDecoration(hintText: tr('android.settings.search'), prefixIcon: const Icon(Icons.search),
          suffixIcon: query.isEmpty ? null : IconButton(tooltip: tr('android.settings.clearSearch'),
            onPressed: () { search.clear(); setState(() => query = ''); }, icon: const Icon(Icons.close))),
        onChanged: (value) => setState(() => query = value.trim().toLowerCase()))),
      SingleChildScrollView(scrollDirection: Axis.horizontal, padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: Row(children: [for (final entry in sections.entries) Padding(padding: const EdgeInsets.only(right: 8),
          child: ChoiceChip(label: LText(entry.value), selected: section == entry.key,
            onSelected: (_) => setState(() { section = entry.key; FocusManager.instance.primaryFocus?.unfocus(); })))])),
      if (message.isNotEmpty) Padding(padding: const EdgeInsets.symmetric(horizontal: 16), child: AppNotice(message)),
      Expanded(child: panels.isEmpty ? const Center(child: LText('android.settings.noResults')) : ListView.separated(
        key: ValueKey('$section:$query'), keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 16), itemCount: panels.length,
        separatorBuilder: (context, index) => const SizedBox(height: 16), itemBuilder: (_, index) => panels[index])),
      const Divider(height: 1),
      Padding(padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8), child: Row(children: [
        TextButton(onPressed: busy ? null : resetDefaults, child: const LText('android.settings.reset')),
        const SizedBox(width: 12), Expanded(child: FilledButton(onPressed: busy ? null : save, child: const LText('android.settings.save'))),
      ])),
    ]);
  }
}
