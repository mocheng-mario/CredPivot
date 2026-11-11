import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';
import 'app_navigation.dart';
import 'app_ui.dart';
import 'build_stamp.dart';
import 'chrome_setup_tab.dart';
import 'diagnostics_tab.dart';
import 'credentials_page.dart';
import 'touch_id_gate.dart';
import 'memory_format.dart';
import 'vault_lock_coordinator.dart';
import 'agent_readiness.dart';
import 'settings_page.dart';
import 'shortcuts_page.dart';
import 'vault_tools.dart';
import 'vault_transfer_tools.dart';
import 'webdav_sync.dart';
import 'webdav_bootstrap.dart';
import 'vault_setup.dart';
import 'credential_partitions.dart';
import 'totp_editor.dart';
import 'main_android.dart' as android;

Future<void> main() async {
  if (Platform.isAndroid) { await android.main(); return; }
  WidgetsFlutterBinding.ensureInitialized();
  try {
    await AppPresentation.instance.loadCatalog();
  } catch (_) {
    // 此时语言目录本身不可用，不能依赖翻译接口；也不能让首帧之前的异常只留下黑屏。
    runApp(const MaterialApp(
      home: Scaffold(
        body: Center(
          child: Padding(
            padding: EdgeInsets.all(24),
            child: SelectableText('语言资源加载失败，请重新构建或安装 CredPivot。'),
          ),
        ),
      ),
    ));
    return;
  }
  runApp(const CredPivotApp());
}

class CredPivotApp extends StatelessWidget {
  const CredPivotApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(listenable: AppPresentation.instance, builder: (context, _) => MaterialApp(
      navigatorKey: vaultRootNavigatorKey,
      title: 'CredPivot',
      theme: buildAppTheme(brightness: Brightness.light),
      darkTheme: buildAppTheme(brightness: Brightness.dark),
      themeMode: AppPresentation.instance.mode,
      // macOS 默认将 Home/End 交回系统；显式映射到文本光标，覆盖所有输入框。
      builder: (context, child) => Shortcuts(shortcuts: const <ShortcutActivator, Intent>{
        SingleActivator(LogicalKeyboardKey.home): ExtendSelectionToLineBreakIntent(forward: false, collapseSelection: true),
        SingleActivator(LogicalKeyboardKey.end): ExtendSelectionToLineBreakIntent(forward: true, collapseSelection: true),
        SingleActivator(LogicalKeyboardKey.home, shift: true): ExtendSelectionToLineBreakIntent(forward: false, collapseSelection: false),
        SingleActivator(LogicalKeyboardKey.end, shift: true): ExtendSelectionToLineBreakIntent(forward: true, collapseSelection: false),
        SingleActivator(LogicalKeyboardKey.home, control: true): ExtendSelectionToDocumentBoundaryIntent(forward: false, collapseSelection: true),
        SingleActivator(LogicalKeyboardKey.end, control: true): ExtendSelectionToDocumentBoundaryIntent(forward: true, collapseSelection: true),
        SingleActivator(LogicalKeyboardKey.home, control: true, shift: true): ExtendSelectionToDocumentBoundaryIntent(forward: false, collapseSelection: false),
        SingleActivator(LogicalKeyboardKey.end, control: true, shift: true): ExtendSelectionToDocumentBoundaryIntent(forward: true, collapseSelection: false),
      }, child: child ?? const SizedBox.shrink()),
      home: const VaultHomePage(),
    ));
  }
}

class VaultHomePage extends StatefulWidget {
  const VaultHomePage({super.key});

  @override
  State<VaultHomePage> createState() => _VaultHomePageState();
}

class _VaultHomePageState extends State<VaultHomePage> {
  String _log = tr('vault.build.text');
  String _operationMessage = '';
  String _pendingRecoveryKey = '';

  void _retainRecoveryKey(String key) {
    if (mounted) setState(() => _pendingRecoveryKey = key);
  }
  final _password = TextEditingController();
  final _passwordFocus = FocusNode();
  final _newPassword = TextEditingController();
  final _confirmNewPassword = TextEditingController();
  final _syncHostName = TextEditingController();
  final _recoveryKey = TextEditingController();
  // 备份可能来自其他保险库，恢复密码不与当前主密码共用输入状态。
  final _recoveryPassword = TextEditingController();
  final _chromeExtensionId = TextEditingController();
  Map<String, dynamic> _status = {};
  int _memoryBytes = 0;
  bool _busy = false;
  bool _skippedSetup = false;
  bool _creatingVault = false;
  bool _openingRemote = false;
  bool _initializing = true;
  bool _bootstrapping = false;
  bool _wakeUnlockInProgress = false;
  bool _showMasterPassword = false;
  String _unlockMessage = '';
  int _pageIndex = 0;
  final Set<int> _visitedPages = {0};

  bool get _vaultExists => _status['vault_exists'] == true;
  bool get _unlocked => _status['unlocked'] == true;
  bool get _needsMasterPassword => _showMasterPassword ||
      _status['master_password_required'] != false ||
      _status['local_unlock_configured'] != true;

  Timer? _vaultLockPoll;
  bool _vaultLockPolling = false;
  bool _browserMfaOpening = false;
  int _statusRequestGeneration = 0;
  int _lastVaultLockGen = 0;
  String? _lastDataRevision;

  @override
  void initState() {
    super.initState();
    CredentialPartitions.instance.start();
    CredentialPartitions.instance.addListener(_onPartitionsChanged);
    WebDavSync.instance.start();
    WebDavSync.instance.onFailure = _showSyncFailure;
    AppPresentation.instance.addListener(_onPresentationChanged);
    installVaultLockCoordinator(_onVaultLockedExternally);
    AgentBridge.onShortcut = _handleShortcut;
    AgentBridge.onAppForeground = _onAppForeground;
    AgentBridge.installVaultLockHandler(notifyVaultLocked);
    _vaultLockPoll = Timer.periodic(const Duration(seconds: 2), (_) => _pollVaultLockGeneration());
    _bootstrap();
  }

  void _onPresentationChanged() {
    // 系统外观及语言切换后，重新计算页面中已解析的颜色和输入框文案。
    if (mounted) setState(() {});
  }

  void _onPartitionsChanged() { if (mounted) setState(() {}); }

  Future<void> _showSyncFailure(String message) async {
    if (!mounted || !WebDavSync.instance.unlocked) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        title: const LText('sync.errors.dialogTitle'),
        content: SizedBox(width: appEditDialogWidth(ctx),
            child: SingleChildScrollView(child: SelectableText(message))),
        actions: [TextButton(onPressed: () => Navigator.pop(ctx),
            child: const LText('sync.errors.acknowledge'))],
      ),
    );
  }

  Future<void> _pollVaultLockGeneration() async {
    if (_vaultLockPolling || _initializing || !mounted) return;
    _vaultLockPolling = true;
    final generation = _statusRequestGeneration;
    try {
      final raw = await AgentBridge.request({'type': 'status'});
      if (!mounted || generation != _statusRequestGeneration) return;
      final payload = AgentBridge.payloadOf(raw);
      final gen = (payload['vault_lock_generation'] as num?)?.toInt() ?? 0;
      final agentUnlocked = payload['unlocked'] == true;
      WebDavSync.instance.setUnlocked(agentUnlocked && !_openingRemote);
      CredentialPartitions.instance.setUnlocked(agentUnlocked);
      final revision = payload['data_revision']?.toString();
      if (agentUnlocked && _lastDataRevision != null && revision != _lastDataRevision) AgentBridge.notifyVaultChanged();
      _lastDataRevision = revision;
      if (!agentUnlocked && _unlocked) {
        notifyVaultLocked();
      } else if (agentUnlocked && !_unlocked) {
        // 浏览器可在原生验证窗口中解锁，Flutter 也要同步显示新状态。
        await _refreshStatus();
      } else if (agentUnlocked && _lastVaultLockGen != 0 && gen != _lastVaultLockGen) {
        notifyVaultLocked();
      } else if (_status['master_password_required'] != payload['master_password_required'] ||
          _status['sync_host_name'] != payload['sync_host_name'] ||
          _status['vault_path'] != payload['vault_path'] ||
          _vaultExists != (payload['vault_exists'] == true)) {
        await _refreshStatus();
      }
      _lastVaultLockGen = gen;
      if (agentUnlocked && !_busy && !_browserMfaOpening && ModalRoute.of(context)?.isCurrent == true) {
        unawaited(_openBrowserMfa());
      }
    } catch (_) {
      // 失去后台状态时先遮住内容，不能继续展示上一次解锁会话的数据。
      if (mounted && _unlocked) notifyVaultLocked();
    } finally {
      _vaultLockPolling = false;
    }
  }

  void _onVaultLockedExternally() {
    WebDavSync.instance.setUnlocked(false);
    CredentialPartitions.instance.setUnlocked(false);
    _statusRequestGeneration++;
    clearSensitiveAuthGrace();
    _password.clear();
    _recoveryKey.clear();
    _recoveryPassword.clear();
    _newPassword.clear();
    _confirmNewPassword.clear();
    if (mounted) {
      setState(() {
        _status = {..._status, 'unlocked': false};
        _showMasterPassword = false;
        _unlockMessage = '';
        _operationMessage = '';
      });
      _refreshStatus().catchError((Object _) {});
    }
  }

  Future<void> _openBrowserMfa() async {
    if (_browserMfaOpening || !mounted) return;
    _browserMfaOpening = true;
    Map<String, dynamic>? pending;
    var saved = false;
    try {
      final response = AgentBridge.payloadOf(await AgentBridge.request({'type': 'browser_mfa_pending'}));
      if (!mounted || response['request'] is! Map) return;
      final source = response['request'] as Map;
      pending = Map<String, dynamic>.from(source);
      source.remove('image');
      await AgentBridge.showMainWindow();
      if (!mounted || !_unlocked) return;
      saved = await showTotpEditor(context, browserRequest: pending);
      if (saved && mounted) { AgentBridge.notifyVaultChanged(); await _refreshStatus(); }
    } on AgentException catch (problem) {
      if (mounted) _appendLog(AgentBridge.friendlyMessage(problem));
    } catch (_) {
      if (mounted) _appendLog(tr('mfa.showTotpEditor.message'));
    } finally {
      pending?.remove('image');
      if (pending != null && !saved) {
        try { await AgentBridge.request({'type': 'browser_mfa_resolve', 'request_id': pending['id'], 'approved': false}); } catch (_) {}
      }
      _browserMfaOpening = false;
    }
  }

  @override
  void dispose() {
    CredentialPartitions.instance.removeListener(_onPartitionsChanged);
    CredentialPartitions.instance.stop();
    WebDavSync.instance.onFailure = null;
    WebDavSync.instance.stop();
    AgentBridge.onShortcut = null;
    AgentBridge.onAppForeground = null;
    AppPresentation.instance.removeListener(_onPresentationChanged);
    _vaultLockPoll?.cancel();
    _password.dispose();
    _passwordFocus.dispose();
    _newPassword.dispose();
    _confirmNewPassword.dispose();
    _syncHostName.dispose();
    _recoveryKey.dispose();
    _recoveryPassword.dispose();
    _chromeExtensionId.dispose();
    super.dispose();
  }

  Future<void> _run(String label, Future<void> Function() action) async {
    if (_busy || !mounted) return;
    setState(() {
      _busy = true;
      _operationMessage = '';
    });
    try {
      await action();
    } on AgentException catch (e) {
      final msg = AgentBridge.diagnosticMessage(e);
      _appendLog(tr('vault.errors.operationFailed', args: {'label': label, 'error': msg}));
      if (AgentBridge.isAgentNotStartedError(e)) {
        _showAgentNotStartedHint();
      }
    } catch (_) {
      _appendLog(tr('vault.errors.operationFailedDiagnostic', args: {'label': label}));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _appendLog(String line) {
    if (!mounted) return;
    setState(() {
      _log = line;
      _operationMessage = line;
    });
  }

  Future<void> _refreshStatus() async {
    if (!mounted) return;
    final generation = ++_statusRequestGeneration;
    final raw = await AgentBridge.request({'type': 'status'});
    final payload = AgentBridge.payloadOf(raw);
    // 遥测失败不能阻止应用收到真实锁定状态。
    Map<String, dynamic> chrome = {};
    var memoryBytes = _memoryBytes;
    try { chrome = await AgentBridge.chromeHostStatus(); } catch (_) {}
    try { memoryBytes = await AgentBridge.residentMemoryBytes(); } catch (_) {}
    // 锁定通知或较新的刷新已经到达时，不再应用旧的解锁状态。
    if (!mounted || generation != _statusRequestGeneration) return;
    if (_status['vault_id'] != payload['vault_id']) CredentialPartitions.instance.setUnlocked(false);
    CredentialPartitions.instance.setUnlocked(payload['unlocked'] == true);
    _memoryBytes = memoryBytes;
    if (payload['unlocked'] != true) {
      clearSensitiveAuthGrace();
      if (_unlocked) {
        vaultRootNavigatorKey.currentState?.popUntil((route) => route.isFirst);
        _password.clear();
        _newPassword.clear();
        _confirmNewPassword.clear();
        _recoveryKey.clear();
        _recoveryPassword.clear();
        _showMasterPassword = false;
        _unlockMessage = '';
        _operationMessage = '';
      }
    } else if (!_unlocked) {
      // 浏览器也可能完成解锁，不把锁定页尚未提交的主密码留在内存中。
      _password.clear();
      _showMasterPassword = false;
      _unlockMessage = '';
    }
    setState(() {
      _status = payload;
      _log = const JsonEncoder.withIndent('  ').convert({
        'build_stamp': kCredPivotBuildStamp,
        'chrome_host': chrome,
        'agent': payload,
      });
    });
    WebDavSync.instance.setUnlocked(payload['unlocked'] == true && !_openingRemote);
  }

  Future<void> _bootstrap() async {
    if (_bootstrapping || !mounted) return;
    _bootstrapping = true;
    setState(() => _initializing = true);
    try {
      if (!await AgentBridge.ensureAgentReady()) {
        _appendLog(
          tr('vault.bootstrap.text'),
        );
        return;
      }
      try { await AppPresentation.instance.load(); } catch (_) { /* 外观设置不能阻止保险库解锁。 */ }
      try {
        _chromeExtensionId.text = await AgentBridge.getChromeExtensionId();
        final chrome = await AgentBridge.chromeHostStatus();
        final id = _chromeExtensionId.text.trim();
        if (id.isNotEmpty &&
            (chrome['manifest_exists'] != true ||
                chrome['installed_host_exists'] != true ||
                chrome['trusted_host_configured'] != true ||
                chrome['installed_host_current'] != true ||
                chrome['manifest_host_matches_installed'] != true ||
                chrome['host_id_matches_manifest'] != true)) {
          final r = await AgentBridge.installChromeHost(id);
          if (r['ok'] != true) {
            _appendLog('Chrome Host: ${r['message']}');
          }
        }
      } catch (_) {
        // 浏览器集成不可用时仍须继续显示解锁页和执行启动验证。
        _appendLog(tr('vault.bootstrap.text.item2'));
      }
      await _refreshStatus();
    } catch (_) {
      _appendLog(tr('vault.bootstrap.text.item3'));
    } finally {
      _bootstrapping = false;
      if (mounted) setState(() => _initializing = false);
    }
    // 浏览器后台拉起时由原生协调器统一验证，避免与启动验证重复弹窗。
    // 普通启动只主动弹一次；取消后停留在锁定页，避免反复抢占焦点。
    if (mounted &&
        _vaultExists &&
        !_unlocked &&
        _status['browser_background_launch'] != true) {
      if (_needsMasterPassword) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (mounted && !_unlocked) _passwordFocus.requestFocus();
        });
      } else {
        await _unlockTouchId();
      }
    }
  }

  Future<void> _onAppForeground() async {
    if (!mounted || _initializing || _busy || _wakeUnlockInProgress) return;
    _wakeUnlockInProgress = true;
    try {
      final settings = await AgentBridge.fetchAppSettings();
      final values = settings['settings'];
      if (values is! Map || values['auto_unlock_on_wake'] != true) return;
      await _refreshStatus();
      // 设置和状态查询期间可能已切到后台，不能因此在其他应用前弹出验证。
      final foreground = await AgentBridge.isMainWindowForeground();
      if (!mounted || _busy || !foreground || !_vaultExists || _unlocked) return;
      setState(() {
        _showMasterPassword = false;
        _unlockMessage = '';
      });
      if (_needsMasterPassword) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (mounted && !_unlocked) _passwordFocus.requestFocus();
        });
      } else {
        await _unlockTouchId();
      }
    } catch (_) {
      // 自动验证不可用时保留手动解锁入口，不放宽现有的解锁策略。
    } finally {
      _wakeUnlockInProgress = false;
    }
  }

  Future<void> _showAgentNotStartedHint() {
    if (!mounted) return Future.value();
    return showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const LText('vault.showAgentNotStartedHint.text'),
        content: const LText(
          'vault.showAgentNotStartedHint.text.item2',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('vault.showAgentNotStartedHint.text.item3')),
          TextButton(
            onPressed: () {
              Navigator.pop(ctx);
              _restartAgent();
            },
            child: const LText('vault.showAgentNotStartedHint.text.item4'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.pop(ctx);
              AgentBridge.relaunchApp();
            },
            child: const LText('vault.showAgentNotStartedHint.text.item5'),
          ),
        ],
      ),
    );
  }

  Future<void> _restartAgent() async {
    await _run(tr('vault.showAgentNotStartedHint.text.item4'), () async {
      final ok = await AgentBridge.restartAgent();
      if (!ok) {
        _appendLog(tr('vault.restartAgent.text'));
        return;
      }
      await _refreshStatus();
      _appendLog(tr('agent.status.restarted'));
    });
  }

  Future<void> _relaunchApp() async {
    await AgentBridge.relaunchApp();
  }

  Future<bool> _guardAgent(String actionLabel) async {
    final ok = await AgentBridge.ensureAgentReady();
    if (!ok) {
      _appendLog(tr('vault.guardAgent.text', args: {'actionLabel': actionLabel}));
      await _showAgentNotStartedHint();
    }
    return ok;
  }

  Future<void> _createVault() async {
    final pw = _password.text;
    if (pw.length < 8) {
      _appendLog(tr('vault.createVault.text'));
      return;
    }
    if (!await _guardAgent(tr('vault.createVault.text.item2'))) return;
    await _run(tr('vault.createVault.text.item2'), () async {
      final recovery = await AgentBridge.vaultCreate(pw);
      Object? hostNameError;
      try {
        await AgentBridge.setSyncHostName(_syncHostName.text.trim());
        _syncHostName.clear();
      } catch (e) {
        // 名称写入失败不能跳过恢复密钥提示；展示密钥后再报告此错误。
        hostNameError = e;
      }
      await _refreshStatus();
      if (!mounted) return;
      final session = await AgentBridge.clipboardSession();
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const LText('vault.createVault.text.item3'),
          content: SelectableText(recovery),
          actions: [
            TextButton(
              onPressed: () async {
                try {
                  await AgentBridge.copyConcealed(recovery, session: session);
                } catch (error) { vaultMessage(ctx, error); return; }
                if (ctx.mounted) {
                  ScaffoldMessenger.of(ctx).showSnackBar(const SnackBar(content: LText('common.copied')));
                }
              },
              child: const LText('common.copy'),
            ),
            FilledButton(onPressed: () => Navigator.pop(ctx), child: const LText('vault.createVault.text.item4')),
          ],
        ),
      );
      if (hostNameError != null) throw hostNameError;
    });
  }

  Future<void> _editSyncHostName() async {
    final original = _status['sync_host_name_override']?.toString() ?? '';
    var name = original;
    final value = await showDialog<String>(context: context, builder: (ctx) => AlertDialog(
      title: const LText('vault.syncHost.title'),
      content: SizedBox(width: appEditDialogWidth(ctx), child: AppFieldRow(label: tr('vault.syncHost.label'), help: tr('vault.syncHost.help'), child: TextFormField(
        initialValue: original,
        autofocus: true,
        maxLength: 128,
        decoration: InputDecoration(hintText: _status['computer_name']?.toString()),
        onChanged: (text) => name = text,
        onFieldSubmitted: (text) => Navigator.pop(ctx, text),
      ))),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.cancel')),
        FilledButton(onPressed: () => Navigator.pop(ctx, name), child: const LText('common.save')),
      ],
    ));
    if (value == null || !mounted) return;
    await _run(tr('vault.syncHost.title'), () async {
      await AgentBridge.setSyncHostName(value.trim());
      await _refreshStatus();
      // 同步页可能已打开；只刷新本地状态，不触发网络同步。
      await WebDavSync.instance.refresh();
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: LText('vault.syncHost.saved')));
    });
  }

  Future<void> _unlock() async {
    if (_busy) return;
    if (_password.text.isEmpty) {
      setState(() => _unlockMessage = tr('vault.unlock.text'));
      _passwordFocus.requestFocus();
      return;
    }
    setState(() => _unlockMessage = '');
    if (!await _guardAgent(tr('vault.actions.unlock'))) return;
    await _run(tr('vault.actions.unlock'), () async {
      final ok = await AgentBridge.unlockWithPassword(_password.text);
      if (!mounted) return;
      if (!ok) {
        _password.clear();
        setState(() => _unlockMessage = tr('vault.unlock.text.item2'));
        _passwordFocus.requestFocus();
        return;
      }
      _password.clear();
      await _refreshStatus();
    });
    if (mounted && !_unlocked && _unlockMessage.isEmpty) {
      setState(() => _unlockMessage = tr('vault.unlock.text.item3'));
    }
  }

  Future<void> _unlockTouchId() async {
    if (_busy) return;
    setState(() => _unlockMessage = '');
    await _run('Touch ID', () async {
      final ok = await AgentBridge.unlockWithTouchId()
          .timeout(const Duration(seconds: 120), onTimeout: () => false);
      if (!ok) {
        if (!mounted) return;
        setState(() {
          _showMasterPassword = true;
          _unlockMessage = tr('vault.unlockTouchId.text');
        });
        await _refreshStatus();
        return;
      }
      await _refreshStatus();
    });
    if (mounted && !_unlocked && _unlockMessage.isEmpty) {
      setState(() {
        _showMasterPassword = true;
        _unlockMessage = tr('vault.unlockTouchId.text.item2');
      });
    }
  }

  Future<void> _lock() async {
    await _run(tr('vault.lock.text'), () async {
      await AgentBridge.lockVault();
      clearSensitiveAuthGrace();
      await _refreshStatus();
    });
  }

  Future<void> _changePassword() async {
    if (_busy || !_unlocked || !mounted) return;
    final currentPassword = _password.text;
    final newPassword = _newPassword.text;
    if (currentPassword.isEmpty) {
      _appendLog(tr('vault.changePassword.currentRequired'));
      return;
    }
    if (newPassword.length < 8) {
      _appendLog(tr('vault.changePassword.text'));
      return;
    }
    if (newPassword != _confirmNewPassword.text) {
      _appendLog(tr('vault.changePassword.mismatch'));
      return;
    }
    if (!await requireTouchId(context, reason: tr('vault.changePassword.reason')) || !mounted) return;
    await _run(tr('vault.changePassword.text.item2'), () async {
      await AgentBridge.vaultChangePassword(currentPassword, newPassword);
      _password.clear();
      _newPassword.clear();
      _confirmNewPassword.clear();
      await _refreshStatus();
      _appendLog(tr('vault.changePassword.text.item3'));
    });
  }

  Future<void> _exportOvb() async {
    if (_busy || !_unlocked || !mounted) return;
    await _run(tr('vault.exportOvb.text'), () async {
      final password = TextEditingController();
      ModalRoute<String>? route;
      var exporting = false, closing = false;
      var error = '';
      try {
        final output = await showDialog<String>(context: context, barrierDismissible: false, builder: (ctx) {
          route = ModalRoute.of<String>(ctx);
          return StatefulBuilder(builder: (ctx, update) {
            Future<void> save() async {
              if (exporting || closing) return;
              final secret = password.text;
              if (secret.isEmpty) { update(() => error = tr('vault.exportOvb.passwordRequired')); return; }
              update(() { exporting = true; error = ''; });
              try {
                final path = await AgentBridge.pickSaveFile();
                if (path == null || !ctx.mounted || closing) return;
                // 首页密码框会在解锁后清空，不能作为导出凭据；主密码验证同时完成敏感授权。
                // 选定路径后再验证，避免用户停留在保存面板期间授权过期。
                await AgentBridge.request({'type': 'verify_master_password', 'password': secret});
                if (!ctx.mounted || closing) return;
                await AgentBridge.vaultExportOvb(path, secret);
                if (ctx.mounted) {
                  closing = true;
                  password.clear();
                  Navigator.pop(ctx, path);
                }
              } on AgentException catch (problem) {
                if (ctx.mounted && !closing) update(() => error = problem.code == 'bad_unlock'
                    ? tr('vault.exportOvb.passwordInvalid') : AgentBridge.friendlyMessage(problem));
              } catch (_) {
                if (ctx.mounted && !closing) update(() => error = tr('vault.exportOvb.failed'));
              } finally {
                if (ctx.mounted && !closing) update(() => exporting = false);
              }
            }
            return PopScope(canPop: !exporting, child: AlertDialog(
              title: const LText('vault.exportOvb.reason'),
              content: SizedBox(width: appEditDialogWidth(ctx), child: SingleChildScrollView(child: Column(
                mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                const LText('vault.exportOvb.passwordHelp'),
                const SizedBox(height: 16),
                AppFieldRow(label: tr('vault.vaultOverview.text.item19'), child: TextField(
                  controller: password, enabled: !exporting, obscureText: true, autofocus: true,
                  autocorrect: false, enableSuggestions: false, enableIMEPersonalizedLearning: false,
                  decoration: const InputDecoration(), onSubmitted: (_) => save())),
                if (error.isNotEmpty) SelectableText(error, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
                if (exporting) const LinearProgressIndicator(),
              ]))),
              actions: [
                TextButton(onPressed: exporting ? null : () { closing = true; Navigator.pop(ctx); }, child: const LText('common.cancel')),
                FilledButton(onPressed: exporting ? null : save, child: LText(exporting ? 'common.saving' : 'vault.exportOvb.chooseAndExport')),
              ],
            ));
          });
        });
        // 等弹窗卸载再释放控制器或显示结果，避免退出动画期间访问已销毁的输入框。
        await route?.completed;
        if (output == null || !mounted) return;
        _appendLog(tr('vault.exportOvb.text.item2', args: {'path': output}));
        await showDialog<void>(context: context, builder: (ctx) => AlertDialog(
          title: const LText('vault.exportOvb.success'), content: SelectableText(output),
          actions: [FilledButton(onPressed: () => Navigator.pop(ctx), child: const LText('common.close'))],
        ));
        if (mounted) await _refreshStatus();
      } finally {
        await route?.completed;
        password.dispose();
      }
    });
  }

  Future<void> _recoverOvb({required bool useRecovery}) async {
    if (_busy || !mounted) return;
    final initial = !_vaultExists;
    // 在打开系统面板前记录输入，避免后续锁定清空控件后将空口令提交给恢复操作。
    var password = _recoveryPassword.text;
    final recoveryKey = _recoveryKey.text.trim();
    if (useRecovery && recoveryKey.isEmpty) {
      _appendLog(tr('vault.recoverOvb.recoveryKeyRequired'));
      return;
    }
    if (!initial && !useRecovery && password.isEmpty) {
      _appendLog(tr('vault.recoverOvb.passwordRequired'));
      return;
    }
    final ovb = await AgentBridge.pickOpenFile();
    if (ovb == null || !mounted) return;
    final target = await AgentBridge.pickDirectory();
    if (target == null || !mounted) return;
    if (initial && !useRecovery && password.isEmpty) {
      final supplied = await askInitialBackupPassword(context);
      if (supplied == null || !mounted) return;
      password = supplied;
    }
    await _run(tr('vault.recoverOvb.text'), () async {
      await AgentBridge.vaultRecoverOvb(
        ovbPath: ovb,
        targetDir: target,
        password: useRecovery ? null : password,
        recoveryKey: useRecovery ? recoveryKey : null,
      );
      await AgentBridge.lockVault();
      await AgentBridge.vaultOpenDir(target);
      _onVaultLockedExternally();
      if (initial && !useRecovery && !await AgentBridge.unlockWithPassword(password)) {
        throw AgentException('bad_unlock', tr('sync.bootstrap.openFailed'));
      }
      await _refreshStatus();
      _appendLog(tr('vault.recoverOvb.text.item2', args: {'target': target}));
    });
  }

  Future<void> _openRemote() async {
    if (_busy) return;
    WebDavBootstrapOutcome? outcome;
    setState(() { _busy = true; _openingRemote = true; _operationMessage = ''; });
    try {
      outcome = await openWebDavBootstrap(context);
    } on AgentException catch (error) {
      _appendLog(AgentBridge.diagnosticMessage(error));
    } catch (_) {
      _appendLog(tr('sync.errors.operation'));
    } finally {
      _openingRemote = false;
      try { await _refreshStatus(); }
      catch (_) { _appendLog(tr('sync.errors.operation')); }
      if (mounted) setState(() => _busy = false);
    }
    if (mounted && outcome == WebDavBootstrapOutcome.createNew) setState(() => _creatingVault = true);
  }

  Widget _initialVaultView() => SafeArea(child: _creatingVault ? Column(children: [
    Align(alignment: Alignment.centerLeft, child: TextButton.icon(
      onPressed: _busy ? null : () => setState(() { _creatingVault = false; _password.clear(); _syncHostName.clear(); }),
      icon: const Icon(Icons.arrow_back), label: const LText('setup.back'))),
    if (_operationMessage.isNotEmpty) Padding(padding: const EdgeInsets.all(16), child: AppNotice(_operationMessage)),
    Expanded(child: _vaultOverview()),
  ]) : _skippedSetup ? UnconfiguredVaultPage(onSetup: () => setState(() => _skippedSetup = false)) : Column(children: [
    if (_operationMessage.isNotEmpty) Padding(padding: const EdgeInsets.all(16), child: AppNotice(_operationMessage)),
    Wrap(spacing: 10, children: [
      TextButton(onPressed: _busy ? null : _openVaultDir, child: const LText('vaultTools.maintenance.switch')),
      TextButton(onPressed: _busy || _pendingRecoveryKey.isNotEmpty ? null : () => _run(tr('vaultTools.maintenance.importJson'), () async {
        await showVaultTransferTool(context, VaultTransferTool.importJson, onRecoveryKey: _retainRecoveryKey);
      }), child: const LText('vaultTools.maintenance.importJson')),
    ]),
    Expanded(child: VaultSetupChoices(busy: _busy, onCreate: () => setState(() => _creatingVault = true),
      onWebDav: _openRemote, onRestore: () => _recoverOvb(useRecovery: false),
      onSkip: () => setState(() => _skippedSetup = true))),
  ]));

  Future<void> _openVaultDir() async {
    if (_busy || !mounted) return;
    final dir = await AgentBridge.pickDirectory();
    if (dir == null) return;
    await _run(tr('vault.openVaultDir.text'), () async {
      await AgentBridge.vaultOpenDir(dir);
      _onVaultLockedExternally();
      await _refreshStatus();
    });
  }

  Future<void> _handleShortcut(String action) async {
    if (!mounted || _busy) return;
    if (!_unlocked) {
      if (_status['master_password_required'] == false && _status['local_unlock_configured'] == true) await _unlockTouchId();
      else { _passwordFocus.requestFocus(); return; }
      if (!mounted || !_unlocked) return;
    }
    // 搜索和新建不跨过正在打开的编辑窗口，避免打断当前草稿。
    if (ModalRoute.of(context)?.isCurrent != true) return;
    if (action == 'search') await showCredentialSearch(context);
    if (action == 'new') await showNewCredentialMenu(context);
  }

  void _selectPage(int index) {
    if (_status.isEmpty || (_vaultExists && !_unlocked)) return;
    setState(() {
      _pageIndex = index;
      _visitedPages.add(index);
    });
  }

  void _selectPartition(String id) {
    if (!_unlocked) return;
    AgentBridge.activePartitionId = id;
    _selectPage(1);
  }

  @override
  Widget build(BuildContext context) {
    final vaultLabel = !_vaultExists ? tr('vault.build.text.item2') : (_unlocked ? tr('vault.status.unlockedShort') : tr('vault.status.lockedShort'));
    return AgentReadinessScope(
      builder: (context, agentReady) => Scaffold(
        // 首次创建/恢复保险库仍需可用；已有保险库锁定后只显示解锁入口。
        body: _initializing
            ? const Center(child: CircularProgressIndicator())
            : !agentReady || _status.isEmpty
                ? _connectionUnavailable()
                : !_vaultExists
                    ? _initialVaultView()
                    : !_unlocked
                    ? _lockedView()
                    : SafeArea(
          child: LayoutBuilder(builder: (context, constraints) {
            return Row(children: [
              AppSidebar(
                partitions: CredentialPartitions.instance.items,
                selectedPartitionId: AgentBridge.activePartitionId,
                onPartitionSelected: _selectPartition,
                selectedIndex: _pageIndex,
                onSelected: _selectPage,
                compact: constraints.maxWidth < 960,
                agentReady: agentReady,
                unlocked: agentReady && _unlocked,
                footer:
                    tr('vault.status.memoryBuildMultiline', args: {'memory': formatResidentMemory(_memoryBytes), 'build': kCredPivotBuildStamp}),
              ),
              Expanded(
                  child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                    Padding(
                      padding: const EdgeInsets.fromLTRB(24, 22, 24, 18),
                      child: Row(children: [
                        Expanded(
                            child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                              LText(_pageIndex == 1 ? tr('partitions.credentialsTitle', args: {'name': CredentialPartitions.instance.activeName}) : appPageTitles[_pageIndex],
                                  style: Theme.of(context)
                                      .textTheme
                                      .headlineMedium),
                              const SizedBox(height: 4),
                              LText(appPageDescriptions[_pageIndex],
                                  style: Theme.of(context).textTheme.bodySmall),
                            ])),
                        const SizedBox(width: 12),
                        if (agentReady && _unlocked) ...[
                          IconButton(tooltip: tr('vault.build.text.item4'), onPressed: _busy ? null : () => _handleShortcut('search'), icon: const Icon(Icons.search_rounded)),
                          IconButton(tooltip: tr('credentials.actions.new'), onPressed: _busy ? null : () => _handleShortcut('new'), icon: const Icon(Icons.add_rounded)),
                        ],
                        AppStatusBadge(agentReady ? vaultLabel : tr('vault.build.text.item5'),
                            color: agentReady && _unlocked
                                ? AppColors.green
                                : AppColors.muted),
                        if (agentReady && _unlocked) ...[
                          const SizedBox(width: 8),
                          IconButton(
                              onPressed: _busy ? null : _lock,
                              tooltip: tr('vault.actions.lock'),
                              icon: const Icon(Icons.lock_outline_rounded)),
                        ],
                      ]),
                    ),
                    if (_busy)
                      const LinearProgressIndicator(minHeight: 2)
                    else
                      const SizedBox(height: 2),
                    if (_status['settings_valid'] == false)
                      Padding(
                        padding: EdgeInsets.symmetric(horizontal: 24),
                        child: AppNotice(tr('vault.build.text.item6')),
                      ),
                    if (_operationMessage.isNotEmpty)
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 24),
                        child: ConstrainedBox(
                          constraints: const BoxConstraints(maxHeight: 96),
                          child: SingleChildScrollView(
                              child: AppNotice(
                            _operationMessage,
                            onDismiss: () =>
                                setState(() => _operationMessage = ''),
                          )),
                        ),
                      ),
                    if (_pendingRecoveryKey.isNotEmpty)
                      Padding(padding: const EdgeInsets.symmetric(horizontal: 24), child: Card(child: Padding(
                        padding: const EdgeInsets.all(12), child: Column(mainAxisSize: MainAxisSize.min, children: [
                          LText(_unlocked ? 'vaultTools.maintenance.saveKey' : 'vaultTools.maintenance.pendingKey'),
                          if (_unlocked) ...[
                            SelectableText(_pendingRecoveryKey),
                            TextButton(onPressed: () => _retainRecoveryKey(''), child: const LText('vaultTools.maintenance.savedKey')),
                          ],
                        ]),
                      ))),
                    Expanded(
                      child: agentReady
                          // 按需创建页面，保留切换状态；锁定时所有已创建页面都会收到新的 unlocked。
                          ? IndexedStack(
                              index: _pageIndex,
                              children: List.generate(
                                  appPageTitles.length,
                                  (index) => _visitedPages.contains(index)
                                      ? TickerMode(
                                          enabled: index == _pageIndex,
                                          child: ExcludeFocus(
                                              excluding: index != _pageIndex,
                                              child: _page(index)),
                                        )
                                      : const SizedBox.shrink()),
                            )
                          : AgentNotReadyPane(
                              onRestartAgent: _restartAgent,
                              onRelaunchApp: _relaunchApp,
                              log: _log),
                    ),
                  ])),
            ]);
          }),
        ),
      ),
    );
  }

  Widget _connectionUnavailable() => Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 460),
          child: AppPanel(
            title: tr('vault.connectionUnavailable.title'),
            subtitle: tr('vault.connectionUnavailable.description'),
            icon: Icons.lock_outline_rounded,
            child: Wrap(spacing: 10, runSpacing: 10, children: [
              FilledButton(onPressed: _busy ? null : _bootstrap,
                  child: const LText('vault.connectionUnavailable.text')),
              OutlinedButton(onPressed: _busy ? null : () async {
                await _restartAgent();
                if (mounted) await _bootstrap();
              }, child: const LText('vault.connectionUnavailable.text.item2')),
              TextButton(onPressed: _busy ? null : _relaunchApp,
                  child: const LText('vault.showAgentNotStartedHint.text.item5')),
            ]),
          ),
        ),
      );

  Widget _lockedView() {
    final canUseBiometrics = _status['local_unlock_configured'] == true &&
        _status['master_password_required'] == false;
    return SafeArea(
      child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 460),
            child: AppPanel(
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch,
                  mainAxisSize: MainAxisSize.min, children: [
                Icon(Icons.lock_outline_rounded,
                    size: 44, color: AppColors.primary),
                const SizedBox(height: 18),
                LText('vault.lockedView.text', textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.titleLarge),
                const SizedBox(height: 8),
                LText(_status['master_password_required'] == true
                    ? tr('vault.lockedView.text.item2')
                    : tr('vault.lockedView.text.item3'),
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodySmall),
                const SizedBox(height: 24),
                if (_busy) ...[
                  const LinearProgressIndicator(minHeight: 2),
                  const SizedBox(height: 16),
                ],
                if (_unlockMessage.isNotEmpty) AppNotice(_unlockMessage),
                if (_needsMasterPassword) ...[
                  AppFieldRow(label: tr('vault.fields.masterPasswordLabel'), child: TextField(
                    controller: _password,
                    focusNode: _passwordFocus,
                    autofocus: true,
                    obscureText: true,
                    enabled: !_busy,
                    autocorrect: false,
                    enableSuggestions: false,
                    decoration: InputDecoration(hintText: tr('vault.lockedView.text.item4'), prefixIcon: Icon(Icons.key_outlined)),
                    onSubmitted: (_) { if (!_busy) _unlock(); },
                  )),
                  const SizedBox(height: 14),
                  FilledButton.icon(onPressed: _busy ? null : _unlock,
                      icon: const Icon(Icons.lock_open_rounded),
                      label: const LText('vault.actions.unlock')),
                  if (canUseBiometrics)
                    TextButton.icon(onPressed: _busy ? null : _unlockTouchId,
                        icon: const Icon(Icons.fingerprint_rounded),
                        label: const LText('vault.lockedView.text.item5')),
                ] else ...[
                  FilledButton.icon(onPressed: _busy ? null : _unlockTouchId,
                      icon: const Icon(Icons.fingerprint_rounded),
                      label: const LText('vault.actions.unlockBiometric')),
                  TextButton(onPressed: _busy ? null : () {
                    setState(() => _showMasterPassword = true);
                    WidgetsBinding.instance.addPostFrameCallback((_) {
                      if (mounted && !_unlocked) _passwordFocus.requestFocus();
                    });
                  }, child: const LText('vault.actions.useMasterPassword')),
                ],
              ]),
            ),
          ),
        ),
      ),
    );
  }

  Widget _page(int index) {
    switch (index) {
      case 1:
        return CredentialsTab(
            key: ValueKey(AgentBridge.activePartitionId),
            unlocked: _unlocked, onUnlock: () => _selectPage(0));
      case 2:
        return ChromeSetupTab(
            extensionIdController: _chromeExtensionId, busy: _busy,
            active: _pageIndex == 2, onOpenSettings: () => _selectPage(5));
      case 3:
        return SecurityCenterTab(
          unlocked: _unlocked,
          onUnlock: () => _selectPage(0),
          onVaultSwitched: () {
            _onVaultLockedExternally();
            _refreshStatus();
          },
        );
      case 4:
        return DiagnosticsTab(
            active: _pageIndex == 4,
            busy: _busy,
            onRestartAgent: _restartAgent,
            onRelaunchApp: _relaunchApp,
            onOpenSettings: () => _selectPage(5));
      case 6:
        return ShortcutsPage(active: _pageIndex == 6, busy: _busy);
      case 7:
        return const WebDavSyncPage();
      case 8:
        return const PartitionManagementPage();
      case 5:
        return SettingsPage(
            active: _pageIndex == 5,
            busy: _busy,
            onConfigureSsh: _unlocked ? _appendSshIdentityAgent : null,
            onRemoveSsh: _removeSshIdentityAgent,
            onOpenVault: _openVaultDir,
            onSaved: () async {
              await AppPresentation.instance.load();
              await WebDavSync.instance.refresh();
              _chromeExtensionId.text = await AgentBridge.getChromeExtensionId();
              await _refreshStatus();
            });
      default:
        return _vaultOverview();
    }
  }

  Widget _vaultOverview() {
    return AbsorbPointer(
      absorbing: _busy,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(24, 6, 24, 24),
        children: [
          AppPanel(
            child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Container(
                      padding: const EdgeInsets.all(15),
                      decoration: BoxDecoration(
                          color: AppColors.primary.withValues(alpha: 0.08),
                          borderRadius: BorderRadius.circular(16)),
                      child: Icon(
                          _unlocked
                              ? Icons.shield_outlined
                              : Icons.lock_outline_rounded,
                          size: 30,
                          color: AppColors.primary),
                    ),
                    const SizedBox(width: 18),
                    Expanded(
                        child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                          LText(
                              _unlocked
                                  ? tr('vault.vaultOverview.text')
                                  : (_vaultExists ? tr('vault.vaultOverview.text.item2') : tr('vault.vaultOverview.text.item3')),
                              style: Theme.of(context).textTheme.titleLarge),
                          const SizedBox(height: 7),
                          LText(
                              _unlocked
                                  ? tr('vault.vaultOverview.text.item4')
                                  : (_vaultExists
                                      ? (_status['master_password_required'] == true
                                          ? tr('vault.vaultOverview.text.item5')
                                          : tr('vault.vaultOverview.text.item6'))
                                      : tr('vault.vaultOverview.text.item7')),
                              style: Theme.of(context).textTheme.bodySmall),
                        ])),
                  ]),
                  if ((_status['local_unlock_notice']?.toString() ?? '').isNotEmpty)
                    AppNotice(_status['local_unlock_notice'].toString()),
                  const SizedBox(height: 22),
                  if (!_unlocked) ...[
                    if (!_vaultExists) ...[
                      AppFieldRow(label: tr('vault.syncHost.label'), help: tr('vault.syncHost.help'), child: TextField(
                        controller: _syncHostName,
                        maxLength: 128,
                        decoration: InputDecoration(prefixIcon: const Icon(Icons.computer_outlined)),
                      )),
                      const SizedBox(height: 14),
                    ],
                    AppFieldRow(label: tr('vault.fields.masterPassword'), child: TextField(
                      controller: _password,
                      obscureText: true,
                      decoration: InputDecoration(prefixIcon: Icon(Icons.key_outlined)),
                      onSubmitted: (_) {
                        if (!_busy) {
                          if (_vaultExists) {
                            _unlock();
                          } else {
                            _createVault();
                          }
                        }
                      },
                    )),
                    const SizedBox(height: 14),
                    Wrap(spacing: 10, runSpacing: 10, children: [
                      FilledButton.icon(
                          onPressed: _vaultExists && _status['local_unlock_configured'] == true &&
                                  _status['master_password_required'] == false
                              ? _unlockTouchId : (_vaultExists ? _unlock : _createVault),
                          icon: Icon(_vaultExists
                              ? Icons.lock_open_rounded
                              : Icons.add_rounded),
                          label: LText(!_vaultExists ? tr('vault.createVault.text.item2') :
                              (_status['local_unlock_configured'] == true && _status['master_password_required'] == false
                                  ? tr('vault.actions.unlockBiometric') : tr('vault.vaultOverview.text.item8')))),
                      if (_vaultExists && _status['local_unlock_configured'] == true &&
                          _status['master_password_required'] == false)
                        OutlinedButton.icon(
                            onPressed: _unlock,
                            icon: const Icon(Icons.key_outlined),
                            label: const LText('vault.actions.useMasterPassword')),
                      TextButton(
                          onPressed: _openVaultDir,
                          child: const LText('vault.vaultOverview.text.item9')),
                    ]),
                  ] else ...[
                    Row(children: [
                      const Icon(Icons.computer_outlined, size: 20),
                      const SizedBox(width: 10),
                      Expanded(child: LText('sync.host.local', args: {
                        'name': _status['sync_host_name'] ?? ''})),
                      TextButton.icon(onPressed: _busy ? null : _editSyncHostName,
                          icon: const Icon(Icons.edit_outlined, size: 16),
                          label: const LText('common.edit')),
                    ]),
                    const SizedBox(height: 14),
                    Wrap(spacing: 10, runSpacing: 10, children: [
                      FilledButton.icon(
                          onPressed: () => _selectPage(1),
                          icon: const Icon(Icons.key_outlined),
                          label: const LText('vault.vaultOverview.text.item10')),
                      OutlinedButton.icon(
                          onPressed: () => _selectPage(2),
                          icon: const Icon(Icons.language_rounded),
                          label: const LText('vault.vaultOverview.text.item11')),
                      TextButton(
                          onPressed: () => _selectPage(3),
                          child: const LText('vault.vaultOverview.text.item12')),
                    ]),
                  ],
                ]),
          ),
          const SizedBox(height: 16),
          LayoutBuilder(builder: (context, constraints) {
            final cards = [
              _overviewMetric(
                  Icons.dns_outlined, tr('vault.vaultOverview.text.item13'), tr('vault.vaultOverview.text.item14'), tr('vault.vaultOverview.text.item15')),
              _overviewMetric(
                  Icons.timer_outlined,
                  tr('vault.vaultOverview.text.item16'),
                  tr('vault.status.idleMinutes', args: {'minutes': ((_status['idle_timeout_sec'] as num?)?.toInt() ?? 300) ~/ 60}),
                  tr('vault.vaultOverview.text.item18')),
            ];
            if (constraints.maxWidth < 520)
              return Column(
                  children: [cards[0], const SizedBox(height: 12), cards[1]]);
            return Row(children: [
              Expanded(child: cards[0]),
              const SizedBox(width: 16),
              Expanded(child: cards[1])
            ]);
          }),
          const SizedBox(height: 16),
          AppPanel(
            title: tr('vaultTools.maintenance.title'),
            subtitle: tr('vaultTools.maintenance.help'),
            icon: Icons.folder_open_outlined,
            child: Wrap(spacing: 10, runSpacing: 10, children: [
              OutlinedButton(onPressed: _busy ? null : _openVaultDir,
                child: const LText('vaultTools.maintenance.switch')),
              for (final tool in VaultTransferTool.values)
                if (_unlocked || tool == VaultTransferTool.importJson)
                  OutlinedButton(onPressed: _busy || (_pendingRecoveryKey.isNotEmpty &&
                      (tool == VaultTransferTool.importJson || tool == VaultTransferTool.resetRecovery)) ? null : () => _run(tr(tool.label), () async {
                    await showVaultTransferTool(context, tool, onRecoveryKey: _retainRecoveryKey);
                    await _refreshStatus();
                  }), child: LText(tool.label)),
            ]),
          ),
          const SizedBox(height: 16),
          if (_unlocked) ...[
            AppPanel(
              title: tr('vault.vaultOverview.title'),
              subtitle: tr('vault.vaultOverview.description'),
              icon: Icons.password_rounded,
              child: Column(children: [
                AppFieldRow(label: tr('vault.vaultOverview.text.item19'), child: TextField(
                    controller: _password,
                    enabled: !_busy,
                    obscureText: true,
                    autocorrect: false, enableSuggestions: false, enableIMEPersonalizedLearning: false,
                    decoration: InputDecoration())),
                const SizedBox(height: 12),
                AppFieldRow(label: tr('vault.vaultOverview.text.item20'), child: TextField(
                    controller: _newPassword,
                    enabled: !_busy,
                    obscureText: true,
                    autocorrect: false, enableSuggestions: false, enableIMEPersonalizedLearning: false,
                    decoration:
                        InputDecoration())),
                const SizedBox(height: 12),
                AppFieldRow(label: tr('vault.changePassword.confirm'), child: TextField(
                    controller: _confirmNewPassword, enabled: !_busy, obscureText: true,
                    autocorrect: false, enableSuggestions: false, enableIMEPersonalizedLearning: false,
                    decoration: const InputDecoration())),
                const SizedBox(height: 14),
                Align(
                    alignment: Alignment.centerLeft,
                    child: Wrap(spacing: 10, runSpacing: 10, children: [
                      OutlinedButton(
                          onPressed: _busy ? null : _changePassword,
                          child: const LText('vault.vaultOverview.text.item21')),
                    ])),
              ]),
            ),
            const SizedBox(height: 16),
            AppPanel(
              title: tr('vault.vaultOverview.text.item22'),
              subtitle: tr('vault.backup.help'),
              icon: Icons.file_download_outlined,
              child: Align(alignment: Alignment.centerLeft, child: OutlinedButton.icon(
                onPressed: _busy ? null : _exportOvb, icon: const Icon(Icons.file_download_outlined),
                label: const LText('vault.vaultOverview.text.item22'))),
            ),
            const SizedBox(height: 16),
          ],
          Card(
              child: ExpansionTile(
            shape: const Border(),
            collapsedShape: const Border(),
            leading:
                Icon(Icons.restore_rounded, color: AppColors.primary),
            title: const LText('vault.vaultOverview.text.item23'),
            subtitle: const LText('vault.vaultOverview.text.item24'),
            childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
            children: [
              if (_unlocked) AppNotice(tr('vault.vaultOverview.text.item25')),
              AppFieldRow(label: tr('vault.vaultOverview.text.item26'), child: TextField(
                  controller: _recoveryPassword,
                  obscureText: true,
                  decoration: InputDecoration())),
              const SizedBox(height: 12),
              AppFieldRow(label: tr('vault.fields.recoveryKey'), child: TextField(
                  controller: _recoveryKey,
                  obscureText: true,
                  decoration: InputDecoration())),
              const SizedBox(height: 14),
              Align(
                  alignment: Alignment.centerLeft,
                  child: Wrap(spacing: 10, runSpacing: 10, children: [
                    OutlinedButton(
                        onPressed: () => _recoverOvb(useRecovery: false),
                        child: const LText('vault.vaultOverview.text.item27')),
                    OutlinedButton(
                        onPressed: () => _recoverOvb(useRecovery: true),
                        child: const LText('vault.vaultOverview.text.item28')),
                  ])),
            ],
          )),
          const SizedBox(height: 16),
          Card(
              child: ExpansionTile(
            shape: const Border(),
            collapsedShape: const Border(),
            leading: const Icon(Icons.info_outline_rounded),
            title: const LText('vault.vaultOverview.text.item29'),
            subtitle: LText(
                'vault.status.memoryBuild', args: {'memory': formatResidentMemory(_memoryBytes), 'build': kCredPivotBuildStamp}),
            childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
            children: [
              Align(
                  alignment: Alignment.centerLeft,
                  child: SelectableText(_log,
                      style: const TextStyle(
                          fontSize: 12, fontFamily: 'monospace', height: 1.6)))
            ],
          )),
        ],
      ),
    );
  }

  Widget _overviewMetric(
          IconData icon, String title, String value, String caption) =>
      AppPanel(
        child: Row(children: [
          Icon(icon, size: 24, color: AppColors.primary),
          const SizedBox(width: 16),
          Expanded(
              child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                LText(title, style: Theme.of(context).textTheme.bodySmall),
                const SizedBox(height: 4),
                Text(value, style: Theme.of(context).textTheme.titleLarge),
                const SizedBox(height: 4),
                LText(caption, style: Theme.of(context).textTheme.bodySmall),
              ])),
        ]),
      );

  Future<void> _appendSshIdentityAgent() async {
    await _run('SSH', () async {
      final r = await AgentBridge.appendSshIdentityAgent();
      _appendLog('${r['message']}\n${r['configPath'] ?? ''}');
    });
  }

  Future<void> _removeSshIdentityAgent() async {
    await _run('SSH', () async {
      final r = await AgentBridge.removeSshIdentityAgent();
      _appendLog(r['message']?.toString() ?? r.toString());
    });
  }
}
