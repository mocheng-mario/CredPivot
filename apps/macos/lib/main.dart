import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';

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

void main() {
  WidgetsFlutterBinding.ensureInitialized();
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
  String _log = '启动中…';
  String _operationMessage = '';
  final _password = TextEditingController();
  final _passwordFocus = FocusNode();
  final _newPassword = TextEditingController();
  final _recoveryKey = TextEditingController();
  // 备份可能来自其他保险库，恢复密码不与当前主密码共用输入状态。
  final _recoveryPassword = TextEditingController();
  final _chromeExtensionId = TextEditingController();
  Map<String, dynamic> _status = {};
  int _memoryBytes = 0;
  bool _busy = false;
  bool _initializing = true;
  bool _bootstrapping = false;
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
  int _statusRequestGeneration = 0;
  int _lastVaultLockGen = 0;
  String? _lastDataRevision;

  @override
  void initState() {
    super.initState();
    AppPresentation.instance.addListener(_onPresentationChanged);
    installVaultLockCoordinator(_onVaultLockedExternally);
    AgentBridge.onShortcut = _handleShortcut;
    AgentBridge.installVaultLockHandler(notifyVaultLocked);
    _vaultLockPoll = Timer.periodic(const Duration(seconds: 2), (_) => _pollVaultLockGeneration());
    _bootstrap();
  }

  void _onPresentationChanged() {
    // 系统外观及语言切换后，重新计算页面中已解析的颜色和输入框文案。
    if (mounted) setState(() {});
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
          _vaultExists != (payload['vault_exists'] == true)) {
        await _refreshStatus();
      }
      _lastVaultLockGen = gen;
    } catch (_) {
      // 失去后台状态时先遮住内容，不能继续展示上一次解锁会话的数据。
      if (mounted && _unlocked) notifyVaultLocked();
    } finally {
      _vaultLockPolling = false;
    }
  }

  void _onVaultLockedExternally() {
    _statusRequestGeneration++;
    clearSensitiveAuthGrace();
    _password.clear();
    _recoveryKey.clear();
    _recoveryPassword.clear();
    _newPassword.clear();
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

  @override
  void dispose() {
    AgentBridge.onShortcut = null;
    AppPresentation.instance.removeListener(_onPresentationChanged);
    _vaultLockPoll?.cancel();
    _password.dispose();
    _passwordFocus.dispose();
    _newPassword.dispose();
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
      _appendLog('$label 失败: $msg');
      if (AgentBridge.isAgentNotStartedError(e)) {
        _showAgentNotStartedHint();
      }
    } catch (_) {
      _appendLog('$label 失败，请查看「诊断」页的事件记录');
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
    _memoryBytes = memoryBytes;
    if (payload['unlocked'] != true) {
      clearSensitiveAuthGrace();
      if (_unlocked) {
        vaultRootNavigatorKey.currentState?.popUntil((route) => route.isFirst);
        _password.clear();
        _newPassword.clear();
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
  }

  Future<void> _bootstrap() async {
    if (_bootstrapping || !mounted) return;
    _bootstrapping = true;
    setState(() => _initializing = true);
    try {
      if (!await AgentBridge.ensureAgentReady()) {
        _appendLog(
          '后台 Agent 未就绪。可点「重启 Agent」或「重新打开应用」。'
          ' 若从旧构建启动，请先 make macos-build-debug 后重开。',
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
        _appendLog('浏览器连接初始化未完成，解锁后可在「浏览器连接」页修复。');
      }
      await _refreshStatus();
    } catch (_) {
      _appendLog('初始化失败，请查看「诊断」页的事件记录');
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

  Future<void> _showAgentNotStartedHint() {
    if (!mounted) return Future.value();
    return showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const LText('后台未启动'),
        content: const LText(
          '凭据后台（Agent）未运行，无法创建/解锁保险库。\n\n'
          '请先尝试「重启 Agent」；仍失败请「重新打开应用」或 Cmd+Q 完全退出后重开。',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const LText('知道了')),
          TextButton(
            onPressed: () {
              Navigator.pop(ctx);
              _restartAgent();
            },
            child: const LText('重启 Agent'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.pop(ctx);
              AgentBridge.relaunchApp();
            },
            child: const LText('重新打开应用'),
          ),
        ],
      ),
    );
  }

  Future<void> _restartAgent() async {
    await _run('重启 Agent', () async {
      final ok = await AgentBridge.restartAgent();
      if (!ok) {
        _appendLog('重启 Agent 失败，请重新打开应用');
        return;
      }
      await _refreshStatus();
      _appendLog('Agent 已重启');
    });
  }

  Future<void> _relaunchApp() async {
    await AgentBridge.relaunchApp();
  }

  Future<bool> _guardAgent(String actionLabel) async {
    final ok = await AgentBridge.ensureAgentReady();
    if (!ok) {
      _appendLog('$actionLabel 前检查：Agent 未就绪');
      await _showAgentNotStartedHint();
    }
    return ok;
  }

  Future<void> _createVault() async {
    final pw = _password.text;
    if (pw.length < 8) {
      _appendLog('主密码至少 8 位');
      return;
    }
    if (!await _guardAgent('创建保险库')) return;
    await _run('创建保险库', () async {
      final recovery = await AgentBridge.vaultCreate(pw);
      await _refreshStatus();
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const LText('请保存恢复密钥'),
          content: SelectableText(recovery),
          actions: [
            TextButton(
              onPressed: () async {
                await AgentBridge.copyConcealed(recovery);
                if (ctx.mounted) {
                  ScaffoldMessenger.of(ctx).showSnackBar(const SnackBar(content: LText('已复制')));
                }
              },
              child: const LText('复制'),
            ),
            FilledButton(onPressed: () => Navigator.pop(ctx), child: const LText('已记录')),
          ],
        ),
      );
    });
  }

  Future<void> _unlock() async {
    if (_busy) return;
    if (_password.text.isEmpty) {
      setState(() => _unlockMessage = '请输入保险库主密码');
      _passwordFocus.requestFocus();
      return;
    }
    setState(() => _unlockMessage = '');
    if (!await _guardAgent('解锁')) return;
    await _run('解锁', () async {
      final ok = await AgentBridge.unlockWithPassword(_password.text);
      if (!mounted) return;
      if (!ok) {
        _password.clear();
        setState(() => _unlockMessage = '主密码不正确，请重新输入');
        _passwordFocus.requestFocus();
        return;
      }
      _password.clear();
      await _refreshStatus();
    });
    if (mounted && !_unlocked && _unlockMessage.isEmpty) {
      setState(() => _unlockMessage = '解锁未完成，请重试');
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
          _unlockMessage = '指纹解锁未完成，可以输入主密码或重试指纹';
        });
        await _refreshStatus();
        return;
      }
      await _refreshStatus();
    });
    if (mounted && !_unlocked && _unlockMessage.isEmpty) {
      setState(() {
        _showMasterPassword = true;
        _unlockMessage = '解锁未完成，请输入主密码或重试';
      });
    }
  }

  Future<void> _lock() async {
    await _run('锁定', () async {
      await AgentBridge.lockVault();
      clearSensitiveAuthGrace();
      await _refreshStatus();
    });
  }

  Future<void> _changePassword() async {
    if (_newPassword.text.length < 8) {
      _appendLog('新密码至少 8 位');
      return;
    }
    if (!await requireTouchId(context, reason: '更改保险库主密码')) return;
    await _run('改密', () async {
      await AgentBridge.vaultChangePassword(_password.text, _newPassword.text);
      _password.clear();
      _newPassword.clear();
      await _refreshStatus();
      _appendLog('主密码已更新');
    });
  }

  Future<void> _exportOvb() async {
    if (!await requireTouchId(context, reason: '导出保险库备份')) return;
    final path = await AgentBridge.pickSaveFile();
    if (path == null) return;
    await _run('导出 OVB', () async {
      await AgentBridge.vaultExportOvb(path, _password.text);
      _password.clear();
      await _refreshStatus();
      _appendLog('已导出: $path');
    });
  }

  Future<void> _recoverOvb({required bool useRecovery}) async {
    final ovb = await AgentBridge.pickOpenFile();
    if (ovb == null) return;
    final target = await AgentBridge.pickDirectory();
    if (target == null) return;
    await _run('恢复 OVB', () async {
      await AgentBridge.vaultRecoverOvb(
        ovbPath: ovb,
        targetDir: target,
        password: useRecovery ? null : _recoveryPassword.text,
        recoveryKey: useRecovery ? _recoveryKey.text.trim() : null,
      );
      await AgentBridge.lockVault();
      await AgentBridge.vaultOpenDir(target);
      _onVaultLockedExternally();
      await _refreshStatus();
      _appendLog('已恢复到: $target。工作库已切换，请重新解锁。');
    });
  }

  Future<void> _openVaultDir() async {
    final dir = await AgentBridge.pickDirectory();
    if (dir == null) return;
    await _run('打开目录', () async {
      await AgentBridge.lockVault();
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

  @override
  Widget build(BuildContext context) {
    final vaultLabel = !_vaultExists ? '未创建' : (_unlocked ? '已解锁' : '已锁定');
    return AgentReadinessScope(
      builder: (context, agentReady) => Scaffold(
        // 首次创建/恢复保险库仍需可用；已有保险库锁定后只显示解锁入口。
        body: _initializing
            ? const Center(child: CircularProgressIndicator())
            : !agentReady || _status.isEmpty
                ? _connectionUnavailable()
                : _vaultExists && !_unlocked
                    ? _lockedView()
                    : SafeArea(
          child: LayoutBuilder(builder: (context, constraints) {
            return Row(children: [
              AppSidebar(
                selectedIndex: _pageIndex,
                onSelected: _selectPage,
                compact: constraints.maxWidth < 960,
                agentReady: agentReady,
                unlocked: agentReady && _unlocked,
                footer:
                    '内存 ${formatResidentMemory(_memoryBytes)}\nBuild $kCredPivotBuildStamp',
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
                              LText(appPageTitles[_pageIndex],
                                  style: Theme.of(context)
                                      .textTheme
                                      .headlineMedium),
                              const SizedBox(height: 4),
                              LText(appPageDescriptions[_pageIndex],
                                  style: Theme.of(context).textTheme.bodySmall),
                            ])),
                        const SizedBox(width: 12),
                        if (agentReady && _unlocked) ...[
                          IconButton(tooltip: tr('搜索全部凭据'), onPressed: _busy ? null : () => _handleShortcut('search'), icon: const Icon(Icons.search_rounded)),
                          IconButton(tooltip: tr('新建记录'), onPressed: _busy ? null : () => _handleShortcut('new'), icon: const Icon(Icons.add_rounded)),
                        ],
                        AppStatusBadge(agentReady ? vaultLabel : '未连接',
                            color: agentReady && _unlocked
                                ? AppColors.green
                                : AppColors.muted),
                        if (agentReady && _unlocked) ...[
                          const SizedBox(width: 8),
                          IconButton(
                              onPressed: _busy ? null : _lock,
                              tooltip: tr('锁定保险库'),
                              icon: const Icon(Icons.lock_outline_rounded)),
                        ],
                      ]),
                    ),
                    if (_busy)
                      const LinearProgressIndicator(minHeight: 2)
                    else
                      const SizedBox(height: 2),
                    if (_status['settings_valid'] == false)
                      const Padding(
                        padding: EdgeInsets.symmetric(horizontal: 24),
                        child: AppNotice('配置文件无效，当前使用保守设置。请前往「设置」修复或恢复默认。'),
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
            title: '正在等待本机后台',
            subtitle: '确认保险库状态后才能继续使用。',
            icon: Icons.lock_outline_rounded,
            child: Wrap(spacing: 10, runSpacing: 10, children: [
              FilledButton(onPressed: _busy ? null : _bootstrap,
                  child: const LText('重新连接')),
              OutlinedButton(onPressed: _busy ? null : () async {
                await _restartAgent();
                if (mounted) await _bootstrap();
              }, child: const LText('重启后台')),
              TextButton(onPressed: _busy ? null : _relaunchApp,
                  child: const LText('重新打开应用')),
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
                LText('CredPivot 已锁定', textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.titleLarge),
                const SizedBox(height: 8),
                LText(_status['master_password_required'] == true
                    ? '首次解锁或已达到验证期限，请输入保险库主密码。'
                    : '完成身份验证后，才能访问凭据、设置和其他功能。',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodySmall),
                const SizedBox(height: 24),
                if (_busy) ...[
                  const LinearProgressIndicator(minHeight: 2),
                  const SizedBox(height: 16),
                ],
                if (_unlockMessage.isNotEmpty) AppNotice(_unlockMessage),
                if (_needsMasterPassword) ...[
                  TextField(
                    controller: _password,
                    focusNode: _passwordFocus,
                    autofocus: true,
                    obscureText: true,
                    enabled: !_busy,
                    autocorrect: false,
                    enableSuggestions: false,
                    decoration: InputDecoration(
                        labelText: tr('保险库主密码'),
                        hintText: tr('不是 Mac 登录密码'),
                        prefixIcon: Icon(Icons.key_outlined)),
                    onSubmitted: (_) { if (!_busy) _unlock(); },
                  ),
                  const SizedBox(height: 14),
                  FilledButton.icon(onPressed: _busy ? null : _unlock,
                      icon: const Icon(Icons.lock_open_rounded),
                      label: const LText('解锁')),
                  if (canUseBiometrics)
                    TextButton.icon(onPressed: _busy ? null : _unlockTouchId,
                        icon: const Icon(Icons.fingerprint_rounded),
                        label: const LText('重试指纹验证')),
                ] else ...[
                  FilledButton.icon(onPressed: _busy ? null : _unlockTouchId,
                      icon: const Icon(Icons.fingerprint_rounded),
                      label: const LText('指纹解锁')),
                  TextButton(onPressed: _busy ? null : () {
                    setState(() => _showMasterPassword = true);
                    WidgetsBinding.instance.addPostFrameCallback((_) {
                      if (mounted && !_unlocked) _passwordFocus.requestFocus();
                    });
                  }, child: const LText('使用主密码')),
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
      case 5:
        return SettingsPage(
            active: _pageIndex == 5,
            busy: _busy,
            onConfigureSsh: _unlocked ? _appendSshIdentityAgent : null,
            onRemoveSsh: _removeSshIdentityAgent,
            onOpenVault: _openVaultDir,
            onSaved: () async {
              await AppPresentation.instance.load();
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
                                  ? '一切就绪，安心使用'
                                  : (_vaultExists ? '欢迎回来' : '你的安全空间，从这里开始'),
                              style: Theme.of(context).textTheme.titleLarge),
                          const SizedBox(height: 7),
                          LText(
                              _unlocked
                                  ? '保险库已解锁，可以管理凭据或使用浏览器填充。'
                                  : (_vaultExists
                                      ? (_status['master_password_required'] == true
                                          ? '首次使用或达到设置中的验证期限，请输入主密码。'
                                          : '优先使用指纹解锁，也可以输入主密码。')
                                      : '设置至少 8 位的主密码，并妥善保管创建后的恢复密钥。'),
                              style: Theme.of(context).textTheme.bodySmall),
                        ])),
                  ]),
                  if ((_status['local_unlock_notice']?.toString() ?? '').isNotEmpty)
                    AppNotice(_status['local_unlock_notice'].toString()),
                  const SizedBox(height: 22),
                  if (!_unlocked) ...[
                    TextField(
                      controller: _password,
                      obscureText: true,
                      decoration: InputDecoration(
                          labelText: tr('主密码'),
                          prefixIcon: Icon(Icons.key_outlined)),
                      onSubmitted: (_) {
                        if (!_busy) {
                          if (_vaultExists) {
                            _unlock();
                          } else {
                            _createVault();
                          }
                        }
                      },
                    ),
                    const SizedBox(height: 14),
                    Wrap(spacing: 10, runSpacing: 10, children: [
                      FilledButton.icon(
                          onPressed: _vaultExists && _status['local_unlock_configured'] == true &&
                                  _status['master_password_required'] == false
                              ? _unlockTouchId : (_vaultExists ? _unlock : _createVault),
                          icon: Icon(_vaultExists
                              ? Icons.lock_open_rounded
                              : Icons.add_rounded),
                          label: LText(!_vaultExists ? '创建保险库' :
                              (_status['local_unlock_configured'] == true && _status['master_password_required'] == false
                                  ? '指纹解锁' : '主密码解锁'))),
                      if (_vaultExists && _status['local_unlock_configured'] == true &&
                          _status['master_password_required'] == false)
                        OutlinedButton.icon(
                            onPressed: _unlock,
                            icon: const Icon(Icons.key_outlined),
                            label: const LText('使用主密码')),
                      TextButton(
                          onPressed: _openVaultDir,
                          child: const LText('打开已有保险库')),
                    ]),
                  ] else ...[
                    Wrap(spacing: 10, runSpacing: 10, children: [
                      FilledButton.icon(
                          onPressed: () => _selectPage(1),
                          icon: const Icon(Icons.key_outlined),
                          label: const LText('管理凭据')),
                      OutlinedButton.icon(
                          onPressed: () => _selectPage(2),
                          icon: const Icon(Icons.language_rounded),
                          label: const LText('连接浏览器')),
                      TextButton(
                          onPressed: () => _selectPage(3),
                          child: const LText('备份与恢复')),
                    ]),
                  ],
                ]),
          ),
          const SizedBox(height: 16),
          LayoutBuilder(builder: (context, constraints) {
            final cards = [
              _overviewMetric(
                  Icons.dns_outlined, '存储方式', '本机加密', '数据保存在当前保险库目录'),
              _overviewMetric(
                  Icons.timer_outlined,
                  '自动锁定',
                  '${((_status['idle_timeout_sec'] as num?)?.toInt() ?? 300) ~/ 60} 分钟',
                  '空闲后自动锁定保险库'),
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
          if (_unlocked) ...[
            AppPanel(
              title: '主密码与导出',
              subtitle: '导出需要再次输入当前主密码；更改主密码时同时填写新密码。',
              icon: Icons.password_rounded,
              child: Column(children: [
                TextField(
                    controller: _password,
                    obscureText: true,
                    decoration: InputDecoration(labelText: tr('当前主密码'))),
                const SizedBox(height: 12),
                TextField(
                    controller: _newPassword,
                    obscureText: true,
                    decoration:
                        InputDecoration(labelText: tr('新主密码（至少 8 位）'))),
                const SizedBox(height: 14),
                Align(
                    alignment: Alignment.centerLeft,
                    child: Wrap(spacing: 10, runSpacing: 10, children: [
                      OutlinedButton(
                          onPressed: _changePassword,
                          child: const LText('更改主密码')),
                      OutlinedButton.icon(
                          onPressed: _exportOvb,
                          icon: const Icon(Icons.file_download_outlined),
                          label: const LText('导出 OVB 备份')),
                    ])),
              ]),
            ),
            const SizedBox(height: 16),
          ],
          Card(
              child: ExpansionTile(
            shape: const Border(),
            collapsedShape: const Border(),
            leading:
                Icon(Icons.restore_rounded, color: AppColors.primary),
            title: const LText('从备份恢复'),
            subtitle: const LText('使用主密码或恢复密钥打开 OVB'),
            childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
            children: [
              if (_unlocked) const AppNotice('恢复会切换当前保险库，请先保存正在编辑的内容。'),
              TextField(
                  controller: _recoveryPassword,
                  obscureText: true,
                  decoration: InputDecoration(labelText: tr('备份的主密码'))),
              const SizedBox(height: 12),
              TextField(
                  controller: _recoveryKey,
                  obscureText: true,
                  decoration: InputDecoration(labelText: tr('恢复密钥'))),
              const SizedBox(height: 14),
              Align(
                  alignment: Alignment.centerLeft,
                  child: Wrap(spacing: 10, runSpacing: 10, children: [
                    OutlinedButton(
                        onPressed: () => _recoverOvb(useRecovery: false),
                        child: const LText('使用主密码恢复')),
                    OutlinedButton(
                        onPressed: () => _recoverOvb(useRecovery: true),
                        child: const LText('使用恢复密钥恢复')),
                  ])),
            ],
          )),
          const SizedBox(height: 16),
          Card(
              child: ExpansionTile(
            shape: const Border(),
            collapsedShape: const Border(),
            leading: const Icon(Icons.info_outline_rounded),
            title: const LText('运行信息'),
            subtitle: LText(
                '内存 ${formatResidentMemory(_memoryBytes)} · Build $kCredPivotBuildStamp'),
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
