import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';
import 'build_stamp.dart';
import 'credentials_page.dart';
import 'touch_id_gate.dart';
import 'memory_format.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const CredPivotApp());
}

class CredPivotApp extends StatelessWidget {
  const CredPivotApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CredPivot',
      theme: ThemeData(colorSchemeSeed: const Color(0xFF2F6FED), useMaterial3: true),
      home: const VaultHomePage(),
    );
  }
}

class VaultHomePage extends StatefulWidget {
  const VaultHomePage({super.key});

  @override
  State<VaultHomePage> createState() => _VaultHomePageState();
}

class _VaultHomePageState extends State<VaultHomePage> {
  String _log = '启动中…';
  final _password = TextEditingController();
  final _newPassword = TextEditingController();
  final _recoveryKey = TextEditingController();
  final _chromeExtensionId = TextEditingController();
  Map<String, dynamic> _status = {};
  int _memoryBytes = 0;
  bool _busy = false;

  bool get _vaultExists => _status['vault_exists'] == true;
  bool get _unlocked => _status['unlocked'] == true;

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  @override
  void dispose() {
    _password.dispose();
    _newPassword.dispose();
    _recoveryKey.dispose();
    _chromeExtensionId.dispose();
    super.dispose();
  }

  Future<void> _run(String label, Future<void> Function() action) async {
    setState(() => _busy = true);
    try {
      await action();
    } on AgentException catch (e) {
      final msg = AgentBridge.friendlyMessage(e);
      _appendLog('$label 失败: $msg');
      if (AgentBridge.isAgentNotStartedError(e)) {
        _showAgentNotStartedHint();
      }
    } catch (e) {
      _appendLog('$label 失败: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _appendLog(String line) {
    setState(() => _log = line);
  }

  Future<void> _refreshStatus() async {
    final raw = await AgentBridge.request({'type': 'status'});
    final payload = AgentBridge.payloadOf(raw);
    final chrome = await AgentBridge.chromeHostStatus();
    _memoryBytes = await AgentBridge.residentMemoryBytes();
    if (payload['unlocked'] != true) {
      clearSensitiveAuthGrace();
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
    try {
      await AgentBridge.startAgent();
      if (!await AgentBridge.ensureAgentReady()) {
        _appendLog(
          '后台 Agent 未就绪。可点「重启 Agent」或「重新打开应用」。'
          ' 若从旧构建启动，请先 make macos-build-debug 后重开。',
        );
      }
      _chromeExtensionId.text = await AgentBridge.getChromeExtensionId();
      if (_chromeExtensionId.text.isNotEmpty) {
        final r = await AgentBridge.installChromeHost(_chromeExtensionId.text);
        if (r['ok'] != true) {
          _appendLog('Chrome Host: ${r['message']}');
        }
      }
      if (_chromeExtensionId.text.trim().isEmpty) {
        _chromeExtensionId.text = 'kclmbggfjdokgcmgdofhhkpadklbjcii';
      }
      await _refreshStatus();
    } catch (e) {
      _appendLog('错误: $e');
    }
  }

  Future<void> _showAgentNotStartedHint() {
    if (!mounted) return Future.value();
    return showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('后台未启动'),
        content: const Text(
          '凭据后台（Agent）未运行，无法创建/解锁保险库。\n\n'
          '请先尝试「重启 Agent」；仍失败请「重新打开应用」或 Cmd+Q 完全退出后重开。',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('知道了')),
          TextButton(
            onPressed: () {
              Navigator.pop(ctx);
              _restartAgent();
            },
            child: const Text('重启 Agent'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.pop(ctx);
              AgentBridge.relaunchApp();
            },
            child: const Text('重新打开应用'),
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
          title: const Text('请保存恢复密钥'),
          content: SelectableText(recovery),
          actions: [
            TextButton(
              onPressed: () {
                Clipboard.setData(ClipboardData(text: recovery));
                ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('已复制')));
              },
              child: const Text('复制'),
            ),
            FilledButton(onPressed: () => Navigator.pop(ctx), child: const Text('已记录')),
          ],
        ),
      );
    });
  }

  Future<void> _unlock() async {
    if (!await _guardAgent('解锁')) return;
    await _run('解锁', () async {
      final ok = await AgentBridge.unlockWithPassword(_password.text);
      if (!ok) {
        _appendLog('解锁失败：主密码不正确');
        return;
      }
      await _refreshStatus();
    });
  }

  Future<void> _unlockTouchId() async {
    await _run('Touch ID', () async {
      final ok = await AgentBridge.unlockWithTouchId()
          .timeout(const Duration(seconds: 120), onTimeout: () => false);
      if (!ok) {
        _appendLog(
          'Touch ID 未通过（取消、未录入指纹或本机不支持时会出现）。'
          ' 写库/解密须用「主密码解锁」；Touch ID 仅作扩展操作门槛。',
        );
        return;
      }
      await _refreshStatus();
      if (_status['database_attached'] != true) {
        _appendLog(
          'Touch ID 已通过（会话门槛）。要挂载 SQLCipher 并保存密码，请再点「主密码解锁」。',
        );
      }
    });
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
    await _run('改密', () async {
      await AgentBridge.vaultChangePassword(_password.text, _newPassword.text);
      _password.text = _newPassword.text;
      _newPassword.clear();
      await _refreshStatus();
      _appendLog('主密码已更新（VMK 不变）');
    });
  }

  Future<void> _exportOvb() async {
    final path = await AgentBridge.pickSaveFile();
    if (path == null) return;
    await _run('导出 OVB', () async {
      await AgentBridge.vaultExportOvb(path, _password.text);
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
        password: useRecovery ? null : _password.text,
        recoveryKey: useRecovery ? _recoveryKey.text.trim() : null,
      );
      await AgentBridge.vaultOpenDir(target);
      await _refreshStatus();
      _appendLog('已恢复到并打开: $target');
    });
  }

  Future<void> _openVaultDir() async {
    final dir = await AgentBridge.pickDirectory();
    if (dir == null) return;
    await _run('打开目录', () async {
      await AgentBridge.vaultOpenDir(dir);
      await _refreshStatus();
    });
  }

  @override
  Widget build(BuildContext context) {
    final vaultLabel = !_vaultExists
        ? '未创建'
        : (_unlocked ? '已解锁' : '已锁定');
    final format = _status['format']?.toString() ?? 'm2';
    return DefaultTabController(
      length: 3,
      child: Scaffold(
      appBar: AppBar(
        title: Text('CredPivot ${format.toUpperCase()}'),
        bottom: const TabBar(tabs: [
          Tab(text: '保险库'),
          Tab(text: '凭据'),
          Tab(text: '安全中心'),
        ]),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 8),
            child: Center(
              child: Text(
                'Build: $kCredPivotBuildStamp',
                style: Theme.of(context).textTheme.labelSmall,
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: Center(child: Text('Vault: $vaultLabel')),
          ),
        ],
      ),
      body: TabBarView(
        children: [
          Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text('状态', style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 8),
              Expanded(
                flex: 2,
                child: SingleChildScrollView(child: Text(_log)),
              ),
              Text('常驻内存约 ${formatResidentMemory(_memoryBytes)}'),
              const SizedBox(height: 12),
              TextField(
                controller: _password,
                decoration: const InputDecoration(
                  labelText: '主密码',
                  hintText: '创建 / 解锁 / 导出 OVB 时使用',
                ),
                obscureText: true,
              ),
              if (_vaultExists && _unlocked) ...[
                const SizedBox(height: 8),
                TextField(
                  controller: _newPassword,
                  decoration: const InputDecoration(labelText: '新主密码（改密）'),
                  obscureText: true,
                ),
              ],
              const SizedBox(height: 8),
              TextField(
                controller: _recoveryKey,
                decoration: const InputDecoration(
                  labelText: '恢复密钥（仅 OVB 恢复）',
                ),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _chromeExtensionId,
                decoration: const InputDecoration(
                  labelText: 'Chrome 扩展 ID',
                  hintText: '例如 kclmbggfjdokgcmgdofhhkpadklbjcii',
                ),
              ),
              const SizedBox(height: 12),
              AbsorbPointer(
                absorbing: _busy,
                child: Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  if (!_vaultExists)
                    FilledButton(onPressed: _createVault, child: const Text('创建保险库')),
                  if (!_unlocked)
                    OutlinedButton(onPressed: _openVaultDir, child: const Text('打开已有目录')),
                  if (_vaultExists && !_unlocked) ...[
                    FilledButton(onPressed: _unlock, child: const Text('主密码解锁')),
                    FilledButton(onPressed: _unlockTouchId, child: const Text('Touch ID')),
                  ],
                  if (_unlocked) ...[
                    OutlinedButton(onPressed: _lock, child: const Text('锁定')),
                    OutlinedButton(onPressed: _changePassword, child: const Text('改主密码')),
                    OutlinedButton(onPressed: _exportOvb, child: const Text('导出 OVB')),
                  ],
                  OutlinedButton(
                    onPressed: () => _recoverOvb(useRecovery: false),
                    child: const Text('从 OVB 恢复（主密码）'),
                  ),
                  OutlinedButton(
                    onPressed: () => _recoverOvb(useRecovery: true),
                    child: const Text('从 OVB 恢复（恢复密钥）'),
                  ),
                  OutlinedButton(
                    onPressed: () => _registerLoginItem(true),
                    child: const Text('注册登录项'),
                  ),
                  OutlinedButton(
                    onPressed: () => _registerLoginItem(false),
                    child: const Text('取消登录项'),
                  ),
                  OutlinedButton(
                    onPressed: _unlocked ? _appendSshIdentityAgent : null,
                    child: const Text('SSH IdentityAgent'),
                  ),
                  OutlinedButton(onPressed: _removeSshIdentityAgent, child: const Text('撤销 SSH')),
                  OutlinedButton(onPressed: _installChromeHost, child: const Text('安装 Chrome Native Host')),
                  OutlinedButton(onPressed: _restartAgent, child: const Text('重启 Agent')),
                  OutlinedButton(onPressed: _relaunchApp, child: const Text('重新打开应用')),
                ],
              ),
              ),
              if (_busy)
                const Padding(
                  padding: EdgeInsets.only(top: 4),
                  child: Text('处理中…', style: TextStyle(fontSize: 12, color: Colors.black54)),
                ),
              const Padding(
                padding: EdgeInsets.only(top: 8),
                child: Text(
                  'M2：CPVC1 + SQLCipher 登录凭据已入库（须主密码解锁）。'
                  ' Chrome 需填写扩展 ID 并安装 Host；保存前请保持本 App 已启动 Agent。',
                  style: TextStyle(fontSize: 12, color: Colors.black54),
                ),
              ),
            ],
          ),
          ),
          CredentialsTab(unlocked: _unlocked),
          SecurityCenterTab(unlocked: _unlocked),
        ],
      ),
    ),
    );
  }

  Future<void> _registerLoginItem(bool enabled) async {
    await _run('登录项', () async {
      await AgentBridge.registerLoginItem(enabled);
      _appendLog(enabled ? '已注册登录项' : '已取消登录项');
    });
  }

  Future<void> _appendSshIdentityAgent() async {
    await _run('SSH', () async {
      final r = await AgentBridge.appendSshIdentityAgent();
      _appendLog('${r['message']}\n${r['configPath'] ?? ''}');
    });
  }

  Future<void> _installChromeHost() async {
    final id = _chromeExtensionId.text.trim();
    if (id.isEmpty) {
      _appendLog('请填写 Chrome 扩展 ID');
      return;
    }
    await _run('Chrome Host', () async {
      final r = await AgentBridge.installChromeHost(id);
      _appendLog('${r['message']}\n${r['manifest_path'] ?? ''}');
    });
  }

  Future<void> _removeSshIdentityAgent() async {
    await _run('SSH', () async {
      final r = await AgentBridge.removeSshIdentityAgent();
      _appendLog(r['message']?.toString() ?? r.toString());
    });
  }
}
