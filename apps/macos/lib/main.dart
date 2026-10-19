import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'agent_bridge.dart';
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
    super.dispose();
  }

  Future<void> _run(String label, Future<void> Function() action) async {
    setState(() => _busy = true);
    try {
      await action();
    } on AgentException catch (e) {
      _appendLog('$label 失败: ${e.message}');
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
    _memoryBytes = await AgentBridge.residentMemoryBytes();
    setState(() {
      _status = payload;
      _log = const JsonEncoder.withIndent('  ').convert(payload);
    });
  }

  Future<void> _bootstrap() async {
    try {
      await AgentBridge.startAgent();
      await AgentBridge.installChromeHost();
      await _refreshStatus();
    } catch (e) {
      _appendLog('错误: $e');
    }
  }

  Future<void> _createVault() async {
    final pw = _password.text;
    if (pw.length < 8) {
      _appendLog('主密码至少 8 位');
      return;
    }
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
      final ok = await AgentBridge.unlockWithTouchId();
      if (!ok) {
        _appendLog('Touch ID 未通过（扩展演示门槛，完整解密仍需主密码）');
        return;
      }
      await _refreshStatus();
    });
  }

  Future<void> _lock() async {
    await _run('锁定', () async {
      await AgentBridge.lockVault();
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
    return Scaffold(
      appBar: AppBar(
        title: const Text('CredPivot M1'),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: Center(child: Text('Vault: $vaultLabel')),
          ),
        ],
      ),
      body: AbsorbPointer(
        absorbing: _busy,
        child: Padding(
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
              const SizedBox(height: 12),
              Wrap(
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
                ],
              ),
              const Padding(
                padding: EdgeInsets.only(top: 8),
                child: Text(
                  'M1：真实 CPVC1 + SQLCipher（~/.credpivot/vault）。Chrome/SSH 凭据仍为会话内演示，业务入库在 M2。',
                  style: TextStyle(fontSize: 12, color: Colors.black54),
                ),
              ),
            ],
          ),
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

  Future<void> _removeSshIdentityAgent() async {
    await _run('SSH', () async {
      final r = await AgentBridge.removeSshIdentityAgent();
      _appendLog(r['message']?.toString() ?? r.toString());
    });
  }
}
