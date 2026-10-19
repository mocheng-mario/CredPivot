import 'dart:convert';

import 'package:flutter/material.dart';
import 'agent_bridge.dart';
import 'memory_format.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const CredPivotM0App());
}

class CredPivotM0App extends StatelessWidget {
  const CredPivotM0App({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CredPivot M0',
      theme: ThemeData(colorSchemeSeed: const Color(0xFF2F6FED), useMaterial3: true),
      home: const M0HomePage(),
    );
  }
}

class M0HomePage extends StatefulWidget {
  const M0HomePage({super.key});

  @override
  State<M0HomePage> createState() => _M0HomePageState();
}

class _M0HomePageState extends State<M0HomePage> {
  String _status = '启动中…';
  final _passwordController = TextEditingController(text: 'credpivot-m0');
  int _memoryBytes = 0;
  bool _unlocked = false;

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  Future<void> _refreshStatus() async {
    final raw = await AgentBridge.request({'type': 'status'});
    final payload = raw['payload'] as Map<String, dynamic>? ?? raw;
    _unlocked = payload['unlocked'] == true;
    _memoryBytes = await AgentBridge.residentMemoryBytes();
    setState(() {
      _status = const JsonEncoder.withIndent('  ').convert(payload);
    });
  }

  Future<void> _bootstrap() async {
    try {
      await AgentBridge.startAgent();
      await AgentBridge.installChromeHost();
      await _refreshStatus();
    } catch (e) {
      setState(() => _status = '错误: $e');
    }
  }

  Future<void> _unlockPassword() async {
    final ok = await AgentBridge.unlockWithPassword(_passwordController.text);
    if (ok) {
      await _refreshStatus();
    } else {
      setState(() => _status = '解锁失败');
    }
  }

  Future<void> _unlockTouchId() async {
    final ok = await AgentBridge.unlockWithTouchId();
    if (ok) {
      await _refreshStatus();
    } else {
      setState(() => _status = 'Touch ID 失败/回退主密码');
    }
  }

  Future<void> _lock() async {
    await AgentBridge.lockVault();
    await _refreshStatus();
  }

  Future<void> _registerLoginItem(bool enabled) async {
    try {
      await AgentBridge.registerLoginItem(enabled);
      setState(() {
        _status = enabled ? '已注册登录项（SMAppService）' : '已取消登录项';
      });
    } catch (e) {
      setState(() => _status = '登录项操作失败: $e');
    }
  }

  Future<void> _appendSshIdentityAgent() async {
    if (!_unlocked) {
      setState(() => _status = 'Vault 已锁定：请先解锁后再配置 SSH IdentityAgent');
      return;
    }
    try {
      final r = await AgentBridge.appendSshIdentityAgent();
      _showSshResult(r);
    } catch (e) {
      setState(() => _status = 'SSH IdentityAgent 失败: $e');
    }
  }

  Future<void> _removeSshIdentityAgent() async {
    try {
      final r = await AgentBridge.removeSshIdentityAgent();
      _showSshResult(r);
    } catch (e) {
      setState(() => _status = '撤销 SSH 配置失败: $e');
    }
  }

  void _showSshResult(Map<String, dynamic> r) {
    final msg = r['message'] ?? r.toString();
    final path = r['configPath'];
    final socket = r['socketPath'];
    setState(() {
      _status = socket != null ? '$msg\n\nconfig: $path\nsocket: $socket' : '$msg\n\nconfig: $path';
    });
  }

  @override
  Widget build(BuildContext context) {
    final vaultLabel = _unlocked ? '已解锁' : '已锁定';
    return Scaffold(
      appBar: AppBar(
        title: const Text('CredPivot M0 平台可行性'),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: Center(child: Text('Vault: $vaultLabel')),
          ),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('Agent 状态', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Expanded(child: SingleChildScrollView(child: Text(_status))),
            Text(
              '本 App 常驻内存约 ${formatResidentMemory(_memoryBytes)}'
              '（关窗后可在菜单栏复测 M0-8）',
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _passwordController,
              decoration: const InputDecoration(labelText: 'M0 演示主密码'),
              obscureText: true,
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                FilledButton(onPressed: _unlockPassword, child: const Text('主密码解锁')),
                FilledButton(onPressed: _unlockTouchId, child: const Text('Touch ID 解锁')),
                OutlinedButton(
                  onPressed: _unlocked ? _lock : null,
                  child: const Text('锁定'),
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
                  child: const Text('接入 SSH IdentityAgent'),
                ),
                OutlinedButton(
                  onPressed: _removeSshIdentityAgent,
                  child: const Text('撤销 SSH 配置'),
                ),
              ],
            ),
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text(
                '产品设计上 SSH 在设置页「一键接入/撤销」；首发向导含 Chrome/Touch ID，M0 暂用上方按钮。'
                ' 接入需解锁；撤销不依赖 Vault。',
                style: TextStyle(fontSize: 12, color: Colors.black54),
              ),
            ),
            if (!_unlocked)
              const Padding(
                padding: EdgeInsets.only(top: 4),
                child: Text(
                  '锁定时不接入 SSH；登录项为系统设置，可随时注册/取消。',
                  style: TextStyle(fontSize: 12, color: Colors.black54),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
