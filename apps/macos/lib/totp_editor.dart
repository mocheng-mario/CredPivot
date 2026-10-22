import 'dart:async';
import 'dart:convert';
import 'credential_confirm.dart';
import 'package:flutter/material.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'touch_id_gate.dart';
import 'website_rules_editor.dart';

Future<bool> showTotpEditor(BuildContext context, {Map<String, dynamic>? existing, List<Map<String, dynamic>> groups = const []}) async {
  Map<String, dynamic>? reveal;
  try {
    if (existing != null) {
      if (!await requireTouchId(context, reason: '编辑 MFA')) return false;
      reveal = await AgentBridge.totpReveal(existing['id'].toString());
    }
    if (!context.mounted) return false;
    return await showDialog<bool>(context: context, barrierDismissible: false,
      builder: (_) => _TotpEditor(existing: existing, reveal: reveal, groups: groups)) == true;
  } catch (e) {
    if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e is AgentException ? e.message : '无法打开 MFA 编辑器')));
    return false;
  }
}

class _TotpEditor extends StatefulWidget {
  const _TotpEditor({this.existing, this.reveal, required this.groups});
  final Map<String, dynamic>? existing, reveal;
  final List<Map<String, dynamic>> groups;
  @override
  State<_TotpEditor> createState() => _TotpEditorState();
}

class _TotpEditorState extends State<_TotpEditor> {
  late final input = TextEditingController(text: widget.reveal?['otpauth_uri']?.toString() ?? '');
  late final issuer = TextEditingController(text: widget.existing?['issuer']?.toString() ?? '');
  late final account = TextEditingController(text: widget.existing?['account']?.toString() ?? '');
  late final rules = (widget.reveal?['website_rules'] as List? ?? []).map((r) => Map<String, dynamic>.from(r as Map)).toList();
  late final pendingRules = (widget.reveal?['pending_website_rules'] as List? ?? []).map((r) => Map<String, dynamic>.from(r as Map)).toList();
  String? groupId;
  Map<String, dynamic>? parsed;
  String error = '';
  bool busy = false, parsing = false, concealed = true;
  bool closing = false, confirmingDiscard = false;
  late final String initialSnapshot;
  String snapshot() => jsonEncode([input.text,issuer.text,account.text,groupId,rules]);
  Timer? debounce;
  int generation = 0;

  @override
  void initState() {
    super.initState();
    initialSnapshot = snapshot();
    if (input.text.isNotEmpty) scheduleMicrotask(() => parseInput(fillMetadata: false));
  }
  @override
  void dispose() {
    debounce?.cancel();
    for (final controller in [input, issuer, account]) { controller.dispose(); }
    super.dispose();
  }

  Future<bool> parseInput({bool fillMetadata = true}) async {
    if (!mounted) return false;
    final version = ++generation;
    final raw = input.text;
    setState(() { parsing = true; error = ''; parsed = null; });
    try {
      final result = await AgentBridge.manage({'action': 'totp_parse', 'input': raw});
      if (!mounted || version != generation || input.text != raw) return false;
      setState(() {
        parsed = result;
        if (fillMetadata) {
          if ((result['issuer'] as String).isNotEmpty) issuer.text = result['issuer'] as String;
          if ((result['account'] as String).isNotEmpty) account.text = result['account'] as String;
        }
      });
      return true;
    } catch (e) {
      if (mounted && version == generation) setState(() => error = e is AgentException ? e.message : 'URI 解析失败');
      return false;
    } finally {
      if (mounted && version == generation) setState(() => parsing = false);
    }
  }

  Future<void> scan() async {
    try {
      final uris = await AgentBridge.scanQrImage();
      if (!mounted) return;
      if (uris.isEmpty) { setState(() => error = '图片中没有找到 TOTP 二维码'); return; }
      String? chosen = uris.first;
      if (uris.length > 1) chosen = await showDialog<String>(context: context, builder: (ctx) => SimpleDialog(
        title: const LText('选择二维码'), children: [for (var n = 0; n < uris.length; n++) SimpleDialogOption(
          onPressed: () => Navigator.pop(ctx, uris[n]), child: LText('TOTP 二维码 ${n + 1}'))]));
      if (!mounted || chosen == null) return;
      input.text = chosen;
      await parseInput();
    } catch (e) { if (mounted) setState(() => error = e is AgentException ? e.message : '二维码读取失败'); }
  }

  Future<void> cancel() async {
    if (busy || closing || confirmingDiscard) return;
    confirmingDiscard = true;
    try {
      if (snapshot() != initialSnapshot && !await confirmDiscardChanges(context)) return;
      if (mounted) { closing = true; Navigator.pop(context, false); }
    } finally { confirmingDiscard = false; }
  }

  Future<void> save() async {
    if (busy || closing) return;
    debounce?.cancel();
    setState(() => busy = true);
    try {
      if (!await parseInput(fillMetadata: false)) return;
      final validation = await websiteRulesError(rules, allowEmpty: true);
      if (!mounted) return;
      if (validation != null) { setState(() => error = validation); return; }
      if (widget.existing != null) {
        if (!await requireTouchId(context, reason: '保存 MFA 与适用网站修改')) return;
        await AgentBridge.manage({'action': 'totp_update', 'id': widget.existing!['id'],
          'expected_revision': widget.reveal!['current_revision'], 'issuer': issuer.text.trim(),
          'account': account.text.trim(), 'secret': input.text.trim(), 'website_rules': rules,
          'resolve_pending_rules': pendingRules.isNotEmpty});
      } else {
        await AgentBridge.createTotp(issuer: issuer.text.trim(), account: account.text.trim(),
          secretBase32: input.text.trim(), groupId: groupId, websiteRules: rules);
      }
      if (mounted) { closing = true; Navigator.pop(context, true); }
    } catch (e) { if (mounted) setState(() => error = e is AgentException ? e.message : '保存 MFA 失败，请重试'); }
    finally { if (mounted && !closing) setState(() => busy = false); }
  }

  @override
  Widget build(BuildContext context) => PopScope(canPop: false, onPopInvokedWithResult: (didPop, _) { if (!didPop) cancel(); }, child: AlertDialog(
    title: LText(widget.existing == null ? '添加 MFA / TOTP' : '编辑 MFA / TOTP'),
    content: SizedBox(width: appEditDialogWidth(context), child: SingleChildScrollView(child: Column(
      mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: appFormFields([
        TextField(controller: input, enabled: !busy, obscureText: concealed,
          decoration: InputDecoration(labelText: 'otpauth URI / Base32', helperText: tr('粘贴完整 URI 可解析发行方、账号、算法、位数与周期'), helperMaxLines: 2,
            suffixIcon: IconButton(onPressed: () => setState(() => concealed = !concealed), icon: Icon(concealed ? Icons.visibility : Icons.visibility_off))),
          onChanged: (_) { generation++; debounce?.cancel(); setState(() { parsed = null; parsing = false; }); debounce = Timer(const Duration(milliseconds: 400), () => parseInput()); }),
        Wrap(spacing: 12, children: [
          TextButton.icon(onPressed: busy || parsing ? null : () => parseInput(), icon: const Icon(Icons.manage_search), label: LText(parsing ? '解析中…' : '解析参数')),
          TextButton.icon(onPressed: busy ? null : scan, icon: const Icon(Icons.qr_code_scanner), label: const LText('从二维码图片导入')),
        ]),
        if (parsed != null) LText('TOTP · ${parsed!['algorithm']} · ${parsed!['digits']} 位 · ${parsed!['period']} 秒'),
        if (parsed != null && (parsed!['extra_parameters'] as Map).isNotEmpty) LText('附加参数：${(parsed!['extra_parameters'] as Map).keys.join('、')}'),
        if (parsed != null) for (final warning in parsed!['warnings'] as List) Text(warning.toString(), style: TextStyle(color: Theme.of(context).colorScheme.error)),
        TextField(controller: issuer, enabled: !busy, decoration: InputDecoration(labelText: tr('发行方 Issuer'))),
        TextField(controller: account, enabled: !busy, decoration: InputDecoration(labelText: tr('账号标签（无需创建登录记录）'))),
        if (widget.existing == null && widget.groups.isNotEmpty) DropdownButtonFormField<String>(
          isExpanded: true, value: groupId, decoration: InputDecoration(labelText: tr('分组')),
          items: [const DropdownMenuItem<String>(value: null, child: LText('（未分组）')), for (final g in widget.groups) DropdownMenuItem(value: g['id'] as String, child: Text(g['name'].toString()))],
          onChanged: busy ? null : (v) => setState(() => groupId = v)),
        const LText('适用网站：关联账号和独立填充共用此处规则。留空时仅在 App 使用，浏览器不会填充。'),
        if (pendingRules.isNotEmpty) ...[
          const AppNotice('旧账号关联的网站范围尚未启用。勾选需要保留的网站；保存后，未勾选的建议会被舍弃。'),
          for (final pending in pendingRules) CheckboxListTile(
            contentPadding: EdgeInsets.zero,
            title: Text(pending['uri'].toString()),
            subtitle: Text(pending['match_mode'].toString()),
            value: rules.any((r) => r['uri'] == pending['uri'] && r['match_mode'] == pending['match_mode']),
            onChanged: busy ? null : (v) => setState(() {
              if (v == true) {
                if (!rules.any((r) => r['uri'] == pending['uri'] && r['match_mode'] == pending['match_mode'])) rules.add({...pending, 'id': newWebsiteRule()['id']});
              } else {
                rules.removeWhere((r) => r['uri'] == pending['uri'] && r['match_mode'] == pending['match_mode']);
              }
            })),
        ],
        if (parsed?['suggested_website'] != null) Align(alignment: Alignment.centerLeft, child: TextButton.icon(
          onPressed: busy ? null : () => setState(() {
            final uri = parsed!['suggested_website'] as String;
            if (!rules.any((r) => r['uri'] == uri)) rules.add(newWebsiteRule(uri));
          }), icon: const Icon(Icons.add_link), label: Text('添加建议网站：${parsed!['suggested_website']}'))),
        WebsiteRulesEditor(rules: rules, enabled: !busy, onChanged: () => setState(() {})),
        if (error.isNotEmpty) Text(error, style: TextStyle(color: Theme.of(context).colorScheme.error)),
      ]),
    ))),
    actions: [TextButton(onPressed: busy ? null : cancel, child: const LText('取消')),
      FilledButton(onPressed: busy || parsing ? null : save, child: LText(busy ? '保存中…' : '保存'))],
  ));
}
