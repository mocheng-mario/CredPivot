import 'dart:async';
import 'dart:convert';
import 'credential_confirm.dart';
import 'package:flutter/material.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'touch_id_gate.dart';
import 'website_rules_editor.dart';
import 'credential_group_ui.dart';

Future<bool> showTotpEditor(BuildContext context, {Map<String, dynamic>? existing, List<Map<String, dynamic>> groups = const [], Map<String, dynamic>? browserRequest}) async {
  final partition = existing?['partition_id']?.toString() ?? AgentBridge.activePartitionId;
  Map<String, dynamic>? reveal;
  try {
    if (existing != null) {
      if (!await requireTouchId(context, reason: tr('mfa.showTotpEditor.reason'))) return false;
      reveal = await AgentBridge.totpReveal(existing['id'].toString());
    }
    if (browserRequest == null) groups = await loadCredentialGroups('totp', partitionId: partition);
    if (!context.mounted) return false;
    return await showDialog<bool>(context: context, barrierDismissible: false,
      builder: (_) => _TotpEditor(existing: existing, reveal: reveal, groups: groups, partitionId: partition, browserRequest: browserRequest)) == true;
  } catch (e) {
    if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e is AgentException ? e.message : tr('mfa.showTotpEditor.message'))));
    return false;
  }
}

class _TotpEditor extends StatefulWidget {
  const _TotpEditor({this.existing, this.reveal, required this.groups, required this.partitionId, this.browserRequest});
  final Map<String, dynamic>? existing, reveal, browserRequest;
  final List<Map<String, dynamic>> groups;
  final String partitionId;
  @override
  State<_TotpEditor> createState() => _TotpEditorState();
}

class _TotpEditorState extends State<_TotpEditor> {
  late final input = TextEditingController(text: widget.reveal?['otpauth_uri']?.toString() ?? '');
  late final issuer = TextEditingController(text: widget.existing?['issuer']?.toString() ?? '');
  late final account = TextEditingController(text: widget.existing?['account']?.toString() ?? '');
  late final rules = widget.browserRequest != null ? [newWebsiteRule(widget.browserRequest!['origin'].toString())] :
      (widget.reveal?['website_rules'] as List? ?? []).map((r) => Map<String, dynamic>.from(r as Map)).toList();
  late final pendingRules = (widget.reveal?['pending_website_rules'] as List? ?? []).map((r) => Map<String, dynamic>.from(r as Map)).toList();
  String? groupId;
  String linkedLoginId = '';
  Map<String, dynamic>? parsed;
  String error = '';
  bool busy = false, parsing = false, concealed = true, scanning = false;
  bool closing = false, confirmingDiscard = false;
  late final String initialSnapshot;
  String snapshot() => jsonEncode([input.text,issuer.text,account.text,groupId,rules,linkedLoginId]);
  Timer? debounce;
  Timer? requestWatch;
  bool checkingRequest = false;
  int generation = 0;

  @override
  void initState() {
    super.initState();
    initialSnapshot = snapshot();
    if (input.text.isNotEmpty) scheduleMicrotask(() => parseInput(fillMetadata: false));
    if (widget.browserRequest != null) scheduleMicrotask(() async {
      final image = widget.browserRequest!.remove('image')?.toString();
      await scan(image: image?.isNotEmpty == true ? image : null);
    });
    if (widget.browserRequest != null) requestWatch = Timer.periodic(const Duration(seconds: 2), (_) async {
      if (!mounted || busy || closing || checkingRequest) return;
      checkingRequest = true;
      try {
        final status = AgentBridge.payloadOf(await AgentBridge.request({'type': 'browser_mfa_pending', 'request_id': widget.browserRequest!['id']}));
        if (mounted && !busy && !closing && status['active'] != true) {
          closeExpiredRequest();
        }
      } catch (_) {
        if (mounted && !busy && !closing) closeExpiredRequest();
      } finally { checkingRequest = false; }
    });
  }
  @override
  void dispose() {
    debounce?.cancel();
    requestWatch?.cancel();
    for (final controller in [input, issuer, account]) { controller.dispose(); }
    super.dispose();
  }

  void closeExpiredRequest() {
    closing = true;
    final route = ModalRoute.of(context);
    // 先关闭二维码选择等子弹窗，再退出添加窗口，避免把结果交给错误的路由。
    Navigator.of(context).popUntil((candidate) => candidate == route || candidate.isFirst);
    if (route?.isCurrent == true) Navigator.pop(context, false);
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
      if (mounted && version == generation) setState(() => error = e is AgentException ? e.message : tr('mfa.parseInput.message'));
      return false;
    } finally {
      if (mounted && version == generation) setState(() => parsing = false);
    }
  }

  Future<void> scan({String? image}) async {
    if (!mounted || scanning || busy || closing) return;
    setState(() => scanning = true);
    try {
      final uris = await AgentBridge.scanQrImage(image: image);
      if (!mounted || closing) return;
      if (uris.isEmpty) { setState(() => error = tr('mfa.scan.text')); return; }
      String? chosen = uris.first;
      if (uris.length > 1) chosen = await showDialog<String>(context: context, builder: (ctx) => SimpleDialog(
        title: const LText('mfa.scan.text.item2'), children: [for (var n = 0; n < uris.length; n++) SimpleDialogOption(
          onPressed: () => Navigator.pop(ctx, uris[n]), child: LText('mfa.scan.qrIndex', args: {'index': n + 1}))]));
      if (!mounted || closing || chosen == null) return;
      input.text = chosen;
      await parseInput();
    } catch (e) { if (mounted && !closing) setState(() => error = e is AgentException ? e.message : tr('mfa.scan.message')); }
    finally { if (mounted && !closing) setState(() => scanning = false); }
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
    if (busy || scanning || closing) return;
    debounce?.cancel();
    setState(() => busy = true);
    try {
      if (!await parseInput(fillMetadata: false)) return;
      final validation = await websiteRulesError(rules, allowEmpty: true);
      if (!mounted) return;
      if (validation != null) { setState(() => error = validation); return; }
      if (widget.existing != null) {
        if (!await requireTouchId(context, reason: tr('mfa.save.reason'))) return;
        await AgentBridge.manage({'action': 'totp_update', 'id': widget.existing!['id'],
          'expected_revision': widget.reveal!['current_revision'], 'issuer': issuer.text.trim(),
          'account': account.text.trim(), 'secret': input.text.trim(), 'website_rules': rules,
          'resolve_pending_rules': pendingRules.isNotEmpty});
      } else if (widget.browserRequest != null) {
        if (!await requireTouchId(context, reason: tr('mfa.browser.title')) || !mounted) return;
        await AgentBridge.request({'type': 'browser_mfa_resolve', 'request_id': widget.browserRequest!['id'],
          'approved': true, 'linked_login_id': linkedLoginId, 'issuer': issuer.text.trim(),
          'account': account.text.trim(), 'input': input.text.trim(), 'website_rules': rules}, partitionId: widget.partitionId);
      } else {
        await AgentBridge.createTotp(partitionId: widget.partitionId, issuer: issuer.text.trim(), account: account.text.trim(),
          secretBase32: input.text.trim(), groupId: groupId, websiteRules: rules);
      }
      if (mounted) { closing = true; Navigator.pop(context, true); }
    } catch (e) { if (mounted) setState(() => error = e is AgentException ? e.message : tr('mfa.save.message')); }
    finally { if (mounted && !closing) setState(() => busy = false); }
  }

  @override
  Widget build(BuildContext context) => PopScope(canPop: false, onPopInvokedWithResult: (didPop, _) { if (!didPop) cancel(); }, child: AppEditDialog(
    title: LText(widget.browserRequest != null ? 'mfa.browser.title' : widget.existing == null ? 'mfa.build.text' : 'mfa.build.text.item2'),
    content: SizedBox(width: appEditDialogWidth(context), child: SingleChildScrollView(child: Column(
      mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: appFormFields([
        if (widget.browserRequest != null) ...[
          Text('${tr('mfa.browser.website')}: ${widget.browserRequest!['origin']}'),
          const LText('mfa.browser.linkHelp'),
          if (widget.browserRequest!['login_candidates_unavailable'] == true) AppNotice(tr('mfa.browser.linksUnavailable')),
          ConstrainedBox(constraints: const BoxConstraints(maxHeight: 220), child: SingleChildScrollView(child: Column(children: [
            RadioListTile<String>(value: '', groupValue: linkedLoginId, contentPadding: EdgeInsets.zero,
              title: const LText('passkey.links.none'), onChanged: busy ? null : (id) => setState(() => linkedLoginId = id ?? '')),
            for (final login in (widget.browserRequest!['login_candidates'] as List? ?? []).cast<Map>())
              RadioListTile<String>(value: login['id'].toString(), groupValue: linkedLoginId, contentPadding: EdgeInsets.zero,
                title: Text('${login['partition_name'] ?? ''} · ${login['display_name'] ?? ''} · ${login['username'] ?? ''}'),
                subtitle: Text(login['origin']?.toString() ?? ''), onChanged: busy ? null : (id) => setState(() => linkedLoginId = id ?? '')),
          ]))),
        ],
        AppFieldRow(label: 'otpauth URI / Base32', help: tr('mfa.build.text.item3'), child: TextField(controller: input, enabled: !busy && !scanning, obscureText: concealed,
          decoration: InputDecoration(suffixIcon: IconButton(onPressed: () => setState(() => concealed = !concealed), icon: Icon(concealed ? Icons.visibility : Icons.visibility_off))),
          onChanged: (_) { generation++; debounce?.cancel(); setState(() { parsed = null; parsing = false; }); debounce = Timer(const Duration(milliseconds: 400), () => parseInput()); })),
        Wrap(spacing: 12, children: [
          TextButton.icon(onPressed: busy || parsing || scanning ? null : () => parseInput(), icon: const Icon(Icons.manage_search), label: LText(parsing ? tr('mfa.build.text.item4') : tr('mfa.build.text.item5'))),
          TextButton.icon(onPressed: busy || scanning ? null : () => scan(), icon: const Icon(Icons.qr_code_scanner), label: const LText('mfa.build.text.item6')),
        ]),
        if (parsed != null) LText('mfa.editor.parameters', args: {'algorithm': parsed!['algorithm'], 'digits': parsed!['digits'], 'period': parsed!['period']}),
        if (parsed != null && (parsed!['extra_parameters'] as Map).isNotEmpty) LText('mfa.editor.extraParameters', args: {'parameters': (parsed!['extra_parameters'] as Map).keys.join('、')}),
        if (parsed != null) for (final warning in parsed!['warnings'] as List) Text(warning.toString(), style: TextStyle(color: Theme.of(context).colorScheme.error)),
        AppFieldRow(label: tr('mfa.fields.issuerLabel'), child: TextField(controller: issuer, enabled: !busy && !scanning, decoration: InputDecoration())),
        AppFieldRow(label: tr('mfa.fields.accountLabel'), child: TextField(controller: account, enabled: !busy && !scanning, decoration: InputDecoration())),
        if (widget.existing == null && widget.groups.isNotEmpty) AppFieldRow(label: tr('common.group'), child: DropdownButtonFormField<String>(
          isExpanded: true, value: groupId, decoration: InputDecoration(),
          items: [const DropdownMenuItem<String>(value: null, child: LText('common.ungroupedOption')), for (final g in widget.groups) DropdownMenuItem(value: g['id'] as String, child: Text(credentialGroupLabel(g), overflow: TextOverflow.ellipsis))],
          onChanged: busy ? null : (v) => setState(() => groupId = v))),
        const LText('mfa.build.text.item9'),
        if (pendingRules.isNotEmpty) ...[
          AppNotice(tr('mfa.build.text.item10')),
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
          }), icon: const Icon(Icons.add_link), label: Text(tr('mfa.editor.suggestedWebsite', args: {'origin': parsed!['suggested_website']})))),
        WebsiteRulesEditor(rules: rules, enabled: !busy, onChanged: () => setState(() {})),
        if (error.isNotEmpty) Text(error, style: TextStyle(color: Theme.of(context).colorScheme.error)),
      ]),
    ))),
    actions: [TextButton(onPressed: busy ? null : cancel, child: const LText('common.cancel')),
      FilledButton(onPressed: busy || parsing || scanning ? null : save, child: LText(busy ? tr('common.saving') : tr('common.save')))],
  ));
}
