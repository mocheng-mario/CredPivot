import 'package:flutter/material.dart';

import 'agent_bridge.dart';
import 'app_ui.dart';
import 'credential_confirm.dart';
import 'credential_group_ui.dart';
import 'vault_tools.dart' show vaultAction, vaultMessage;

Future<bool> importGooglePasswords(BuildContext context) async {
  try {
    final path = await AgentBridge.pickOpenFile();
    if (path == null || !context.mounted) return false;
    return await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (_) => _GooglePasswordImport(path: path),
    ) == true;
  } catch (error) {
    if (context.mounted) vaultMessage(context, error);
    return false;
  }
}

class _GooglePasswordImport extends StatefulWidget {
  const _GooglePasswordImport({required this.path});
  final String path;

  @override
  State<_GooglePasswordImport> createState() => _GooglePasswordImportState();
}

class _GooglePasswordImportState extends State<_GooglePasswordImport> {
  final _groupName = TextEditingController();
  List<Map<String, dynamic>> _partitions = [], _groups = [];
  String _partition = AgentBridge.activePartitionId;
  String _group = '__none__';
  String _error = '';
  Map<String, dynamic>? _preview, _report;
  final _selected = <int>{};
  bool _busy = false, _dirty = false, _closing = false, _confirming = false;

  List<Map> get _items => (_preview?['items'] as List? ?? []).cast<Map>();
  Map<String, dynamic> get _target => {
    'path': widget.path,
    'partition_id': _partition,
    'group_id': _group == '__none__' || _group == '__new__' ? null : _group,
    'new_group_name': _group == '__new__' ? _groupName.text.trim() : '',
  };
  String get _partitionName => _partitions
      .firstWhere((row) => row['id'] == _partition, orElse: () => {})['name']?.toString() ?? '';
  String get _groupLabel => _group == '__new__' ? _groupName.text.trim()
      : _group == '__none__' ? tr('common.ungroupedOption')
      : _groups.firstWhere((row) => row['id'] == _group, orElse: () => {})['name']?.toString() ?? '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _groupName.dispose();
    super.dispose();
  }

  String _message(Object error) => error is AgentException
      ? tr(error.message.replaceFirst(RegExp(r'^invalid format: '), ''))
      : tr('import.google.failed');

  Future<void> _load() async {
    if (_busy) return;
    setState(() { _busy = true; _error = ''; });
    try {
      final result = await AgentBridge.manage({'action': 'partition_list'});
      final partitions = (result['partitions'] as List).map((row) => Map<String, dynamic>.from(row as Map)).toList();
      if (!partitions.any((row) => row['id'] == _partition)) _partition = AgentBridge.personalPartitionId;
      final groups = await AgentBridge.listCredentialGroups('login', partitionId: _partition);
      if (!mounted) return;
      setState(() { _partitions = partitions; _groups = groups; });
    } catch (error) {
      if (mounted) setState(() => _error = _message(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _changePartition(String value) async {
    if (_busy) return;
    setState(() {
      _partition = value;
      _group = '__none__';
      _groups = [];
      _dirty = true;
    });
    await _load();
  }

  Future<void> _cancel() async {
    if (_busy || _closing || _confirming) return;
    if (_report != null) {
      _closing = true;
      Navigator.pop(context, true);
      return;
    }
    _confirming = true;
    try {
      if (_dirty && !await confirmDiscardChanges(context)) return;
      if (mounted) { _closing = true; Navigator.pop(context, false); }
    } finally { _confirming = false; }
  }

  Future<void> _prepare() async {
    if (_busy || _partitions.isEmpty) return;
    if (_group == '__new__' && _groupName.text.trim().isEmpty) {
      setState(() => _error = tr('import.google.groupRequired'));
      return;
    }
    setState(() { _busy = true; _error = ''; });
    try {
      final preview = await vaultAction(context, {'action': 'google_preview', ..._target});
      if (!mounted) return;
      setState(() {
        _preview = preview;
        _selected.clear();
        for (final row in _items) {
          if (row['state'] == 'new') _selected.add((row['row_id'] as num).toInt());
        }
      });
    } catch (error) {
      if (mounted) setState(() => _error = _message(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _apply() async {
    if (_busy || _selected.isEmpty || _preview == null) return;
    setState(() { _busy = true; _error = ''; });
    try {
      final report = await vaultAction(context, {
        'action': 'google_import', ..._target,
        'selected_rows': _selected.toList()..sort(),
        'preview_token': _preview!['preview_token'],
      });
      AgentBridge.notifyVaultChanged();
      if (mounted) setState(() => _report = report);
    } catch (error) {
      if (mounted) setState(() {
        if (error is AgentException && error.code == 'conflict') {
          _preview = null;
          _selected.clear();
          _error = tr('import.google.previewChanged');
        } else {
          _error = _message(error);
        }
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Widget _configuration() => ListView(children: [
    AppNotice(tr('import.google.help')),
    appFieldRows([
      AppFieldRow(label: tr('import.google.partition'), child: DropdownButtonFormField<String>(
        value: _partitions.any((row) => row['id'] == _partition) ? _partition : null,
        isExpanded: true,
        items: _partitions.map((row) => DropdownMenuItem(value: row['id'].toString(), child: Text(row['name'].toString()))).toList(),
        onChanged: _busy ? null : (value) { if (value != null) _changePartition(value); },
      )),
      AppFieldRow(label: tr('common.group'), child: DropdownButtonFormField<String>(
        key: ValueKey('$_partition:$_group'), value: _group, isExpanded: true,
        items: [
          const DropdownMenuItem(value: '__none__', child: LText('common.ungroupedOption')),
          const DropdownMenuItem(value: '__new__', child: LText('import.google.newGroup')),
          for (final row in _groups) DropdownMenuItem(value: row['id'].toString(), child: Text(credentialGroupLabel(row), overflow: TextOverflow.ellipsis)),
        ],
        onChanged: _busy ? null : (value) {
          if (value != null) setState(() { _group = value; _dirty = true; _error = ''; });
        },
      )),
      if (_group == '__new__') AppFieldRow(label: tr('import.google.groupName'), help: tr('groups.type.sharedHelp'),
        child: TextField(controller: _groupName, enabled: !_busy, maxLength: 80,
          decoration: InputDecoration(hintText: tr('import.google.groupHint')),
          onChanged: (_) => _dirty = true,
        )),
    ]),
    if (_partitions.isEmpty && !_busy)
      TextButton(onPressed: _load, child: const LText('common.retry')),
  ]);

  Widget _previewList() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      LText('import.google.destination', args: {'partition': _partitionName, 'group': _groupLabel}),
      const SizedBox(height: 8),
      LText('import.google.previewHelp', style: Theme.of(context).textTheme.bodySmall),
      const SizedBox(height: 8),
      Wrap(spacing: 8, runSpacing: 4, crossAxisAlignment: WrapCrossAlignment.center, children: [
        LText('import.google.selected', args: {'count': _selected.length, 'total': _items.length}),
        TextButton(onPressed: _busy ? null : () => setState(() {
          for (final row in _items) {
            if (row['state'] == 'new') _selected.add((row['row_id'] as num).toInt());
          }
          _dirty = true;
        }), child: const LText('import.google.selectNew')),
        TextButton(onPressed: _busy ? null : () => setState(() { _selected.clear(); _dirty = true; }),
            child: const LText('import.google.clearSelection')),
      ]),
      const Divider(),
      Expanded(child: ListView.builder(itemCount: _items.length, itemBuilder: (context, index) {
        final row = _items[index];
        final id = (row['row_id'] as num).toInt();
        final selectable = row['state'] == 'new' || row['state'] == 'conflict';
        return CheckboxListTile(
          contentPadding: EdgeInsets.zero,
          value: _selected.contains(id),
          onChanged: _busy || !selectable ? null : (value) => setState(() {
            if (value == true) { _selected.add(id); } else { _selected.remove(id); }
            _dirty = true;
          }),
          title: Text(row['title'].toString().isEmpty
              ? tr('import.google.line', args: {'line': row['line']}) : row['title'].toString()),
          subtitle: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text([row['origin'], row['username']].where((value) => value != null && value.toString().isNotEmpty).join(' · ')),
            LText('import.google.${row['state']}',
                style: TextStyle(color: row['state'] == 'conflict' || row['state'] == 'invalid'
                    ? Theme.of(context).colorScheme.error : AppColors.muted)),
            if (row['reason']?.toString().isNotEmpty == true) LText(row['reason'].toString()),
          ]),
        );
      })),
    ],
  );

  @override
  Widget build(BuildContext context) => PopScope(
    canPop: false,
    onPopInvokedWithResult: (didPop, _) { if (!didPop) _cancel(); },
    child: AlertDialog(
      title: LText(_report != null ? 'import.google.complete' : 'import.google.title'),
      content: SizedBox(
        width: appEditDialogWidth(context),
        height: (MediaQuery.sizeOf(context).height * .55).clamp(160.0, 560.0).toDouble(),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          if (_busy) const LinearProgressIndicator(),
          if (_error.isNotEmpty) AppNotice(_error),
          if (_report != null)
            Expanded(child: SingleChildScrollView(child: LText('import.google.summary', args: {
              'imported': _report!['imported'], 'copied': _report!['copied'],
              'skipped': _report!['skipped'], 'partition': _partitionName, 'group': _groupLabel,
            })))
          else Expanded(child: _preview == null ? _configuration() : _previewList()),
        ]),
      ),
      actions: [
        TextButton(onPressed: _busy ? null : _cancel,
            child: LText(_report == null ? 'common.cancel' : 'common.close')),
        if (_preview != null && _report == null) TextButton(onPressed: _busy ? null : () => setState(() {
          _preview = null; _selected.clear(); _error = '';
        }), child: const LText('import.google.back')),
        if (_report == null) FilledButton(
          onPressed: _busy || _partitions.isEmpty || (_preview != null && _selected.isEmpty)
              ? null : (_preview == null ? _prepare : _apply),
          child: LText(_preview == null ? 'import.google.preview' : 'common.confirmImport'),
        ),
      ],
    ),
  );
}
