import 'package:flutter/material.dart';
import 'agent_bridge.dart';
import 'app_ui.dart';
import 'touch_id_gate.dart';

Future<void> showDuplicateLogins(BuildContext context) => showDialog<void>(
  context: context, builder: (_) => const _DuplicateLogins());

class _DuplicateLogins extends StatefulWidget {
  const _DuplicateLogins();
  @override
  State<_DuplicateLogins> createState() => _DuplicateLoginsState();
}

class _DuplicateLoginsState extends State<_DuplicateLogins> {
  final partition = AgentBridge.activePartitionId;
  List<Map<String,dynamic>> groups = [];
  final keepers = <int,String>{};
  String error = '';
  bool busy = false;
  @override
  void initState() { super.initState(); load(); }

  Future<void> load() async {
    setState(() { busy = true; error = ''; });
    try {
      final result = await AgentBridge.manage({'action':'duplicate_logins','partition_id':partition});
      if (!mounted) return;
      setState(() {
        groups = (result['groups'] as List).map((r) => Map<String,dynamic>.from(r as Map)).toList();
        keepers.clear();
        for (var i=0;i<groups.length;i++) { keepers[i]=(groups[i]['items'] as List).first['id'].toString(); }
      });
    } catch (e) { if (mounted) setState(() => error = e is AgentException ? tr(e.message) : tr('common.operationFailed')); }
    finally { if (mounted) setState(() => busy = false); }
  }

  String date(dynamic value) => value is num && value > 0
    ? DateTime.fromMillisecondsSinceEpoch(value.toInt()).toLocal().toIso8601String().split('.').first.replaceFirst('T',' ') : '—';

  Future<void> merge(int index) async {
    if (busy) return;
    setState(() { busy = true; error = ''; });
    try {
      final keeper = keepers[index]!;
      final sources = (groups[index]['items'] as List).map((r) => r['id'].toString()).where((id) => id != keeper).toList();
      if (!await requireTouchId(context,reason:'duplicates.compare')) return;
      if (!mounted) return;
      final plan = await AgentBridge.manage({'action':'login_merge_preview','keeper':keeper,'sources':sources});
      if (!mounted) return;
      final items = (plan['items'] as List).cast<Map>();
      final fields = <String,String Function(Map)>{
        tr('common.website'): (r) => r['origin'].toString(),
        tr('common.username'): (r) => r['username'].toString(),
        tr('common.group'): (r) => r['group_name']?.toString() ?? tr('common.ungrouped'),
        tr('credentials.list.updated'): (r) => date(r['updated_at_ms']),
        tr('common.password'): (r) => tr(r['id'] == keeper ? 'duplicates.keptPassword'
          : r['password_matches_keeper'] == true ? 'duplicates.samePassword' : 'duplicates.differentPassword'),
        'MFA': (r) => '${r['mfa_count']}',
        tr('credentials.passkey.title'): (r) => '${r['passkey_count']}',
        tr('duplicates.notesLength'): (r) => '${r['notes_length']}',
        tr('duplicates.customFields'): (r) => '${r['custom_field_count']}',
        tr('duplicates.servers'): (r) => '${r['server_count']}',
      };
      final accepted = await showDialog<bool>(context:context,builder:(ctx) => AlertDialog(
        title:const LText('duplicates.confirm'),
        content:SizedBox(width:760,height:MediaQuery.sizeOf(ctx).height*.65,child:SingleChildScrollView(child:Column(
          crossAxisAlignment:CrossAxisAlignment.stretch,children:[
            const LText('duplicates.mergeHelp'),
            const SizedBox(height:12),
            SingleChildScrollView(scrollDirection:Axis.horizontal,child:DataTable(dataRowMaxHeight:double.infinity,
              columns:[const DataColumn(label:Text('')),for(final item in items) DataColumn(label:SizedBox(width:160,
                child:Text('${item['id'] == keeper ? '${tr('duplicates.keeper')} · ' : ''}${item['title']}')))],
              rows:[for(final field in fields.entries) DataRow(cells:[DataCell(Text(field.key)),
                for(final item in items) DataCell(SizedBox(width:160,child:SelectableText(field.value(item))))])])),
            const SizedBox(height:12),
            LText('duplicates.summary',args:{'count':sources.length,'history':plan['history_count'],'candidates':plan['candidate_count']}),
            const LText('duplicates.restoreHelp'),
          ]))),
        actions:[TextButton(onPressed:()=>Navigator.pop(ctx,false),child:const LText('common.cancel')),
          FilledButton(onPressed:()=>Navigator.pop(ctx,true),child:const LText('duplicates.confirm'))],
      )) == true;
      if (!accepted || !mounted || !await requireTouchId(context,reason:'duplicates.confirm',confirmed:true)) return;
      if (!mounted) return;
      await AgentBridge.manage({'action':'login_merge_apply','keeper':keeper,'sources':sources,'fingerprint':plan['fingerprint']});
      AgentBridge.notifyVaultChanged();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content:LText('duplicates.done')));
      await load();
    } catch(e) {
      if(mounted) setState(() => error = e is AgentException ? tr(e.message) : tr('common.operationFailed'));
    } finally { if(mounted) setState(() => busy=false); }
  }

  @override
  Widget build(BuildContext context) => PopScope(canPop:!busy,child:AlertDialog(
    title:const LText('duplicates.title'),
    content:SizedBox(width:640,height:MediaQuery.sizeOf(context).height*.6,child:Column(
      crossAxisAlignment:CrossAxisAlignment.stretch,children:[
        const LText('duplicates.help'),
        if(busy) const LinearProgressIndicator(),
        if(error.isNotEmpty) AppNotice(error),
        Expanded(child:ListView(children:[
          if(groups.isEmpty && !busy) const Padding(padding:EdgeInsets.all(24),child:LText('duplicates.empty')),
          for(var i=0;i<groups.length;i++) Card(child:ExpansionTile(
            key:ValueKey('${groups[i]['host']}:${groups[i]['username']}'),initiallyExpanded:true,
            title:Text('${groups[i]['host']} · ${groups[i]['username']}'),
            children:[
              RadioGroup<String>(groupValue:keepers[i],onChanged:(value) {if(!busy && value!=null)setState(()=>keepers[i]=value);},
                child:Column(children:[for(final item in groups[i]['items'] as List) RadioListTile<String>(
                  value:item['id'].toString(),enabled:!busy,
                  title:Text(item['title'].toString()),subtitle:Text('${item['origin']}\n${date(item['updated_at_ms'])}'))])),
              TextButton.icon(onPressed:busy ? null : () => merge(i),icon:const Icon(Icons.compare_arrows),label:const LText('duplicates.compare')),
            ])),
        ])),
      ])),
    actions:[TextButton(onPressed:busy ? null : ()=>Navigator.pop(context),child:const LText('common.close')),
      OutlinedButton(onPressed:busy ? null : load,child:const LText('common.refresh'))],
  ));
}
