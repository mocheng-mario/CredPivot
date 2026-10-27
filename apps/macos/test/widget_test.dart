import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:credpivot_macos/app_presentation.dart';
import 'package:credpivot_macos/credential_group_ui.dart';
import 'package:credpivot_macos/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() async {
    await AppPresentation.instance.loadCatalog();
  });

  testWidgets('app shell shows startup failure without a native agent', (WidgetTester tester) async {
    // 不启动真实 Agent，也不读取真实保险库；确保启动失败仍显示页面而非黑屏。
    const channel = MethodChannel('credpivot/agent');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel,
      (call) async => call.method == 'agentIsRunning' || call.method == 'restartAgent' ? false : null);
    addTearDown(() => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, null));
    tester.view.physicalSize = const Size(1440, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(const CredPivotApp());
    await tester.pumpAndSettle();
    expect(find.byType(VaultHomePage), findsOneWidget);
    expect(find.text(tr('vault.connectionUnavailable.title')), findsOneWidget);
    expect(find.text(tr('vault.connectionUnavailable.text')), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('group collapse survives refresh and is scoped to its module', (WidgetTester tester) async {
    late StateSetter rebuild;
    var scope = 'login';
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: StatefulBuilder(builder: (_, update) {
      rebuild = update;
      return ListView(children: buildGroupedListTiles(scope: scope,
        groups: [{'id': 'test-group', 'name': 'Test group'}],
        items: [{'group_id': 'test-group'}], tileBuilder: (_) => const ListTile(title: Text('Test entry'))));
    }))));
    expect(find.text('Test entry'), findsOneWidget);
    await tester.tap(find.text('Test group  ·  1'));
    await tester.pumpAndSettle();
    expect(find.text('Test entry'), findsNothing);
    rebuild(() {});
    await tester.pumpAndSettle();
    expect(find.text('Test entry'), findsNothing);
    rebuild(() => scope = 'totp');
    await tester.pumpAndSettle();
    expect(find.text('Test entry'), findsOneWidget);
    rebuild(() => scope = 'login');
    await tester.pumpAndSettle();
    expect(find.text('Test entry'), findsNothing);
  });
}
