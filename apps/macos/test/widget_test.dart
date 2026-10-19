import 'package:credpivot_macos/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('app shell builds', (WidgetTester tester) async {
    await tester.pumpWidget(const CredPivotApp());
    expect(find.textContaining('CredPivot M2'), findsOneWidget);
  });
}
