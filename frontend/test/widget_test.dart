import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import '../lib/main.dart';

void main() {
  testWidgets('dashboard shows the title and the URL scanner', (tester) async {
    await tester.pumpWidget(const SentinelApp());

    expect(find.text('SENTINEL AIOPS PORTFOLIO PLATFORM'), findsOneWidget);
    expect(
        find.text('Hybrid URL Threat & Phishing Intelligence'), findsOneWidget);
    expect(find.text('Scan URL'), findsOneWidget);
    expect(find.byType(TextField), findsOneWidget);
  });

  testWidgets('scanner text does not promise safety', (tester) async {
    await tester.pumpWidget(const SentinelApp());

    expect(find.textContaining('not a guarantee of safety'), findsOneWidget);
    expect(find.textContaining('SAFE'), findsNothing);
  });

  testWidgets('scanning an empty box does nothing', (tester) async {
    await tester.pumpWidget(const SentinelApp());

    await tester.tap(find.text('Scan URL'));
    await tester.pump();

    expect(find.textContaining('Scan failed'), findsNothing);
  });
}
