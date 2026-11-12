// Sentinel AIOps dashboard (Flutter)
// Backend: sentinel_bridge.py on http://127.0.0.1:5000
// Android emulator: change kApiBase to http://10.0.2.2:5000
// pubspec.yaml needs:  http: ^1.2.0

import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

const String kApiBase = 'http://127.0.0.1:5000';
const Duration kRefreshEvery = Duration(seconds: 5);

const Color kCyan = Color(0xFF00E5FF);
const Color kNavy = Color(0xFF0A1128);
const Color kPanel = Color(0xFF1C2541);
const Color kPurple = Color(0xFF7C4DFF);
const Color kOrange = Color(0xFFFF6E40);
const Color kGreen = Color(0xFF69F0AE);
const Color kAmber = Color(0xFFFFD740);

void main() => runApp(const SentinelAIOps());

class SentinelAIOps extends StatelessWidget {
  const SentinelAIOps({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'AI-Driven AIOps Threat Detection',
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: kNavy,
        primaryColor: kCyan,
        fontFamily: 'Roboto',
      ),
      home: const DashboardScreen(),
    );
  }
}

// ─── Background ───
class CleanBackgroundPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final rect = Rect.fromLTWH(0, 0, size.width, size.height);
    final gradient = const LinearGradient(
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
      colors: [Color(0xFF050B14), kNavy, kPanel],
      stops: [0.0, 0.5, 1.0],
    );
    canvas.drawRect(rect, Paint()..shader = gradient.createShader(rect));
  }

  @override
  bool shouldRepaint(CustomPainter oldDelegate) => false;
}

// ─── Data models ───
class ThreatData {
  final String label;
  final int count;
  final Color color;
  ThreatData(this.label, this.count, this.color);
}

class DatasetSummary {
  final int totalRecords;
  final int normalRecords;
  final int attackRecords;
  final double attackPercentage;

  DatasetSummary({
    required this.totalRecords,
    required this.normalRecords,
    required this.attackRecords,
    required this.attackPercentage,
  });

  factory DatasetSummary.fromJson(Map<String, dynamic> j) => DatasetSummary(
        totalRecords: (j['total_records'] ?? 0) as int,
        normalRecords: (j['normal'] ?? 0) as int,
        attackRecords: (j['attacks'] ?? 0) as int,
        attackPercentage: ((j['attack_percentage'] ?? 0) as num).toDouble(),
      );
}

class SystemStatus {
  final String level;
  final double cpu;
  final double ram;
  final String message;
  SystemStatus(this.level, this.cpu, this.ram, this.message);

  factory SystemStatus.fromJson(Map<String, dynamic> j) => SystemStatus(
        j['level'] as String,
        (j['cpu'] as num).toDouble(),
        (j['ram'] as num).toDouble(),
        j['message'] as String,
      );
}

class SessionStats {
  final int scanned;
  final int flagged;
  final int truePos;
  final int falsePos;
  SessionStats(this.scanned, this.flagged, this.truePos, this.falsePos);

  factory SessionStats.empty() => SessionStats(0, 0, 0, 0);

  factory SessionStats.fromJson(Map<String, dynamic> j) => SessionStats(
        (j['scanned'] as num).toInt(),
        (j['flagged'] as num).toInt(),
        (j['true_pos'] as num).toInt(),
        (j['false_pos'] as num).toInt(),
      );
}

class Incident {
  final String id;
  final String severity;
  final String family;
  final double confidence;
  final String sourceIp;
  final String time;
  String status;
  final String recommendedAction;
  final String detail;
  final Map<String, dynamic> evidence;
  final String groundTruth;
  final String groundTruthFamily;
  final bool predictionCorrect;

  Incident({
    required this.id,
    required this.severity,
    required this.family,
    required this.confidence,
    required this.sourceIp,
    required this.time,
    required this.status,
    required this.recommendedAction,
    required this.detail,
    required this.evidence,
    required this.groundTruth,
    required this.groundTruthFamily,
    required this.predictionCorrect,
  });

  factory Incident.fromJson(Map<String, dynamic> j) => Incident(
        id: j['id'] as String,
        severity: j['severity'] as String,
        family: j['family'] as String,
        confidence: (j['confidence'] as num).toDouble(),
        sourceIp: j['source_ip'] as String,
        time: j['time'] as String,
        status: j['status'] as String,
        recommendedAction: j['recommended_action'] as String,
        detail: j['detail'] as String,
        evidence: Map<String, dynamic>.from(j['evidence'] as Map),
        groundTruth: j['ground_truth'] as String,
        groundTruthFamily: j['ground_truth_family'] as String,
        predictionCorrect: j['prediction_correct'] as bool,
      );

  bool get isOpen => status == 'OPEN';

  String get title {
    switch (family) {
      case 'DoS':
        return 'Denial-of-Service Attack';
      case 'Probe':
        return 'Network Probe / Scan';
      case 'R2L':
        return 'Remote Access Attempt';
      case 'U2R':
        return 'Privilege Escalation';
      default:
        return family;
    }
  }
}

class FamilyScore {
  final String family;
  final double precision;
  final double recall;
  final int support;
  FamilyScore(this.family, this.precision, this.recall, this.support);

  factory FamilyScore.fromJson(Map<String, dynamic> j) => FamilyScore(
        j['family'] as String,
        (j['precision'] as num).toDouble(),
        (j['recall'] as num).toDouble(),
        (j['support'] as num).toInt(),
      );
}

class ModelMetrics {
  final double accuracy;
  final double precision;
  final double recall;
  final double f1;
  final int testRecords;
  final List<FamilyScore> perFamily;
  final List<MapEntry<String, double>> topFeatures;
  final String note;

  ModelMetrics({
    required this.accuracy,
    required this.precision,
    required this.recall,
    required this.f1,
    required this.testRecords,
    required this.perFamily,
    required this.topFeatures,
    required this.note,
  });

  factory ModelMetrics.fromJson(Map<String, dynamic> j) {
    final b = Map<String, dynamic>.from(j['binary'] as Map);
    return ModelMetrics(
      accuracy: (j['accuracy_5class'] as num).toDouble(),
      precision: (b['precision'] as num).toDouble(),
      recall: (b['recall'] as num).toDouble(),
      f1: (b['f1'] as num).toDouble(),
      testRecords: (j['test_records'] as num).toInt(),
      perFamily: (j['per_family'] as List)
          .map((e) => FamilyScore.fromJson(Map<String, dynamic>.from(e as Map)))
          .toList(),
      topFeatures: (j['top_features'] as List)
          .map((e) => MapEntry<String, double>(
              e['feature'] as String, (e['importance'] as num).toDouble()))
          .toList(),
      note: (j['note'] ?? '') as String,
    );
  }
}

// ─── Screen ───
class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});
  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen>
    with TickerProviderStateMixin {
  List<Incident> alerts = [];
  SystemStatus? system;
  SessionStats session = SessionStats.empty();
  int blockedCount = 0;
  ModelMetrics? metrics;

  List<ThreatData> threatDistribution = [];
  DatasetSummary? datasetSummary;
  int totalThreats = 0;

  bool isLoading = true;
  String? errorMessage;
  bool autoRefresh = true;
  bool _fetching = false;
  Timer? _timer;

  late AnimationController _pulseController;
  late AnimationController _chartController;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1500),
    )..repeat(reverse: true);
    _chartController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1800),
    );

    fetchAll();
    _timer = Timer.periodic(kRefreshEvery, (_) {
      if (autoRefresh) fetchAll();
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    _pulseController.dispose();
    _chartController.dispose();
    super.dispose();
  }

  // ── Networking ──
  Future<void> fetchAll() async {
    if (_fetching) return;
    _fetching = true;
    try {
      await fetchAlerts();
      if (errorMessage == null) {
        if (metrics == null) await fetchMetrics();
        if (threatDistribution.isEmpty) await fetchThreatStats();
      }
    } finally {
      _fetching = false;
      if (mounted) setState(() => isLoading = false);
    }
  }

  Future<void> fetchAlerts() async {
    try {
      final response = await http
          .get(Uri.parse('$kApiBase/api/alerts'))
          .timeout(const Duration(seconds: 15));
      if (!mounted) return;
      if (response.statusCode == 200) {
        final data = json.decode(response.body) as Map<String, dynamic>;
        final fresh = (data['alerts'] as List)
            .map((e) => Incident.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList();
        final freshIds = fresh.map((e) => e.id).toSet();
        setState(() {
          alerts = [
            ...fresh,
            ...alerts.where((a) => !freshIds.contains(a.id)),
          ].take(12).toList();
          system = SystemStatus.fromJson(
              Map<String, dynamic>.from(data['system'] as Map));
          session = SessionStats.fromJson(
              Map<String, dynamic>.from(data['session'] as Map));
          blockedCount = (data['blocked_count'] as num).toInt();
          errorMessage = null;
        });
      } else if (response.statusCode == 503) {
        setState(() => errorMessage =
            'Backend is up but the model is still training. Retrying...');
      } else {
        setState(() => errorMessage = 'Backend error ${response.statusCode}');
      }
    } catch (e) {
      debugPrint('Alerts error: $e');
      if (mounted) {
        setState(() => errorMessage =
            'Cannot reach backend at $kApiBase. Start sentinel_bridge.py.');
      }
    }
  }

  Future<void> fetchMetrics() async {
    try {
      final response = await http
          .get(Uri.parse('$kApiBase/api/metrics'))
          .timeout(const Duration(seconds: 15));
      if (response.statusCode == 200 && mounted) {
        setState(() => metrics = ModelMetrics.fromJson(
            json.decode(response.body) as Map<String, dynamic>));
      }
    } catch (e) {
      debugPrint('Metrics error: $e');
    }
  }

  Future<void> fetchThreatStats() async {
    try {
      final response = await http
          .get(Uri.parse('$kApiBase/api/threat-stats'))
          .timeout(const Duration(seconds: 15));
      if (response.statusCode != 200 || !mounted) return;

      final data = json.decode(response.body) as Map<String, dynamic>;
      final threats = (data['threats'] as Map)
          .map((k, v) => MapEntry(k.toString(), (v as num).toInt()));

      const attackColors = <String, Color>{
        'neptune': Color(0xFFFF6E40),
        'smurf': Color(0xFFFF5252),
        'back': Color(0xFFFF4081),
        'teardrop': Color(0xFFE040FB),
        'pod': Color(0xFF7C4DFF),
        'land': Color(0xFF536DFE),
        'satan': Color(0xFF69F0AE),
        'ipsweep': Color(0xFF00E676),
        'nmap': Color(0xFF76FF03),
        'portsweep': Color(0xFFEEFF41),
        'mscan': Color(0xFFFFD740),
      };

      final sorted = threats.entries.toList()
        ..sort((a, b) => b.value.compareTo(a.value));
      final top = sorted.take(6).toList();
      final others = sorted.skip(6).fold<int>(0, (s, e) => s + e.value);

      setState(() {
        threatDistribution = top
            .map((e) => ThreatData(e.key.toUpperCase(), e.value,
                attackColors[e.key.toLowerCase()] ?? const Color(0xFF9E9E9E)))
            .toList();
        if (others > 0) {
          threatDistribution
              .add(ThreatData('OTHERS', others, const Color(0xFF616161)));
        }
        totalThreats = threats.values.fold<int>(0, (s, v) => s + v);
        datasetSummary = DatasetSummary.fromJson(
            Map<String, dynamic>.from(data['summary'] as Map));
        _chartController.forward(from: 0);
      });
    } catch (e) {
      debugPrint('Stats error: $e');
    }
  }

  Future<void> respondTo(Incident inc) async {
    try {
      final response = await http
          .post(Uri.parse('$kApiBase/api/incidents/${inc.id}/respond'))
          .timeout(const Duration(seconds: 10));
      if (response.statusCode == 200 && mounted) {
        final data = json.decode(response.body) as Map<String, dynamic>;
        setState(() {
          inc.status = 'MITIGATED';
          blockedCount =
              (data['blocked_count'] as num?)?.toInt() ?? blockedCount;
        });
      }
    } catch (e) {
      debugPrint('Respond error: $e');
    }
  }

  // ── Helpers ──
  Color severityColor(String s) {
    switch (s) {
      case 'CRITICAL':
        return kOrange;
      case 'WARNING':
        return kAmber;
      default:
        return kCyan;
    }
  }

  Widget panel(
      {required Widget child, Color border = kCyan, double radius = 16}) {
    return Container(
      padding: const EdgeInsets.all(16),
      margin: const EdgeInsets.only(bottom: 14),
      decoration: BoxDecoration(
        color: kPanel.withOpacity(0.9),
        borderRadius: BorderRadius.circular(radius),
        border: Border.all(color: border.withOpacity(0.3)),
      ),
      child: child,
    );
  }

  Widget chip(String text, Color c) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: c.withOpacity(0.12),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: c.withOpacity(0.35)),
      ),
      child: Text(text,
          style:
              TextStyle(fontSize: 10, color: c, fontWeight: FontWeight.w700)),
    );
  }

  Widget sectionTitle(IconData icon, String text, Color color,
      {Widget? trailing}) {
    return Row(
      children: [
        Icon(icon, color: color, size: 18),
        const SizedBox(width: 8),
        Expanded(
          child: Text(text,
              style: const TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 1.5,
                  color: Colors.white)),
        ),
        if (trailing != null) trailing,
      ],
    );
  }

  // ── Build ──
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: CustomPaint(
        painter: CleanBackgroundPainter(),
        child: SafeArea(
          child: Column(
            children: [
              _buildHeader(),
              Expanded(
                child: isLoading
                    ? const Center(
                        child: CircularProgressIndicator(color: kCyan))
                    : RefreshIndicator(
                        onRefresh: fetchAll,
                        color: kCyan,
                        backgroundColor: kPanel,
                        child: ListView(
                          physics: const AlwaysScrollableScrollPhysics(
                              parent: BouncingScrollPhysics()),
                          padding: const EdgeInsets.symmetric(
                              horizontal: 16, vertical: 8),
                          children: [
                            if (errorMessage != null) _buildErrorBanner(),
                            if (system != null) _buildSystemCard(system!),
                            _buildAlertsSection(),
                            _buildSessionRow(),
                            const SizedBox(height: 14),
                            if (metrics != null) _buildMetricsCard(metrics!),
                            _buildThreatChart(),
                            const SizedBox(height: 20),
                          ],
                        ),
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      margin: const EdgeInsets.all(16),
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      decoration: BoxDecoration(
        color: kPanel.withOpacity(0.9),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: kCyan.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text("AI-Driven AIOps",
                    style: TextStyle(
                        fontSize: 22,
                        fontWeight: FontWeight.w900,
                        letterSpacing: 1.5,
                        color: kCyan)),
                const SizedBox(height: 4),
                Text("Threat Detection & Incident Response",
                    style: TextStyle(
                        fontSize: 11,
                        letterSpacing: 1.2,
                        color: kCyan.withOpacity(0.8),
                        fontWeight: FontWeight.w500)),
                const SizedBox(height: 6),
                chip("ML DETECTION  |  NSL-KDD REPLAY MODE", kGreen),
              ],
            ),
          ),
          IconButton(
            tooltip: autoRefresh ? 'Pause auto-refresh' : 'Resume auto-refresh',
            onPressed: () => setState(() => autoRefresh = !autoRefresh),
            icon: Icon(
              autoRefresh
                  ? Icons.pause_circle_outline
                  : Icons.play_circle_outline,
              color: kCyan,
              size: 28,
            ),
          ),
          FadeTransition(
            opacity: _pulseController,
            child: Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: kNavy,
                border: Border.all(color: kCyan.withOpacity(0.5)),
              ),
              child: const Icon(Icons.psychology, color: kCyan, size: 28),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildErrorBanner() {
    return panel(
      border: kOrange,
      child: Row(
        children: [
          const Icon(Icons.cloud_off, color: kOrange),
          const SizedBox(width: 12),
          Expanded(
            child: Text(errorMessage!,
                style: const TextStyle(fontSize: 13, color: Colors.white70)),
          ),
          TextButton(onPressed: fetchAll, child: const Text('RETRY')),
        ],
      ),
    );
  }

  Widget _buildSystemCard(SystemStatus s) {
    final c = severityColor(s.level);
    return panel(
      border: c,
      child: Row(
        children: [
          Icon(
              s.level == 'INFO'
                  ? Icons.check_circle_outline
                  : Icons.warning_amber_rounded,
              color: c,
              size: 28),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                    "System Health: CPU ${s.cpu.toStringAsFixed(1)}% | RAM ${s.ram.toStringAsFixed(1)}%",
                    style: const TextStyle(
                        fontSize: 15, fontWeight: FontWeight.w800)),
                const SizedBox(height: 4),
                Text(s.message,
                    style: TextStyle(
                        fontSize: 12, color: Colors.white.withOpacity(0.6))),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAlertsSection() {
    if (alerts.isEmpty) {
      return panel(
        child: Text(
          errorMessage == null
              ? 'No threats flagged yet. Waiting for the next traffic window...'
              : 'No data available.',
          style: const TextStyle(color: Colors.white54, fontSize: 13),
        ),
      );
    }
    return Column(children: alerts.map(_buildAlertCard).toList());
  }

  Widget _buildAlertCard(Incident inc) {
    final c = severityColor(inc.severity);
    final mitigated = !inc.isOpen;
    final shown = mitigated ? kGreen : c;

    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      decoration: BoxDecoration(
        color: kPanel.withOpacity(0.9),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: shown.withOpacity(0.4), width: 1.5),
      ),
      child: Theme(
        data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
        child: ExpansionTile(
          key: PageStorageKey<String>(inc.id),
          tilePadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
          childrenPadding: const EdgeInsets.fromLTRB(20, 0, 20, 16),
          iconColor: Colors.white70,
          collapsedIconColor: Colors.white38,
          leading: Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: shown.withOpacity(0.15),
              border: Border.all(color: shown.withOpacity(0.5)),
            ),
            child: Icon(mitigated ? Icons.shield : Icons.warning_amber_rounded,
                color: shown, size: 24),
          ),
          title: Text(inc.title,
              style: const TextStyle(
                  fontWeight: FontWeight.w800,
                  fontSize: 16,
                  letterSpacing: 0.5)),
          subtitle: Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Wrap(
              spacing: 8,
              runSpacing: 6,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                chip(inc.severity, c),
                chip("${(inc.confidence * 100).toStringAsFixed(0)}% confidence",
                    kPurple),
                if (mitigated) chip("MITIGATED", kGreen),
                Text(inc.sourceIp,
                    style: TextStyle(
                        color: Colors.white.withOpacity(0.6),
                        fontSize: 12,
                        fontFamily: 'monospace')),
                Text(inc.time,
                    style: TextStyle(
                        color: Colors.white.withOpacity(0.6),
                        fontSize: 12,
                        fontFamily: 'monospace')),
              ],
            ),
          ),
          children: [
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.3),
                borderRadius: BorderRadius.circular(12),
                border: Border(left: BorderSide(color: shown, width: 4)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(inc.detail,
                      style: TextStyle(
                          color: Colors.white.withOpacity(0.85),
                          fontSize: 13,
                          height: 1.5)),
                  const SizedBox(height: 12),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Icon(Icons.auto_awesome, color: shown, size: 16),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text("Recommended: ${inc.recommendedAction}",
                            style: TextStyle(
                                color: shown,
                                fontSize: 13,
                                fontWeight: FontWeight.w600)),
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),
                  Text("EVIDENCE (model inputs)",
                      style: TextStyle(
                          fontSize: 10,
                          letterSpacing: 1.2,
                          color: Colors.white.withOpacity(0.45),
                          fontWeight: FontWeight.w700)),
                  const SizedBox(height: 6),
                  Wrap(
                    spacing: 6,
                    runSpacing: 6,
                    children: inc.evidence.entries
                        .map((e) => chip("${e.key}: ${e.value}", kCyan))
                        .toList(),
                  ),
                  const SizedBox(height: 14),
                  Row(
                    children: [
                      chip(
                          inc.predictionCorrect
                              ? "REPLAY CHECK: CORRECT"
                              : "REPLAY CHECK: FALSE POSITIVE / WRONG TYPE",
                          inc.predictionCorrect ? kGreen : kOrange),
                      const SizedBox(width: 8),
                      Flexible(
                        child: Text("dataset label: ${inc.groundTruth}",
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                                fontSize: 11,
                                color: Colors.white.withOpacity(0.5))),
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),
                  if (inc.isOpen)
                    ElevatedButton.icon(
                      onPressed: () => respondTo(inc),
                      icon: const Icon(Icons.block, size: 18),
                      label: const Text("EXECUTE RESPONSE (simulated block)"),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: c,
                        foregroundColor: Colors.black,
                      ),
                    )
                  else
                    Text("Source ${inc.sourceIp} added to blocklist.",
                        style: const TextStyle(color: kGreen, fontSize: 12)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSessionRow() {
    return Row(
      children: [
        _statBlock("SCANNED", "${session.scanned}", Icons.radar, kCyan,
            "records this session"),
        const SizedBox(width: 8),
        _statBlock("FLAGGED", "${session.flagged}", Icons.warning_rounded,
            kOrange, "${session.truePos} true / ${session.falsePos} false"),
        const SizedBox(width: 8),
        _statBlock("BLOCKED", "$blockedCount", Icons.shield, kGreen,
            "IPs on blocklist"),
      ],
    );
  }

  Widget _statBlock(
      String label, String value, IconData icon, Color color, String subtitle) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
        decoration: BoxDecoration(
          color: kPanel.withOpacity(0.9),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withOpacity(0.3)),
        ),
        child: Column(
          children: [
            Icon(icon, color: color, size: 20),
            const SizedBox(height: 6),
            Text(value,
                style: TextStyle(
                    fontSize: 18, fontWeight: FontWeight.w900, color: color)),
            const SizedBox(height: 2),
            Text(label,
                style: TextStyle(
                    fontSize: 9,
                    color: Colors.white.withOpacity(0.5),
                    letterSpacing: 1,
                    fontWeight: FontWeight.w600)),
            const SizedBox(height: 2),
            Text(subtitle,
                style: TextStyle(
                    fontSize: 8, color: Colors.white.withOpacity(0.35)),
                textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }

  Widget _buildMetricsCard(ModelMetrics m) {
    String pct(double v) => "${(v * 100).toStringAsFixed(1)}%";

    Color recallColor(double r) =>
        r >= 0.7 ? kGreen : (r >= 0.3 ? kAmber : kOrange);

    return panel(
      border: kPurple,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          sectionTitle(Icons.analytics, "MODEL PERFORMANCE", kPurple,
              trailing: chip("KDDTest+  ${m.testRecords} unseen", kPurple)),
          const SizedBox(height: 16),
          Row(
            children: [
              _statBlock(
                  "ACCURACY", pct(m.accuracy), Icons.percent, kCyan, "5-class"),
              const SizedBox(width: 8),
              _statBlock("PRECISION", pct(m.precision), Icons.gps_fixed, kGreen,
                  "attack vs normal"),
              const SizedBox(width: 8),
              _statBlock("RECALL", pct(m.recall), Icons.track_changes, kAmber,
                  "attack vs normal"),
              const SizedBox(width: 8),
              _statBlock(
                  "F1", pct(m.f1), Icons.balance, kPurple, "attack vs normal"),
            ],
          ),
          const SizedBox(height: 18),
          Text("DETECTION RATE (RECALL) BY ATTACK FAMILY",
              style: TextStyle(
                  fontSize: 10,
                  letterSpacing: 1.2,
                  color: Colors.white.withOpacity(0.45),
                  fontWeight: FontWeight.w700)),
          const SizedBox(height: 8),
          ...m.perFamily.map((f) {
            final c = recallColor(f.recall);
            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: Row(
                children: [
                  SizedBox(
                    width: 64,
                    child: Text(f.family,
                        style: const TextStyle(
                            fontSize: 11, fontWeight: FontWeight.w700)),
                  ),
                  Expanded(
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(4),
                      child: LinearProgressIndicator(
                        value: f.recall.clamp(0.0, 1.0),
                        minHeight: 8,
                        color: c,
                        backgroundColor: Colors.white.withOpacity(0.08),
                      ),
                    ),
                  ),
                  SizedBox(
                    width: 96,
                    child: Text("${pct(f.recall)}  (n=${f.support})",
                        textAlign: TextAlign.right,
                        style: TextStyle(
                            fontSize: 10,
                            color: c,
                            fontWeight: FontWeight.w700)),
                  ),
                ],
              ),
            );
          }),
          const SizedBox(height: 14),
          Text("TOP FEATURES DRIVING PREDICTIONS",
              style: TextStyle(
                  fontSize: 10,
                  letterSpacing: 1.2,
                  color: Colors.white.withOpacity(0.45),
                  fontWeight: FontWeight.w700)),
          const SizedBox(height: 6),
          Wrap(
            spacing: 6,
            runSpacing: 6,
            children: m.topFeatures
                .take(6)
                .map((e) => chip(
                    "${e.key} ${(e.value * 100).toStringAsFixed(1)}%", kCyan))
                .toList(),
          ),
          if (m.note.isNotEmpty) ...[
            const SizedBox(height: 12),
            Text(m.note,
                style: TextStyle(
                    fontSize: 11,
                    height: 1.4,
                    color: Colors.white.withOpacity(0.45),
                    fontStyle: FontStyle.italic)),
          ],
        ],
      ),
    );
  }

  Widget _buildThreatChart() {
    if (threatDistribution.isEmpty) return const SizedBox.shrink();

    final s = datasetSummary;
    return panel(
      border: kPurple,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          sectionTitle(
              Icons.donut_large, "NSL-KDD THREAT DISTRIBUTION", kPurple,
              trailing: chip("KDDTrain+", kPurple)),
          if (s != null) ...[
            const SizedBox(height: 6),
            Text(
                "${s.totalRecords} training records, ${s.attackPercentage}% attacks",
                style: TextStyle(
                    fontSize: 11, color: Colors.white.withOpacity(0.45))),
          ],
          const SizedBox(height: 16),
          SizedBox(
            height: 200,
            child: Row(
              children: [
                Expanded(
                  flex: 3,
                  child: AnimatedBuilder(
                    animation: _chartController,
                    builder: (context, child) {
                      return CustomPaint(
                        painter: CleanPieChartPainter(
                            threatDistribution, _chartController.value),
                        child: Center(
                          child: Column(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              Text(
                                  "${(totalThreats / 1000).toStringAsFixed(1)}K",
                                  style: const TextStyle(
                                      fontSize: 26,
                                      fontWeight: FontWeight.w900)),
                              Text("ATTACKS",
                                  style: TextStyle(
                                      fontSize: 9,
                                      color: Colors.white.withOpacity(0.5),
                                      letterSpacing: 1.5)),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  flex: 2,
                  child: ListView.builder(
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    itemCount: threatDistribution.length,
                    itemBuilder: (context, index) {
                      final t = threatDistribution[index];
                      final pct = totalThreats > 0
                          ? ((t.count / totalThreats) * 100).toStringAsFixed(1)
                          : "0";
                      return Padding(
                        padding: const EdgeInsets.symmetric(vertical: 3),
                        child: Row(
                          children: [
                            Container(
                              width: 10,
                              height: 10,
                              decoration: BoxDecoration(
                                  shape: BoxShape.circle, color: t.color),
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(t.label,
                                  style: TextStyle(
                                      fontSize: 10,
                                      color: Colors.white.withOpacity(0.8),
                                      fontWeight: FontWeight.w600),
                                  overflow: TextOverflow.ellipsis),
                            ),
                            Text("$pct%",
                                style: TextStyle(
                                    fontSize: 10,
                                    fontWeight: FontWeight.w800,
                                    color: t.color)),
                          ],
                        ),
                      );
                    },
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ─── Donut chart painter ───
class CleanPieChartPainter extends CustomPainter {
  final List<ThreatData> data;
  final double animationValue;

  CleanPieChartPainter(this.data, this.animationValue);

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = math.min(size.width, size.height) / 2 - 10;
    final total = data.fold<int>(0, (sum, item) => sum + item.count);
    if (total == 0) return;

    double startAngle = -math.pi / 2;
    for (final item in data) {
      final sweep = (item.count / total) * 2 * math.pi * animationValue;
      final paint = Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 16
        ..strokeCap = StrokeCap.butt
        ..color = item.color;
      canvas.drawArc(Rect.fromCircle(center: center, radius: radius),
          startAngle, sweep, false, paint);
      startAngle += sweep + 0.02;
    }

    canvas.drawCircle(
      center,
      radius - 20,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1
        ..color = Colors.white.withOpacity(0.1),
    );
  }

  @override
  bool shouldRepaint(CleanPieChartPainter old) =>
      old.animationValue != animationValue || old.data != data;
}
