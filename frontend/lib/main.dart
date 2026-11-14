import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const SentinelApp());
}

class SentinelApp extends StatelessWidget {
  const SentinelApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Sentinel AIOps Dashboard',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0F172A),
        cardColor: const Color(0xFF1E293B),
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.cyan,
          brightness: Brightness.dark,
        ),
      ),
      home: const DashboardScreen(),
    );
  }
}

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  final String _baseUrl = const String.fromEnvironment('API_BASE',
      defaultValue: 'http://127.0.0.1:5000');
  bool _loading = false;
  Map<String, dynamic>? _dashboardData;
  String? _error;

  // URL Scanner state
  final TextEditingController _urlController = TextEditingController();
  bool _scanningUrl = false;
  Map<String, dynamic>? _scanResult;
  String? _scanError;

  @override
  void initState() {
    super.initState();
    _fetchDashboard();
  }

  Future<void> _fetchDashboard() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final response = await http.get(Uri.parse('$_baseUrl/api/alerts'));
      if (response.statusCode == 200) {
        setState(() {
          _dashboardData = json.decode(response.body);
          _loading = false;
        });
      } else {
        setState(() {
          _error = 'Backend returned status code ${response.statusCode}';
          _loading = false;
        });
      }
    } catch (e) {
      setState(() {
        _error = 'Cannot connect to Sentinel Bridge backend ($e)';
        _loading = false;
      });
    }
  }

  Future<void> _scanUrl() async {
    final url = _urlController.text.trim();
    if (url.isEmpty) return;

    setState(() {
      _scanningUrl = true;
      _scanResult = null;
      _scanError = null;
    });

    try {
      final response = await http.post(
        Uri.parse('$_baseUrl/api/scan-url'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({'url': url}),
      );
      if (response.statusCode == 200) {
        setState(() {
          _scanResult = json.decode(response.body);
          _scanningUrl = false;
        });
      } else {
        setState(() {
          _scanError = response.statusCode == 429
              ? 'Too many scans. Wait a minute and try again.'
              : 'Scan failed (Code ${response.statusCode})';
          _scanningUrl = false;
        });
      }
    } catch (e) {
      setState(() {
        _scanError = 'Error connecting to analysis engine: $e';
        _scanningUrl = false;
      });
    }
  }

  Color _scanColor() {
    final v = _scanResult?['verdict'];
    if (v == 'SUSPICIOUS') return Colors.redAccent;
    if (v == 'UNKNOWN') return Colors.amberAccent;
    return Colors.greenAccent;
  }

  IconData _scanIcon() {
    final v = _scanResult?['verdict'];
    if (v == 'SUSPICIOUS') return Icons.warning_amber_rounded;
    if (v == 'UNKNOWN') return Icons.help_outline;
    return Icons.check_circle_outline;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Row(
          children: [
            Icon(Icons.shield_outlined, color: Colors.cyan),
            SizedBox(width: 12),
            Text('SENTINEL AIOPS PORTFOLIO PLATFORM',
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18)),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh Dashboard',
            onPressed: _fetchDashboard,
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // URL Threat Scanner Section (Stage 2 Feature)
            Card(
              elevation: 4,
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12)),
              child: Padding(
                padding: const EdgeInsets.all(20.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Row(
                      children: [
                        Icon(Icons.link, color: Colors.cyanAccent),
                        SizedBox(width: 8),
                        Text(
                          'Hybrid URL Threat & Phishing Intelligence',
                          style: TextStyle(
                              fontSize: 18, fontWeight: FontWeight.bold),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Checks a link with rule-based heuristics and the URLhaus malware-URL list. A hit means likely malicious. No hit is not a guarantee of safety.',
                      style: TextStyle(color: Colors.white70, fontSize: 13),
                    ),
                    const SizedBox(height: 16),
                    Row(
                      children: [
                        Expanded(
                          child: TextField(
                            controller: _urlController,
                            decoration: InputDecoration(
                              hintText:
                                  'Enter URL to evaluate (e.g., http://example.com/login)',
                              filled: true,
                              fillColor: const Color(0xFF0F172A),
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(8),
                                borderSide: BorderSide.none,
                              ),
                              contentPadding: const EdgeInsets.symmetric(
                                  horizontal: 16, vertical: 14),
                            ),
                            onSubmitted: (_) => _scanUrl(),
                          ),
                        ),
                        const SizedBox(width: 12),
                        ElevatedButton.icon(
                          onPressed: _scanningUrl ? null : _scanUrl,
                          style: ElevatedButton.styleFrom(
                            backgroundColor: Colors.cyan,
                            foregroundColor: Colors.black,
                            padding: const EdgeInsets.symmetric(
                                horizontal: 20, vertical: 16),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                            ),
                          ),
                          icon: _scanningUrl
                              ? const SizedBox(
                                  width: 16,
                                  height: 16,
                                  child: CircularProgressIndicator(
                                      strokeWidth: 2, color: Colors.black),
                                )
                              : const Icon(Icons.security),
                          label: const Text('Scan URL',
                              style: TextStyle(fontWeight: FontWeight.bold)),
                        ),
                      ],
                    ),
                    if (_scanError != null) ...[
                      const SizedBox(height: 12),
                      Text(_scanError!,
                          style: const TextStyle(color: Colors.redAccent)),
                    ],
                    if (_scanResult != null) ...[
                      const SizedBox(height: 20),
                      Container(
                        padding: const EdgeInsets.all(16),
                        decoration: BoxDecoration(
                          color: const Color(0xFF0F172A),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(
                            color: _scanColor(),
                            width: 1.5,
                          ),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                Row(
                                  children: [
                                    Icon(
                                      _scanIcon(),
                                      color: _scanColor(),
                                    ),
                                    const SizedBox(width: 8),
                                    Text(
                                      '${_scanResult!['verdict_label'] ?? _scanResult!['verdict']}',
                                      style: TextStyle(
                                        fontSize: 16,
                                        fontWeight: FontWeight.bold,
                                        color: _scanColor(),
                                      ),
                                    ),
                                  ],
                                ),
                                Text(
                                  'Heuristic risk: ${_scanResult!['risk_score']}/100',
                                  style: const TextStyle(
                                      fontWeight: FontWeight.bold),
                                ),
                              ],
                            ),
                            const Divider(height: 20),
                            const Text('Analysis Breakdown:',
                                style: TextStyle(
                                    fontWeight: FontWeight.bold, fontSize: 13)),
                            const SizedBox(height: 6),
                            ...(_scanResult!['reasons'] as List)
                                .map((r) => Padding(
                                      padding:
                                          const EdgeInsets.only(bottom: 4.0),
                                      child: Row(
                                        children: [
                                          const Icon(Icons.arrow_right,
                                              size: 16, color: Colors.cyan),
                                          const SizedBox(width: 4),
                                          Expanded(
                                              child: Text(r,
                                                  style: const TextStyle(
                                                      fontSize: 13,
                                                      color: Colors.white70))),
                                        ],
                                      ),
                                    )),
                          ],
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Core AIOps Replay Dashboard Section
            const Text(
              'AIOps Intrusion Detection Feed',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            if (_loading)
              const Center(
                  child: Padding(
                padding: EdgeInsets.all(40.0),
                child: CircularProgressIndicator(),
              ))
            else if (_error != null)
              Card(
                color: Colors.red.withOpacity(0.2),
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Text(_error!,
                      style: const TextStyle(color: Colors.redAccent)),
                ),
              )
            else if (_dashboardData != null) ...[
              // Summary Stat Cards
              Row(
                children: [
                  _statCard(
                      'Session Scanned',
                      '${_dashboardData!['session']['scanned']}',
                      Icons.radar,
                      Colors.blue),
                  const SizedBox(width: 16),
                  _statCard(
                      'Threats Flagged',
                      '${_dashboardData!['session']['flagged']}',
                      Icons.warning,
                      Colors.orange),
                  const SizedBox(width: 16),
                  _statCard(
                      'Server CPU',
                      '${_dashboardData!['system']['cpu']}%',
                      Icons.memory,
                      Colors.cyan),
                ],
              ),
              const SizedBox(height: 24),
              const Text('Active Threat Incidents',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
              const SizedBox(height: 12),
              ...(_dashboardData!['alerts'] as List).map((alert) => Card(
                    margin: const EdgeInsets.only(bottom: 12),
                    child: ListTile(
                      leading: CircleAvatar(
                        backgroundColor: alert['severity'] == 'CRITICAL'
                            ? Colors.red.withOpacity(0.2)
                            : Colors.orange.withOpacity(0.2),
                        child: Icon(
                          alert['severity'] == 'CRITICAL'
                              ? Icons.error_outline
                              : Icons.warning_amber,
                          color: alert['severity'] == 'CRITICAL'
                              ? Colors.red
                              : Colors.orange,
                        ),
                      ),
                      title: Text(
                        '${alert['family']} Attack Detected (${alert['source_ip']})',
                        style: const TextStyle(fontWeight: FontWeight.bold),
                      ),
                      subtitle: Text(
                        'Action: ${alert['recommended_action']}\nDetail: ${alert['detail']}',
                        style: const TextStyle(fontSize: 12),
                      ),
                      trailing: Text(
                        '${(alert['confidence'] * 100).toStringAsFixed(1)}% model confidence',
                        style: const TextStyle(
                            fontWeight: FontWeight.bold, color: Colors.cyan),
                      ),
                    ),
                  )),
            ],
          ],
        ),
      ),
    );
  }

  Widget _statCard(
      String title, String value, IconData icon, Color accentColor) {
    return Expanded(
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Row(
            children: [
              Icon(icon, color: accentColor, size: 32),
              const SizedBox(width: 16),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title,
                      style:
                          const TextStyle(color: Colors.white70, fontSize: 12)),
                  const SizedBox(height: 4),
                  Text(value,
                      style: const TextStyle(
                          fontSize: 20, fontWeight: FontWeight.bold)),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
