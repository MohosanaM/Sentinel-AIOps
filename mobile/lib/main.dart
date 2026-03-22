import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

void main() => runApp(const SentinelAIOps());

class SentinelAIOps extends StatelessWidget {
  const SentinelAIOps({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        // TWEAK 1: Deep Midnight Blue Palette
        scaffoldBackgroundColor: const Color(0xFF0A0E21),
        primaryColor: const Color(0xFF03DAC6), // Teal for "Safe"
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

class _DashboardScreenState extends State<DashboardScreen> with SingleTickerProviderStateMixin {
  List alerts = [];
  bool isLoading = true;
  late AnimationController _pulseController;

  @override
  void initState() {
    super.initState();
    // TWEAK 2: Initialize Pulse Animation for "Live Engine"
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 1),
    )..repeat(reverse: true);
    fetchAlerts();
  }

  @override
  void dispose() {
    _pulseController.dispose();
    super.dispose();
  }

  // --- THE BRIDGE CONNECTION ---
  Future<void> fetchAlerts() async {
    setState(() => isLoading = true);
    try {
      // Connects to your Python Flask server
      // IMPORTANT: Replace with your laptop's IP address (e.g., http://192.168.x.x:5000/api/alerts)
      final response = await http.get(Uri.parse('http://192.168.0.100:5000/api/alerts'));

      if (response.statusCode == 200) {
        setState(() {
          alerts = json.decode(response.body);
          isLoading = false;
        });
      }
    } catch (e) {
      print("Connection Error: $e");
      setState(() => isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // TWEAK 2: Glowing Pulse Dot
            FadeTransition(
              opacity: _pulseController,
              child: const Icon(Icons.circle, color: Colors.redAccent, size: 12),
            ),
            const SizedBox(width: 10),
            const Text('SENTINEL | LIVE ENGINE',
                style: TextStyle(letterSpacing: 2, fontWeight: FontWeight.bold, fontSize: 16)),
          ],
        ),
        backgroundColor: Colors.black,
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh, color: Color(0xFF03DAC6)),
            onPressed: fetchAlerts,
          )
        ],
      ),
      body: isLoading
          ? const Center(child: CircularProgressIndicator(color: Color(0xFF03DAC6)))
          : alerts.isEmpty
          ? const Center(child: Text("No live threats detected.", style: TextStyle(color: Colors.grey)))
          : Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
            child: Text("AI-DRIVEN INCIDENT RESPONSE FEED",
                style: TextStyle(color: Colors.grey, fontSize: 10, letterSpacing: 1.5, fontWeight: FontWeight.bold)),
          ),
          Expanded(
            child: ListView.builder(
              physics: const BouncingScrollPhysics(),
              padding: const EdgeInsets.all(12),
              itemCount: alerts.length,
              itemBuilder: (context, index) {
                final item = alerts[index];
                Color statusColor = item['type'] == "CRITICAL" ? Colors.redAccent : Colors.orangeAccent;

                return Card(
                  color: const Color(0xFF1A1F38), // TWEAK 3: Deep Navy Cards
                  margin: const EdgeInsets.symmetric(vertical: 8),
                  // TWEAK 3: Glassy/Cyber Border
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(15),
                    side: BorderSide(color: statusColor.withOpacity(0.4), width: 1),
                  ),
                  elevation: 0,
                  child: ExpansionTile(
                    iconColor: Colors.white,
                    collapsedIconColor: Colors.white70,
                    leading: Icon(Icons.security, color: statusColor),
                    title: Text(item['msg'],
                        style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 14)),
                    subtitle: Text("SOURCE IP: ${item['ip']} | ${item['time']}",
                        style: const TextStyle(color: Colors.white54, fontSize: 11)),
                    children: [
                      Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(16.0),
                        decoration: BoxDecoration(
                            color: Colors.black26,
                            borderRadius: const BorderRadius.only(bottomLeft: Radius.circular(15), bottomRight: Radius.circular(15))
                        ),
                        child: Row(
                          children: [
                            const Icon(Icons.auto_awesome, color: Color(0xFF03DAC6), size: 16),
                            const SizedBox(width: 10),
                            Expanded(
                              child: Text(item['remediation'],
                                  style: const TextStyle(color: Color(0xFF03DAC6), fontSize: 13, fontStyle: FontStyle.italic)),
                            ),
                          ],
                        ),
                      )
                    ],
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}