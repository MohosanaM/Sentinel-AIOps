from flask import Flask, jsonify
from flask_cors import CORS
import random
import psutil # TWEAK 1: Real-time System Monitoring
from datetime import datetime

app = Flask(__name__)
CORS(app) 

# --- AIOps THREAT DATABASE (Simulated Knowledge) ---
THREAT_TYPES = [
    {"msg": "SQL Injection Pattern Identified", "type": "CRITICAL", "remediation": "AI ACTION: Deep Packet Inspection triggered. Source blocked."},
    {"msg": "Unauthorized SSH Brute Force", "type": "CRITICAL", "remediation": "AI ACTION: Port 22 isolated. MFA challenge issued."},
    {"msg": "Anomalous Traffic Spike (DDoS)", "type": "WARNING", "remediation": "AI INSIGHT: Rate limiting engaged. Scrubbing traffic."},
    {"msg": "Exfiltration Pattern Detected", "type": "CRITICAL", "remediation": "AI ACTION: Data egress halted. Session terminated."},
    {"msg": "Unusual Port Scanning", "type": "WARNING", "remediation": "AI INSIGHT: Pattern suggests reconnaissance phase."}
]

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    current_time = datetime.now().strftime("%H:%M:%S")
    
    # TWEAK 2: FETCH REAL DATA FROM YOUR COMPUTER
    cpu_usage = psutil.cpu_percent(interval=0.5) # Captures CPU over 0.5s
    ram_usage = psutil.virtual_memory().percent
    
    # --- LOGIC: GENERATE THE HYBRID PAYLOAD ---
    live_incidents = []

    # 1. Add the "Real-Time Health" Incident
    if cpu_usage > 80:
        health_alert = {
            "type": "CRITICAL",
            "msg": f"CPU Thermal Throttling: {cpu_usage}% Load",
            "ip": "Local-System",
            "time": current_time,
            "remediation": "AI ACTION: Terminating non-critical processes to prevent hardware failure."
        }
    else:
        health_alert = {
            "type": "INFO",
            "msg": f"System Health: CPU {cpu_usage}% | RAM {ram_usage}%",
            "ip": "Local-System",
            "time": current_time,
            "remediation": "AI STATUS: System performance within optimal parameters."
        }
    live_incidents.append(health_alert)

    # 2. Add 2 Random "Simulated" Security Threats
    selected_threats = random.sample(THREAT_TYPES, 2)
    for threat in selected_threats:
        live_incidents.append({
            "type": threat['type'],
            "msg": threat['msg'],
            "ip": f"192.168.1.{random.randint(10, 250)}",
            "time": current_time,
            "remediation": threat['remediation']
        })

    # TWEAK 3: Professional Terminal Telemetry
    print(f"\n[{current_time}] 🛰️  REAL-TIME TELEMETRY DISPATCHED")
    print(f"   >>> CPU: {cpu_usage}% | RAM: {ram_usage}%")
    print(f"   >>> Threats Identified: {len(live_incidents) - 1}")
    
    return jsonify(live_incidents)

if __name__ == "__main__":
    print("="*50)
    print("      SENTINEL AIOps | HYBRID SECURITY ENGINE")
    print("="*50)
    print(f"[*] INITIALIZING REAL-TIME MONITORING (psutil)... DONE")
    print(f"[*] BROADCASTING ON PORT 5000")
    print("="*50)
    app.run(host='0.0.0.0', port=5000, debug=False)