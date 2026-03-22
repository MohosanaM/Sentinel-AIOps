# SENTINEL-AIOps: Autonomous System Telemetry & Heuristic Threat Detection 🛰️

![Status](https://img.shields.io/badge/Status-Research--Prototype-blueviolet)
![Python](https://img.shields.io/badge/Backend-Python--Flask-blue)
![Flutter](https://img.shields.io/badge/Frontend-Flutter--Dart-02569B)
![Security](https://img.shields.io/badge/Security-AIOps--SOAR-red)

**Lead Researcher:** Mohosana Maymuna  
**Affiliation:** Zhengzhou University (Ranked 3rd/41 in Software Engineering)  
**Research Focus:** Cybersecurity & AI-Driven Infrastructure Monitoring.

---

## 🔬 Scientific Abstract
Sentinel-AIOps is a **Research Prototype** evaluating the efficacy of **Heuristic Pattern Recognition** in distributed DevOps environments. By utilizing a decoupled **Hybrid Telemetry Engine**, the system bridges the gap between low-level hardware metrics (CPU/RAM kernel data) and high-level adversarial threat vectors. This project serves as a technical artifact demonstrating **Security Orchestration, Automation, and Response (SOAR)** logic in a mobile-first command center.

---

## 🚀 Live Command Center (Visual Evidence)
![Sentinel Galactic Ops Interface](Screenshot3153.png)
> **Fig 1:** Sentinel Galactic Ops Interface demonstrating real-time telemetry dispatch and AI-driven remediation protocols.

---

## 📋 Key Technical Features
* **Hybrid Telemetry Engine:** Real-time hardware extraction from the host kernel via the `psutil` library.
* **Heuristic Threat Matrix (v1.0):** Simulated detection of adversarial signatures (SQLi, DDoS, Exfiltration).
* **Decoupled REST API Architecture:** Professional v1 API gateway connecting a Python-Flask backend to a Flutter client.
* **Galactic Glassmorphism UI:** A premium "Space-Grade" interface featuring custom StarField painting and real-time pulse animations.

---

## 🛠️ System Architecture
* **Backend:** Python 3.10+, Flask (REST API Gateway), Flask-CORS.
* **Hardware Layer:** `psutil` (Kernel Telemetry Extraction).
* **Frontend:** Flutter SDK (Dart), HTTP/JSON Telemetry Parsing.

---

## 📂 Repository Structure
```text
├── core/
│   ├── sentinel_server.py     # Backend Engine
│   └── requirements.txt       # Dependencies
├── mobile/
│   ├── lib/                   # Flutter Source Code
│   └── pubspec.yaml           # App Configuration
└── README.md                  # Project Documentation

---

## ⚙️ Installation & Reproducibility
To replicate this research environment, ensure the host machine and the mobile client are on the same local network.

### 1. Initialize Backend (Python)
```bash
cd core
pip install -r requirements.txt
python sentinel_server.py

### 2. Launch Dashboard (Flutter)
```bash
cd mobile
flutter run```

---

## 📜 Future Research Roadmap
* **ML Integration:** Implementing Scikit-learn for true anomaly detection rather than heuristic matrices.
* **Encrypted Handshake:** Upgrading to HTTPS/TLS for secure telemetry transit.
* **Multi-Node Monitoring:** Expanding the kernel extraction to monitor multiple remote servers simultaneously.

---
© 2026 Mohosana Maymuna | Zhengzhou University
