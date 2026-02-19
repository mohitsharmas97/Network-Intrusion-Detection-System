# Network Intrusion Detection System (NIDS)

![Banner](https://img.shields.io/badge/Status-Active-success) ![Python](https://img.shields.io/badge/Python-3.8+-blue.svg) ![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg)

A real-time Network Intrusion Detection System (NIDS) that uses Machine Learning (Random Forest & Isolation Forest) to detect and classify network attacks. The system features a modern web dashboard for monitoring, simulation of attack scenarios, and live packet capture analysis.

## 🚀 Features

- **Real-time Detection**: Analyzes network traffic live using `scapy` (WinPcap/Npcap).
- **Machine Learning**:
    - **Random Forest**: Classifies traffic into Normal or specific attack types (e.g., DDoS, SQL Injection, XSS).
    - **Isolation Forest**: Detects anomalies and zero-day attacks.
- **Attack Simulation**: Built-in simulator to generate synthetic traffic patterns for testing detection logic.
    - **Selectable Attack Types**: Choose from 14+ specific attack types or random mixed traffic.
- **Secure Handling**:
    - **AES-128-GCM**: Encrypts sensitive packet data before storage/display.
    - **HMAC-SHA256**: Ensures data integrity.
- **Interactive Dashboard**:
    - Live packet feed with risk levels.
    - Real-time charts for traffic volume and attack distribution.
    - CSV upload for batch analysis of datasets.

## 🛠️ Tech Stack

- **Backend**: Python, Flask, Socket.IO
- **Frontend**: HTML5, CSS3, JavaScript (Simulated Real-time updates)
- **ML Libraries**: scikit-learn, pandas, numpy, joblib
- **Packet Capture**: Scapy (requires Npcap on Windows)
- **Encryption**: Cryptography (AES-GCM)

## 📦 Installation

### Prerequisites
- Python 3.8+
- [Npcap](https://npcap.com/) (Required for Real-time Capture on Windows)
  - *Note: Install with "WinPcap API-compatible mode" checked.*

### Steps

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/mohitsharmas97/Network-Intrusion-Detection-System.git
    cd Network-Intrusion-Detection-System
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the Application**
    ```bash
    python app.py
    ```

4.  **Access Dashboard**
    Open your browser and navigate to: `http://localhost:5000`

## 🖥️ Usage

### 1. Simulation Mode
- Navigate to the **Simulation** tab.
- Select a specific **Traffic Type** (e.g., "DDoS UDP" or "Random Mixed Traffic").
- Click **Start Simulation**.
- Observe the Live Feed and Charts updating with synthetic data.

### 2. Real-time Capture
- Navigate to the **Real-time Capture** tab.
- Click **Start Capture**.
- The system will sniff actual network packets from your machine's interface, classify them, and display alerts for suspicious activity.

### 3. CSV Analysis
- Navigate to the **CSV Prediction** tab.
- Upload a CSV file (IoT/IIoT dataset format).
- Click **Run Prediction** to analyze the file in batch mode.

## 📂 Project Structure

```
network-intrusion-project/
├── app.py                 # Main Flask application & ML logic
├── rf_model.pkl           # Pre-trained Random Forest model
├── iso_forest.pkl         # Pre-trained Isolation Forest model
├── scaler.pkl             # Feature scaler
├── feature_names.pkl      # List of features used by models
├── requirements.txt       # Python dependencies
├── static/
│   ├── css/style.css      # Dashboard styling
│   └── js/dashboard.js    # Frontend logic (Socket.IO, Charts)
└── templates/
    └── index.html         # Main dashboard interface
```

## 📊 Dataset

This project uses models trained on the **Edge-IIoTset** dataset, covering various IoT/IIoT attack vectors including:
- DDoS (UDP, ICMP, TCP, HTTP)
- SQL Injection, XSS
- Port Scanning, Vulnerability Scanning
- Ransomware, Backdoor, Password Attacks

## 📝 License

This project is licensed under the MIT License.
