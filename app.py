"""
Network Intrusion Detection System - Flask Backend
Uses pre-trained Random Forest and Isolation Forest models from Edge-IIoTset dataset
"""

import os
import time
import json
import random
import threading
import numpy as np
import pandas as pd
# Monkey patch for compatibility with older pickles (pandas < 1.0)
try:
    if not hasattr(pd, 'datetime'):
        pd.datetime = pd.to_datetime
except Exception:
    pass

import joblib
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import io
import base64

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids-secret-key-2024'
# Use threading mode — works on all platforms without extra dependencies
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ─── Model Loading ─────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

print("Loading models...")
try:
    rf_model = joblib.load(os.path.join(BASE_DIR, 'rf_model.pkl'))
    scaler = joblib.load(os.path.join(BASE_DIR, 'scaler.pkl'))
    feature_names = joblib.load(os.path.join(BASE_DIR, 'feature_names.pkl'))
    iso_forest = joblib.load(os.path.join(BASE_DIR, 'iso_forest.pkl'))
    print(f"✅ Models loaded! Features: {len(feature_names)}")
    print(f"   Feature names: {feature_names[:5]}...")
except Exception as e:
    print(f"❌ Error loading models: {e}")
    rf_model = scaler = feature_names = iso_forest = None

# ─── Constants ────────────────────────────────────────────────────────────────
ATTACK_TYPES = [
    'Normal', 'DDoS_UDP', 'DDoS_ICMP', 'Ransomware', 'DDoS_HTTP',
    'SQL_injection', 'Uploading', 'DDoS_TCP', 'Backdoor',
    'Vulnerability_scanner', 'Port_Scanning', 'XSS', 'Password',
    'MITM', 'Fingerprinting'
]

RISK_LEVELS = {
    'Normal': 'Low',
    'DDoS_UDP': 'High', 'DDoS_ICMP': 'High', 'Ransomware': 'High',
    'DDoS_HTTP': 'High', 'SQL_injection': 'High', 'DDoS_TCP': 'High',
    'Backdoor': 'High', 'Password': 'High', 'MITM': 'High',
    'Uploading': 'Medium', 'Vulnerability_scanner': 'Medium',
    'Port_Scanning': 'Medium', 'XSS': 'Medium',
    'Fingerprinting': 'Low',
}

# Global state
simulation_running = False
realtime_running = False
stats = {
    'total_packets': 0,
    'attacks_detected': 0,
    'normal_traffic': 0,
    'encryption_times': [],
    'attack_counts': {k: 0 for k in ATTACK_TYPES},
    'recent_alerts': []
}

# Simulation Config
simulation_config = {
    'attack_type': 'Random'
}

# ─── Encryption ───────────────────────────────────────────────────────────────
def generate_aes_key():
    return os.urandom(16)

def encrypt_packet(data: bytes, key: bytes) -> dict:
    """Encrypt data using AES-128-GCM and compute HMAC-SHA256."""
    start = time.perf_counter()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    mac = h.finalize()
    elapsed_ms = (time.perf_counter() - start) * 1000
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'hmac': base64.b64encode(mac).decode(),
        'encryption_time_ms': round(elapsed_ms, 3),
        'algorithm': 'AES-128-GCM',
        'auth': 'HMAC-SHA256'
    }

# ─── Feature Preprocessing ────────────────────────────────────────────────────
def preprocess_features(df: pd.DataFrame) -> np.ndarray:
    """Preprocess a DataFrame to match the training pipeline."""
    drop_cols = [
        'frame.time', 'ip.src_host', 'ip.dst_host', 'arp.dst.proto_ipv4',
        'arp.src.proto_ipv4', 'http.file_data', 'http.request.uri.query',
        'http.referer', 'http.request.full_uri', 'tcp.options', 'tcp.payload',
        'tcp.flags', 'dns.qry.name', 'mqtt.msg_decoded_as', 'mqtt.msg',
        'mqtt.protoname', 'mqtt.topic', 'Attack_label', 'Attack_type'
    ]
    df_clean = df.drop(columns=[c for c in drop_cols if c in df.columns], errors='ignore')

    from sklearn.preprocessing import LabelEncoder
    le = LabelEncoder()
    for col in df_clean.select_dtypes(include='object').columns:
        df_clean[col] = le.fit_transform(df_clean[col].astype(str))

    for col in feature_names:
        if col not in df_clean.columns:
            df_clean[col] = 0

    X = df_clean[feature_names].fillna(0)
    return scaler.transform(X)

# ─── Prediction ───────────────────────────────────────────────────────────────
def predict_single(features_scaled: np.ndarray) -> dict:
    """Run RF + Isolation Forest on a single scaled feature vector."""
    proba = rf_model.predict_proba(features_scaled)[0]
    pred_class = rf_model.classes_[int(np.argmax(proba))]
    confidence = float(np.max(proba)) * 100

    iso_score = float(iso_forest.decision_function(features_scaled)[0])
    # Explicitly cast numpy bool_ → Python bool to avoid JSON serialization errors
    is_anomaly = bool(iso_forest.predict(features_scaled)[0] == -1)
    is_attack = bool(pred_class != 'Normal')
    risk = RISK_LEVELS.get(str(pred_class), 'Medium')

    return {
        'attack_type': str(pred_class),
        'confidence': round(confidence, 2),
        'risk_level': str(risk),
        'is_attack': is_attack,
        'is_anomaly': is_anomaly,
        'anomaly_score': round(iso_score, 4),
    }

# ─── Sample Data Generator ────────────────────────────────────────────────────
def generate_sample_row(attack_type=None):
    if attack_type is None:
        attack_type = random.choice(ATTACK_TYPES)
    row = {}
    row['frame.time'] = datetime.now().strftime('%b %d, %Y %H:%M:%S.%f')
    row['ip.src_host'] = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    row['ip.dst_host'] = f"10.0.{random.randint(0,10)}.{random.randint(1,50)}"
    row['arp.dst.proto_ipv4'] = '0.0.0.0'
    row['arp.opcode'] = random.choice([0, 1, 2])
    row['arp.hw.size'] = random.choice([0, 6])
    row['arp.src.proto_ipv4'] = '0.0.0.0'
    row['icmp.checksum'] = random.randint(0, 65535)
    row['icmp.seq_le'] = random.randint(0, 1000)
    row['icmp.transmit_timestamp'] = random.randint(0, 999999)
    row['icmp.unused'] = 0
    row['http.file_data'] = ''
    row['http.content_length'] = random.randint(0, 10000)
    row['http.request.uri.query'] = ''
    row['http.request.method'] = random.choice(['GET', 'POST', ''])
    row['http.referer'] = ''
    row['http.request.full_uri'] = ''
    row['http.request.version'] = random.choice(['HTTP/1.1', 'HTTP/2', ''])
    row['http.response'] = random.randint(0, 1)
    row['http.tls_port'] = random.choice([0, 443])
    row['tcp.ack'] = random.randint(0, 2**32)
    row['tcp.ack_raw'] = random.randint(0, 2**32)
    row['tcp.checksum'] = random.randint(0, 65535)
    row['tcp.connection.fin'] = random.choice([0, 1])
    row['tcp.connection.rst'] = random.choice([0, 1])
    row['tcp.connection.syn'] = random.choice([0, 1])
    row['tcp.connection.synack'] = random.choice([0, 1])
    row['tcp.dstport'] = random.choice([80, 443, 22, 502, 8080, random.randint(1024, 65535)])
    row['tcp.flags'] = hex(random.randint(0, 255))
    row['tcp.flags.ack'] = random.choice([0, 1])
    row['tcp.len'] = random.randint(0, 1500)
    row['tcp.options'] = ''
    row['tcp.payload'] = ''
    row['tcp.seq'] = random.randint(0, 2**32)
    row['tcp.srcport'] = random.randint(1024, 65535)
    row['udp.port'] = random.choice([0, 53, 67, 68, random.randint(1024, 65535)])
    row['udp.stream'] = random.randint(0, 100)
    row['udp.time_delta'] = round(random.uniform(0, 1), 6)
    row['dns.qry.name'] = ''
    row['dns.qry.name.len'] = random.choice([0, random.randint(5, 50)])
    row['dns.qry.qu'] = random.choice([0, 1])
    row['dns.qry.type'] = random.choice([0, 1, 28])
    row['dns.retransmission'] = random.choice([0, 1])
    row['dns.retransmit_request'] = random.choice([0, 1])
    row['dns.retransmit_request_in'] = random.choice([0, 1])
    row['mqtt.conack.flags'] = 0
    row['mqtt.conflag.cleansess'] = 0
    row['mqtt.conflags'] = 0
    row['mqtt.hdrflags'] = 0
    row['mqtt.len'] = 0
    row['mqtt.msg_decoded_as'] = ''
    row['mqtt.msg'] = ''
    row['mqtt.msgtype'] = 0
    row['mqtt.proto_len'] = 0
    row['mqtt.protoname'] = ''
    row['mqtt.topic'] = ''
    row['mqtt.topic_len'] = 0
    row['mqtt.ver'] = 0
    row['mbtcp.len'] = random.choice([0, random.randint(6, 260)])
    row['mbtcp.trans_id'] = random.randint(0, 65535)
    row['mbtcp.unit_id'] = random.randint(0, 255)
    row['Attack_label'] = 0 if attack_type == 'Normal' else 1
    row['Attack_type'] = attack_type
    return row

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    avg_enc_time = (
        round(sum(stats['encryption_times'][-100:]) / len(stats['encryption_times'][-100:]), 3)
        if stats['encryption_times'] else 0
    )
    return jsonify({
        'total_packets': stats['total_packets'],
        'attacks_detected': stats['attacks_detected'],
        'normal_traffic': stats['normal_traffic'],
        'avg_encryption_time_ms': avg_enc_time,
        'attack_counts': stats['attack_counts'],
        'recent_alerts': stats['recent_alerts'][-10:]
    })

@app.route('/api/predict/csv', methods=['POST'])
def predict_csv():
    if rf_model is None:
        return jsonify({'error': 'Models not loaded'}), 500
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        df = pd.read_csv(file, low_memory=False)
        total = len(df)
        X_scaled = preprocess_features(df)
        results = []
        aes_key = generate_aes_key()

        for i in range(len(X_scaled)):
            pred = predict_single(X_scaled[i:i+1])
            raw_data = json.dumps({'row': i, 'prediction': pred['attack_type']}).encode()
            enc = encrypt_packet(raw_data, aes_key)

            stats['total_packets'] += 1
            stats['encryption_times'].append(enc['encryption_time_ms'])
            if pred['is_attack']:
                stats['attacks_detected'] += 1
                stats['attack_counts'][pred['attack_type']] = stats['attack_counts'].get(pred['attack_type'], 0) + 1
                stats['recent_alerts'].append({
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'attack_type': pred['attack_type'],
                    'confidence': pred['confidence'],
                    'risk_level': pred['risk_level'],
                    'row': i
                })
                if len(stats['recent_alerts']) > 100:
                    stats['recent_alerts'].pop(0)
            else:
                stats['normal_traffic'] += 1

            src_ip = str(df.iloc[i]['ip.src_host']) if 'ip.src_host' in df.columns else 'N/A'
            dst_ip = str(df.iloc[i]['ip.dst_host']) if 'ip.dst_host' in df.columns else 'N/A'

            results.append({
                'row': int(i),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'attack_type': pred['attack_type'],
                'confidence': pred['confidence'],
                'risk_level': pred['risk_level'],
                'is_attack': bool(pred['is_attack']),
                'is_anomaly': bool(pred['is_anomaly']),
                'encryption_time_ms': enc['encryption_time_ms'],
            })

        attack_count = sum(1 for r in results if r['is_attack'])
        avg_enc = round(sum(r['encryption_time_ms'] for r in results) / len(results), 3) if results else 0

        return jsonify({
            'success': True,
            'total_rows': int(total),
            'processed': int(len(results)),
            'attacks_found': int(attack_count),
            'normal_found': int(len(results) - attack_count),
            'avg_encryption_time_ms': avg_enc,
            'results': results[:500]
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/simulate/start', methods=['POST'])
def start_simulation():
    global simulation_running, simulation_config
    if simulation_running:
        return jsonify({'message': 'Simulation already running'})
    
    data = request.json or {}
    simulation_config['attack_type'] = data.get('attack_type', 'Random')
    
    simulation_running = True
    t = threading.Thread(target=run_simulation, daemon=True)
    t.start()
    return jsonify({'message': f"Simulation started ({simulation_config['attack_type']})"})

@app.route('/api/simulate/stop', methods=['POST'])
def stop_simulation():
    global simulation_running
    simulation_running = False
    return jsonify({'message': 'Simulation stopped'})

def run_simulation():
    """Background thread: generate synthetic packets and emit via SocketIO."""
    global simulation_running, simulation_config
    aes_key = generate_aes_key()

    while simulation_running:
        try:
            selected_type = simulation_config.get('attack_type', 'Random')
            
            if selected_type == 'Random':
                attack_type = random.choices(
                    ATTACK_TYPES,
                    weights=[30, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2],
                    k=1
                )[0]
            else:
                # If specific type selected, generate that type 90% of time, Normal 10% (for realism)
                # Or just strictly generate that type if user wants to see specific attacks
                # The user request said "specify the attack namse and all", implying strict selection
                attack_type = selected_type

            row = generate_sample_row(attack_type)
            df = pd.DataFrame([row])
            X_scaled = preprocess_features(df)
            pred = predict_single(X_scaled)

            raw_data = json.dumps({'port': row.get('tcp.srcport', 0)}).encode()
            enc = encrypt_packet(raw_data, aes_key)

            stats['total_packets'] += 1
            stats['encryption_times'].append(enc['encryption_time_ms'])
            if pred['is_attack']:
                stats['attacks_detected'] += 1
                stats['attack_counts'][pred['attack_type']] = stats['attack_counts'].get(pred['attack_type'], 0) + 1
                stats['recent_alerts'].append({
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'attack_type': pred['attack_type'],
                    'confidence': pred['confidence'],
                    'risk_level': pred['risk_level'],
                    'src_ip': row['ip.src_host'],
                    'dst_ip': row['ip.dst_host']
                })
                if len(stats['recent_alerts']) > 100:
                    stats['recent_alerts'].pop(0)
            else:
                stats['normal_traffic'] += 1

            # Build payload — all native Python types, safe for JSON
            payload = {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'mode': 'simulation',
                'src_ip': str(row['ip.src_host']),
                'dst_ip': str(row['ip.dst_host']),
                'attack_type': pred['attack_type'],
                'confidence': pred['confidence'],
                'risk_level': pred['risk_level'],
                'is_attack': bool(pred['is_attack']),
                'is_anomaly': bool(pred['is_anomaly']),
                'encryption_time_ms': enc['encryption_time_ms'],
                'total_packets': int(stats['total_packets']),
                'attacks_detected': int(stats['attacks_detected']),
                'attack_counts': {k: int(v) for k, v in stats['attack_counts'].items()}
            }
            # emit() from background thread requires the app context
            with app.app_context():
                socketio.emit('packet_update', payload)

        except Exception as e:
            print(f"Simulation error: {e}")

        time.sleep(random.uniform(0.5, 1.0))

@app.route('/api/realtime/start', methods=['POST'])
def start_realtime():
    global realtime_running
    if realtime_running:
        return jsonify({'message': 'Capture already running'})
    try:
        from scapy.all import sniff  # test import
        realtime_running = True
        t = threading.Thread(target=run_realtime_capture, daemon=True)
        t.start()
        return jsonify({'message': 'Real-time capture started'})
    except ImportError:
        return jsonify({'error': 'scapy not installed. Run: pip install scapy'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/realtime/stop', methods=['POST'])
def stop_realtime():
    global realtime_running
    realtime_running = False
    return jsonify({'message': 'Capture stopped'})

def run_realtime_capture():
    global realtime_running
    aes_key = generate_aes_key()

    try:
        from scapy.all import sniff, IP, TCP, UDP, conf
        import scapy.error

        print("[Realtime] Scapy loaded, starting packet capture...")

        # -- Configure Scapy for Windows compatibility --
        # Try to use Layer 3 socket if Layer 2 (WinPcap/Npcap) is missing
        # This allows basic IP sniffing without Npcap in some cases (Raw Sockets)
        
        # Check if we can use the default Layer 2 socket
        use_l3 = False
        try:
            if not conf.L2socket:
                print("[Realtime] L2socket unavailable, forcing L3...")
                use_l3 = True
        except Exception:
             use_l3 = True

        if use_l3:
            print("[Realtime] Switching to Layer 3 (L3socket) capture...")
            conf.L2socket = conf.L3socket

        def process_packet(pkt):
            if not realtime_running:
                return
            try:
                if IP not in pkt:
                    return  # skip non-IP packets

                row = {col: 0 for col in feature_names}
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                if TCP in pkt:
                    if 'tcp.srcport' in row: row['tcp.srcport'] = int(pkt[TCP].sport)
                    if 'tcp.dstport' in row: row['tcp.dstport'] = int(pkt[TCP].dport)
                    if 'tcp.len' in row: row['tcp.len'] = len(pkt[TCP].payload)
                    if 'tcp.flags.ack' in row: row['tcp.flags.ack'] = 1 if pkt[TCP].flags & 0x10 else 0
                    if 'tcp.connection.syn' in row: row['tcp.connection.syn'] = 1 if pkt[TCP].flags & 0x02 else 0
                    if 'tcp.connection.fin' in row: row['tcp.connection.fin'] = 1 if pkt[TCP].flags & 0x01 else 0
                    if 'tcp.connection.rst' in row: row['tcp.connection.rst'] = 1 if pkt[TCP].flags & 0x04 else 0
                if UDP in pkt:
                    if 'udp.port' in row: row['udp.port'] = int(pkt[UDP].dport)
                    if 'udp.stream' in row: row['udp.stream'] = 0

                df = pd.DataFrame([row])
                X_scaled = scaler.transform(df[feature_names].fillna(0))
                pred = predict_single(X_scaled)
                enc = encrypt_packet(json.dumps({'src': src_ip}).encode(), aes_key)

                stats['total_packets'] += 1
                stats['encryption_times'].append(enc['encryption_time_ms'])
                if pred['is_attack']:
                    stats['attacks_detected'] += 1
                    stats['attack_counts'][pred['attack_type']] = stats['attack_counts'].get(pred['attack_type'], 0) + 1
                    stats['recent_alerts'].append({
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'attack_type': pred['attack_type'],
                        'confidence': pred['confidence'],
                        'risk_level': pred['risk_level'],
                        'src_ip': src_ip,
                        'dst_ip': dst_ip
                    })
                    if len(stats['recent_alerts']) > 100:
                        stats['recent_alerts'].pop(0)
                else:
                    stats['normal_traffic'] += 1

                payload = {
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'mode': 'realtime',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'attack_type': pred['attack_type'],
                    'confidence': pred['confidence'],
                    'risk_level': pred['risk_level'],
                    'is_attack': bool(pred['is_attack']),
                    'is_anomaly': bool(pred['is_anomaly']),
                    'encryption_time_ms': enc['encryption_time_ms'],
                    'total_packets': int(stats['total_packets']),
                    'attacks_detected': int(stats['attacks_detected']),
                    'attack_counts': {k: int(v) for k, v in stats['attack_counts'].items()}
                }
                with app.app_context():
                    socketio.emit('packet_update', payload)

            except Exception as e:
                print(f"[Realtime] Packet processing error: {e}")

        # Use a loop with timeout=1 so we can stop cleanly on Windows
        print(f"[Realtime] Capture loop started (timeout-based). use_l3={use_l3}")
        
        while realtime_running:
            # We catch Scapy_Exception here which usually wraps the low-level "No libpcap" error
            try:
                if use_l3:
                     # Force L3socket if needed, although conf.L2socket assignment above should handle it
                     sniff(prn=process_packet, store=False, timeout=1, L2socket=conf.L3socket)
                else:
                     sniff(prn=process_packet, store=False, timeout=1)
            except Exception as e:
                # Check for the specific Scapy error about missing pcap
                err_msg = str(e).lower()
                if "libpcap" in err_msg or "winpcap" in err_msg or "npcap" in err_msg:
                    raise OSError("Npcap is not installed or not found.") # Re-raise as OSError to be caught below
                else:
                    raise e # Re-raise other errors

        print("[Realtime] Capture stopped.")

    except (OSError, ImportError, Exception) as e:
        err_msg = str(e)
        print(f"[Realtime] Capture Exception: {err_msg}")
        
        friendly_error = ""
        if "winpcap" in err_msg.lower() or "npcap" in err_msg.lower() or "libpcap" in err_msg.lower():
            friendly_error = (
                "Capture Error: Npcap (or WinPcap) is missing or not accessible.\n"
                "1. Download and install Npcap from https://npcap.com/\n"
                "2. During installation, check 'Install Npcap in WinPcap API-compatible mode'.\n"
                "3. Restart the application."
            )
        else:
            friendly_error = f"Capture failed: {err_msg}. Ensure Admin privileges and Npcap is installed."

        print(f"[Realtime] Sending error to UI: {friendly_error}")
        with app.app_context():
            socketio.emit('capture_error', {'error': friendly_error})
        realtime_running = False

@app.route('/api/generate_sample')
def generate_sample():
    rows = []
    for _ in range(60):
        rows.append(generate_sample_row('Normal'))
    for attack in ATTACK_TYPES[1:]:
        for _ in range(3):
            rows.append(generate_sample_row(attack))
    random.shuffle(rows)
    df = pd.DataFrame(rows)
    buf = io.BytesIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    return send_file(buf, mimetype='text/csv', as_attachment=True, download_name='sample_network_traffic.csv')

@app.route('/api/reset', methods=['POST'])
def reset_stats():
    global stats
    stats = {
        'total_packets': 0, 'attacks_detected': 0, 'normal_traffic': 0,
        'encryption_times': [],
        'attack_counts': {k: 0 for k in ATTACK_TYPES},
        'recent_alerts': []
    }
    return jsonify({'message': 'Stats reset'})

# ─── SocketIO Events ──────────────────────────────────────────────────────────
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('status', {'message': 'Connected to NIDS server', 'models_loaded': rf_model is not None})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("🚀 Starting Network Intrusion Detection System...")
    print("   Open http://localhost:5000 in your browser")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
