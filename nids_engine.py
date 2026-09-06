import sys, os, time, joblib, json
import pandas as pd
import numpy as np
import smtplib
from email.mime.text import MIMEText
import tensorflow as tf 
import requests
import threading 

# ================= SYSTEM CONFIGURATION =================
SMTP_SERVER, SMTP_PORT = "smtp.gmail.com", 587
SENDER, PASSWORD, RECEIVER = "your@email.com", "your_app_pass", "target@email.com"
FIREBASE_URL = "https://nids-monitor-default-rtdb.asia-southeast1.firebasedatabase.app/logs.json"

# ================= LOAD AI MODEL =================
print("Loading Model components into RAM...")
model = tf.keras.models.load_model('unsw_nids_dnn_model.keras')
preprocessor = joblib.load('unsw_preprocessor.joblib')

RAW_COLS = [
    'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 
    'dloss', 'service', 'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 
    'stcpb', 'dtcpb', 'smean', 'dmean', 'trans_depth', 'response_body_len', 
    'sjit', 'djit', 'sinpkt', 'dinpkt', 'tcprtt', 'synack', 'ackdat', 
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 
    'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'rate'
]

# ================= WARM-UP (LATENCY SHIFTING) =================
print("Warming up model to prevent cold start delay (may take 30-50s)...")

# Initialize dummy data: default to 0 for all columns
dummy_data = {col: [0] for col in RAW_COLS}

# Assign valid string values for categorical feature columns
dummy_data['proto'] = ['tcp']
dummy_data['state'] = ['FIN']
dummy_data['service'] = ['-']

# Create a DataFrame from the dictionary
dummy_df = pd.DataFrame(dummy_data)

# Preprocess and force graph compilation
dummy_processed = preprocessor.transform(dummy_df)
_ = model.predict_on_batch(dummy_processed)

dummy_processed_2_rows = np.vstack([dummy_processed, dummy_processed])
_ = model.predict_on_batch(dummy_processed_2_rows)

print("Warm-up complete! System is ready for real-time traffic.")
# ====================================================================

# ================= HELPER FUNCTIONS =================
def _send_alert_worker(details):
    """Internal worker for SMTP to prevent main loop blocking."""
    msg = MIMEText(f"ALERT: Network Intrusion Detected!\n\nFlow Details:\n{details}")
    msg['Subject'] = "NIDS ALERT: Attack Detected"
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER, PASSWORD)
            server.send_message(msg, SENDER, RECEIVER)
        print("   [!] Email alert sent successfully.")
    except Exception as e: 
        print(f"   [X] Email failed: {e}")

def send_alert_async(details):
    """Spawns a background thread to send alert."""
    t = threading.Thread(target=_send_alert_worker, args=(details,))
    t.daemon = True
    t.start()

def firebase_batch_worker(batch_data):
    """
    Background thread using a Session to send records individually at high speed.
    This preserves Firebase's child_added structure for the frontend.
    """
    try:
        session = requests.Session()
        for data in batch_data:
            session.post(FIREBASE_URL, json=data, timeout=3)
        print(f"   [v] Successfully synced {len(batch_data)} records to Firebase.")
    except Exception as e:
        print(f"   [X] Firebase connection error: {e}")

def send_batch_to_firebase(df, is_attack_array):
    batch_data = []
    current_time = time.time()
    
    for idx in range(len(df)):
        row_dict = df.iloc[idx].to_dict()
        row_dict['label'] = 'attack' if is_attack_array[idx] else 'normal'
        row_dict['timestamp'] = current_time
        batch_data.append(row_dict)
        
    if batch_data:
        t = threading.Thread(target=firebase_batch_worker, args=(batch_data,))
        t.daemon = True 
        t.start()

# ================= MAIN PREDICTION FUNCTION =================
def predict_flow(csv_path):
    try:
        df = pd.read_csv(csv_path)
        if df.empty: 
            return
        df = df.fillna(0)
        
        # 1. Preprocessing
        X_processed = preprocessor.transform(df[RAW_COLS])
        # 2. Prediction 
        probs = model.predict_on_batch(X_processed)
        if probs.shape[1] > 1:
            is_attack = np.argmax(probs, axis=1) == 1 
        else:
            is_attack = (probs > 0.5).flatten()

        display_labels = ["ATTACK" if a else "Normal" for a in is_attack]

        print("\n" + "="*80)
        print(f"DEBUG: DETECTION STATUS ({time.strftime('%T')})")
        debug_df = df[RAW_COLS].head(5).assign(Result=display_labels[:5])
        print(debug_df[['proto', 'state', 'sbytes', 'Result']].to_string(index=False))
        print("="*80)

        # 3. Cloud Sync
        send_batch_to_firebase(df, is_attack)

        # 4. Alarm Logic (Async)
        if any(is_attack):
            print("STATUS: ATTACK DETECTED!")
            first_attack_idx = np.where(is_attack)[0][0]
            send_alert_async(df.iloc[[first_attack_idx]].to_string())
        else:
            print("STATUS: NORMAL")
            
    except Exception as e:
        print(f"Inference Error: {e}")

# ================= MONITORING LOOP =================
if __name__ == "__main__":
    watch_path = sys.argv[1] if len(sys.argv) > 1 else "unsw_input.csv"
    print(f"Monitoring {watch_path} for incoming real-time traffic data...")
    try:
        while True:
            if os.path.exists(watch_path) and os.stat(watch_path).st_size > 0:
                time.sleep(0.05) # Minor grace period to ensure full file write
                predict_flow(watch_path)
                try:
                    os.remove(watch_path) 
                except FileNotFoundError:
                    pass
            time.sleep(0.5)
    except KeyboardInterrupt: 
        print("\nShutting down engine...")