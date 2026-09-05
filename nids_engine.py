import sys, os, time, joblib, json
import pandas as pd
import numpy as np
import smtplib
from email.mime.text import MIMEText
import tensorflow as tf 
import requests
import threading 

# ================= SYSTEM CONFIGURATION =================
# Email Config
SMTP_SERVER, SMTP_PORT = "smtp.gmail.com", 587
SENDER, PASSWORD, RECEIVER = "your@email.com", "your_app_pass", "target@email.com"

# Firebase Config
FIREBASE_URL = "https://nids-monitor-default-rtdb.asia-southeast1.firebasedatabase.app/logs.json"

# ================= LOAD AI MODEL =================
print("Loading Model components into RAM...")
model = tf.keras.models.load_model('unsw_nids_dnn_model.keras')
preprocessor = joblib.load('unsw_preprocessor.joblib')

RAW_COLS = [
    'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 
    'dloss', 'service', 'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 
    'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 
    'sjit', 'djit', 'sintpkt', 'dintpkt', 'tcprtt', 'synack', 'ackdat', 
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 
    'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm'
]

# ================= HELPER FUNCTIONS =================
def send_alert(details):
    """Sends email alert when an attack is detected"""
    msg = MIMEText(f"ALERT: Network Intrusion Detected!\n\nFlow Details:\n{details}")
    msg['Subject'] = "NIDS ALERT: Attack Detected"
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER, PASSWORD)
            server.send_message(msg)
        print("   [!] Email alert sent.")
    except Exception as e: 
        print(f"   [X] Email failed: {e}")

def firebase_worker(data_dict):
    """Background function to send data to Firebase without blocking the main program"""
    try:
        response = requests.post(FIREBASE_URL, json=data_dict, timeout=3)
        if response.status_code != 200:
            print(f"   [X] Firebase returned error code: {response.status_code}")
    except Exception as e:
        pass 

def send_prediction_to_firebase(row_dict, is_attack):
    """Prepares data and triggers the Firebase upload thread"""
    row_dict['label'] = 'attack' if is_attack else 'normal'
    row_dict['timestamp'] = time.time()
    
    t = threading.Thread(target=firebase_worker, args=(row_dict,))
    t.daemon = True 
    t.start()

# ================= MAIN PREDICTION FUNCTION =================
def predict_flow(csv_path):
    try:
        df = pd.read_csv(csv_path)
        if df.empty: return
        df = df.fillna(0)
        
        # 1. Preprocessing
        X_processed = preprocessor.transform(df[RAW_COLS])

        # 2. Binary Prediction 
        probs = model.predict(X_processed, verbose=0)
        
        # Handle both Softmax (2 outputs) and Sigmoid (1 output) models
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

        # === FIREBASE INTEGRATION START ===
        for idx in range(len(df)):
            row_data = df.iloc[idx].to_dict()  
            pred_status = is_attack[idx]       
            send_prediction_to_firebase(row_data, pred_status)
        # ==================================

        # 3. Alarm Logic
        if any(is_attack):
            print("STATUS: ATTACK DETECTED!")
            
            first_attack_idx = np.where(is_attack)[0][0]
            send_alert(df.iloc[[first_attack_idx]].to_string())
        else:
            print("STATUS: NORMAL")
            
    except Exception as e:
        print(f"Inference Error: {e}")

# ================= MONITORING LOOP =================
if __name__ == "__main__":
    watch_path = sys.argv[1] if len(sys.argv) > 1 else "unsw_input.csv"
    print(f"Monitoring {watch_path}...")
    try:
        while True:
            if os.path.exists(watch_path):
                time.sleep(0.1) # Brief delay to ensure file is fully written
                predict_flow(watch_path)
                os.remove(watch_path) 
            time.sleep(0.5)
    except KeyboardInterrupt: 
        print("\nShutting down...")