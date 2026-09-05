#!/bin/bash

ZEEK_BIN="/opt/zeek/bin/zeek"
ZEEK_CUT="/opt/zeek/bin/zeek-cut"
TEMP_DIR="/home/kevin_uet/temp"
VENV_PYTHON="/home/kevin_uet/IDS/env/bin/python3"

# Network Configuration
INTERFACE="eth0"        
WINDOW_SIZE=15          # Capture duration per cycle (15 seconds)
LIVE_CSV="unsw_input.csv" # File that communicates with nids_engine.py

# Initialization
mkdir -p $TEMP_DIR
chmod 777 $TEMP_DIR
rm -f $TEMP_DIR/* *.log $LIVE_CSV

echo "=========================================================="
echo "   STARTING REAL-TIME NIDS CAPTURE ON $INTERFACE          "
echo "=========================================================="

while true; do
    echo "[$(date +%T)] Status: Capturing $WINDOW_SIZE seconds of traffic..."
    
    # 1. Packet Capture
    sudo tcpdump -i $INTERFACE -G $WINDOW_SIZE -W 1 -w $TEMP_DIR/live.pcap -q > /dev/null 2>&1

    if [ ! -s "$TEMP_DIR/live.pcap" ]; then
        echo "   -> No traffic captured. Waiting for next cycle..."
        continue
    fi

    # 2. Run Argus for Flow Metrics
    argus -r "$TEMP_DIR/live.pcap" -w "$TEMP_DIR/live.argus"
    ra -r "$TEMP_DIR/live.argus" -n -u -c , -s stime dur saddr daddr proto sport dport state pkts spkts dpkts bytes sbytes dbytes sttl dttl sload dload sloss dloss sjit djit swin dwin stcpb dtcpb tcprtt synack ackdat sintpkt dintpkt > "$TEMP_DIR/argus_raw.csv"
    
    # 3. Run Zeek for Protocol Logs
    $ZEEK_BIN -C -r "$TEMP_DIR/live.pcap" > /dev/null 2>&1
    
    # --- Process Connection Logs ---
    if [ -f "conn.log" ]; then
        echo "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,service,duration,orig_bytes,resp_bytes,conn_state,orig_pkts,resp_pkts" > conn.csv
        cat conn.log | $ZEEK_CUT ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state orig_pkts resp_pkts | tr '\t' ',' >> conn.csv
    fi

    # --- Process HTTP Logs ---
    echo "uid,trans_depth,response_body_len,method" > http.csv
    if [ -f "http.log" ]; then
        cat http.log | $ZEEK_CUT uid trans_depth response_body_len method | tr '\t' ',' >> http.csv
    fi

    # --- Process FTP Logs ---
    echo "uid,user,password,command" > ftp.csv
    if [ -f "ftp.log" ]; then
        cat ftp.log | $ZEEK_CUT uid user password command | tr '\t' ',' >> ftp.csv
    fi

    # 4. Synthesize standard UNSW-NB15 features
    $VENV_PYTHON extract_features.py "$TEMP_DIR/argus_raw.csv" "$TEMP_DIR/temp_final.csv"

    # 5. forward it to nids_engine for processing
    if [ -f "$TEMP_DIR/temp_final.csv" ]; then
        mv "$TEMP_DIR/temp_final.csv" "$LIVE_CSV"
        echo "   -> Pushed data to Engine ($LIVE_CSV)"
    fi

    # Cleanup temporary files for the next cycle
    rm -f *.log conn.csv http.csv ftp.csv "$TEMP_DIR/live.pcap" "$TEMP_DIR/live.argus" "$TEMP_DIR/argus_raw.csv"
    echo "----------------------------------------------------------"
done