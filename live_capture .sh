#!/bin/bash
# =========================================================================
# REAL-TIME NIDS CAPTURE SCRIPT (Optimized for Raspberry Pi 4)
# Captures traffic continuously without dropping packets by using subshells.
# =========================================================================

BASE_DIR=$(pwd)
ZEEK_BIN="/opt/zeek/bin/zeek"
ZEEK_CUT="/opt/zeek/bin/zeek-cut"
TEMP_DIR="$BASE_DIR/temp"
VENV_PYTHON="$BASE_DIR/IDS/env/bin/python3"

# Network Configuration
INTERFACE="eth0"        
WINDOW_SIZE=15          # Capture duration per cycle (15 seconds)
LIVE_CSV="$BASE_DIR/unsw_input.csv" 

# Initialization
mkdir -p "$TEMP_DIR"
chmod 777 "$TEMP_DIR"
rm -f "$TEMP_DIR"/* "$LIVE_CSV"

echo "=========================================================="
echo "   STARTING REAL-TIME NIDS CAPTURE ON $INTERFACE          "
echo "=========================================================="

# Ensure all background jobs are killed on exit
trap 'echo -e "\n[!] Shutting down and cleaning up..."; pkill -P $$; rm -rf "$TEMP_DIR"/* "$LIVE_CSV"; exit 0' INT

while true; do
    TIMESTAMP=$(date +%s)
    PCAP_FILE="$TEMP_DIR/live_${TIMESTAMP}.pcap"
    
    echo "[$(date +%T)] Status: Capturing $WINDOW_SIZE seconds of traffic..."
    
    # 1. Packet Capture (Blocks for 15 seconds, prevents DNS resolution overhead with -nn)
    sudo tcpdump -i $INTERFACE -G $WINDOW_SIZE -W 1 -w "$PCAP_FILE" -q -nn > /dev/null 2>&1

    if [ ! -s "$PCAP_FILE" ]; then
        echo "   -> No traffic captured. Waiting for next cycle..."
        rm -f "$PCAP_FILE"
        continue
    fi

    # 2. Process Data in a Background Subshell to allow immediate next capture
    (
        PROC_DIR="$TEMP_DIR/proc_${TIMESTAMP}"
        mkdir -p "$PROC_DIR"
        mv "$PCAP_FILE" "$PROC_DIR/live.pcap"
        cd "$PROC_DIR" || exit

        # Run Argus for Flow Metrics
        argus -r live.pcap -w live.argus
        ra -r live.argus -n -u -c , -s stime dur saddr daddr proto sport dport state pkts spkts dpkts bytes sbytes dbytes sttl dttl sload dload sloss dloss sjit djit swin dwin stcpb dtcpb tcprtt synack ackdat sintpkt dintpkt > argus_raw.csv
        
        # Run Zeek for Protocol Logs (Bare mode config if applicable)
        $ZEEK_BIN -C -r live.pcap > /dev/null 2>&1
        
        # Process Connection Logs
        if [ -f "conn.log" ]; then
            echo "ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,service,duration,orig_bytes,resp_bytes,conn_state,orig_pkts,resp_pkts" > conn.csv
            cat conn.log | $ZEEK_CUT ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state orig_pkts resp_pkts | tr '\t' ',' >> conn.csv
        else
            touch conn.csv
        fi

        # Process HTTP Logs
        if [ -f "http.log" ]; then
            echo "uid,trans_depth,response_body_len,method" > http.csv
            cat http.log | $ZEEK_CUT uid trans_depth response_body_len method | tr '\t' ',' >> http.csv
        else
            touch http.csv
        fi

        # Process FTP Logs
        if [ -f "ftp.log" ]; then
            echo "uid,user,password,command" > ftp.csv
            cat ftp.log | $ZEEK_CUT uid user password command | tr '\t' ',' >> ftp.csv
        else
            touch ftp.csv
        fi

        # Synthesize standard UNSW-NB15 features
        $VENV_PYTHON "$BASE_DIR/extract_features.py" argus_raw.csv temp_final.csv

        # Forward it to nids_engine for processing (Atomic move)
        if [ -s "temp_final.csv" ]; then
            mv "temp_final.csv" "$LIVE_CSV"
            echo "   -> Pushed processed data to Engine"
        fi

        # Cleanup process specific temp files
        cd "$BASE_DIR" || exit
        rm -rf "$PROC_DIR"
    ) &
done