#!/bin/bash
# =========================================================================
# OFFLINE NIDS PCAP PROCESSING SCRIPT (Optimized for Raspberry Pi 4)
# Processes an existing .pcap file directly instead of capturing live traffic.
# =========================================================================

# Check if the user has provided a pcap file
if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_pcap_file>"
    exit 1
fi

INPUT_PCAP="$1"

# Check if the pcap file exists
if [ ! -f "$INPUT_PCAP" ]; then
    echo "Error: File '$INPUT_PCAP' not found!"
    exit 1
fi

BASE_DIR=$(pwd)
ZEEK_BIN="/opt/zeek/bin/zeek"
ZEEK_CUT="/opt/zeek/bin/zeek-cut"
TEMP_DIR="$BASE_DIR/temp"
VENV_PYTHON="$BASE_DIR/IDS/env/bin/python3"
OUTPUT_CSV="$BASE_DIR/unsw_input.csv" 

# Initialize temporary directory
mkdir -p "$TEMP_DIR"
chmod 777 "$TEMP_DIR"

TIMESTAMP=$(date +%s)
PROC_DIR="$TEMP_DIR/proc_${TIMESTAMP}"
mkdir -p "$PROC_DIR"

echo "=========================================================="
echo "   STARTING OFFLINE NIDS PROCESSING ON $INPUT_PCAP        "
echo "=========================================================="

echo "[$(date +%T)] Status: Copying pcap to temp directory..."
# Copy the input pcap file to the temporary processing directory
cp "$INPUT_PCAP" "$PROC_DIR/input.pcap"
cd "$PROC_DIR" || exit

echo "[$(date +%T)] Status: Processing $INPUT_PCAP with Argus and Zeek..."

# Run Argus to extract Flow Metrics
argus -r input.pcap -w live.argus
ra -r live.argus -n -u -c , -s stime ltime dur saddr daddr proto sport dport state pkts spkts dpkts bytes sbytes dbytes sttl dttl sload dload sloss dloss sjit djit swin dwin stcpb dtcpb tcprtt synack ackdat sintpkt dintpkt > argus_raw.csv

# Run Zeek to extract Protocol Logs
$ZEEK_BIN -C -r input.pcap > /dev/null 2>&1

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

# Synthesize standard UNSW-NB15 features using Python
echo "[$(date +%T)] Status: Extracting features..."
$VENV_PYTHON "$BASE_DIR/extract_features.py" argus_raw.csv temp_final.csv

# Move processed data to Output
if [ -s "temp_final.csv" ]; then
    mv "temp_final.csv" "$OUTPUT_CSV"
    echo "   -> Success: Data exported to $OUTPUT_CSV"
else
    echo "   -> Error: Feature extraction failed or file is empty."
fi

# Clean up the temporary directory for this process
cd "$BASE_DIR" || exit
rm -rf "$PROC_DIR"

echo "=========================================================="
echo "   PROCESSING COMPLETE                                    "
echo "=========================================================="