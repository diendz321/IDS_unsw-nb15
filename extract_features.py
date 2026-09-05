import sys
import os
import pandas as pd
import numpy as np

def read_csv_log(filename):
    if not os.path.exists(filename): 
        return pd.DataFrame()
    try:
        return pd.read_csv(filename, on_bad_lines='skip', low_memory=False)
    except Exception as e:
        print(f"Warning: Could not read {filename}. Error: {e}")
        return pd.DataFrame()

def fix_alignment(df_conn, df_argus):
    df_conn = df_conn.copy()
    df_argus = df_argus.copy()

    df_conn.columns = [str(c).strip().lower() for c in df_conn.columns]

    argus_rename_map = {
        'SrcAddr': 'id.orig_h', 'DstAddr': 'id.resp_h',
        'Sport': 'id.orig_p', 'Dport': 'id.resp_p', 'Proto': 'proto'
    }
    df_argus = df_argus.rename(columns=argus_rename_map)

    merge_keys = ['id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p', 'proto']

    for df in [df_conn, df_argus]:
        for col in ['id.orig_h', 'id.resp_h', 'proto']:
            if col in df.columns:
                df[col] = df[col].astype(str).str.strip().str.lower()
        for col in ['id.orig_p', 'id.resp_p']:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
                df[col] = df[col].fillna(0).astype(int).astype(str).str.strip()
        if 'proto' in df.columns:
            df['proto'] = df['proto'].replace('ipv6-icmp', 'icmp')

    merged_df = pd.merge(df_conn, df_argus, on=merge_keys, how='right')
    return merged_df
    
def process_pipeline(argus_input, output_csv):
    cols_49 = [
        'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 
        'sttl', 'dttl', 'sloss', 'dloss', 'service', 'sload', 'dload', 'spkts', 'dpkts', 
        'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 
        'sjit', 'djit', 'stime', 'ltime', 'sintpkt', 'dintpkt', 'tcprtt', 'synack', 
        'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 
        'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 
        'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm'
    ]
    
    df_argus = pd.read_csv(argus_input)
    df_conn = read_csv_log('conn.csv')
    df_http = read_csv_log('http.csv')
    df_ftp = read_csv_log('ftp.csv')
    
    if df_conn.empty: 
        return
    
    merged_df = fix_alignment(df_conn, df_argus)
    merged_df = merged_df.sort_values('StartTime')
    
    if 'uid' in merged_df.columns:
        merged_df['uid'] = merged_df['uid'].fillna('-')
    if 'service' in merged_df.columns:
        merged_df['service'] = merged_df['service'].fillna('-')
        
    final_df = pd.DataFrame(index=merged_df.index, columns=cols_49).fillna(0)
    
    final_df['srcip'] = merged_df['id.orig_h']
    final_df['dstip'] = merged_df['id.resp_h']
    final_df['sport'] = merged_df['id.orig_p']
    final_df['dsport'] = merged_df['id.resp_p']
    final_df['dur'] = pd.to_numeric(merged_df['Dur'].replace('-', 0), errors='coerce').fillna(0)
    final_df['proto'] = merged_df['proto']
    final_df['service'] = merged_df['service'].astype(str).replace('none', '-')
    
    final_df['sbytes'] = pd.to_numeric(merged_df['SrcBytes'].replace('-', 0), errors='coerce').fillna(0)
    final_df['dbytes'] = pd.to_numeric(merged_df['DstBytes'].replace('-', 0), errors='coerce').fillna(0)
    final_df['spkts'] = pd.to_numeric(merged_df['SrcPkts'].replace('-', 0), errors='coerce').fillna(0)
    final_df['dpkts'] = pd.to_numeric(merged_df['DstPkts'].replace('-', 0), errors='coerce').fillna(0)
    
    dur_ms = final_df['dur'] * 1000
    final_df['stime'] = pd.to_numeric(merged_df['StartTime'], errors='coerce').fillna(0)
    final_df['ltime'] = final_df['stime'] + final_df['dur']
        
    feature_map = {
        'state': 'State', 'sttl': 'sTtl', 'dttl': 'dTtl', 'sload': 'SrcLoad', 
        'dload': 'DstLoad', 'sloss': 'SrcLoss', 'dloss': 'DstLoss',
        'sjit': 'SrcJitter', 'djit': 'DstJitter', 'stcpb': 'SrcTCPBase', 
        'dtcpb': 'DstTCPBase', 'tcprtt': 'TcpRtt', 'synack': 'SynAck', 
        'ackdat': 'AckDat', 'sintpkt': 'SIntPkt', 'dintpkt': 'DIntPkt'
    }
    for target, source in feature_map.items():
        if source in merged_df.columns:
            if target == 'state':
                final_df[target] = merged_df[source].astype(str).str.upper().str.strip()
            else:
                final_df[target] = pd.to_numeric(merged_df[source], errors='coerce').fillna(0)  

    final_df['swin'] = merged_df['SrcWin'].clip(upper=255)
    final_df['dwin'] = merged_df['DstWin'].clip(upper=255)
    
    final_df['is_sm_ips_ports'] = np.where(
        (merged_df['id.orig_h'] == merged_df['id.resp_h']) & 
        (merged_df['id.orig_p'] == merged_df['id.resp_p']), 1, 0
    )

    final_df['smeansz'] = np.where(final_df['spkts'] > 0, final_df['sbytes'] / final_df['spkts'], 0)
    final_df['dmeansz'] = np.where(final_df['dpkts'] > 0, final_df['dbytes'] / final_df['dpkts'], 0)

    def global_count(series, window=100):
        vals = series.tolist()
        counts = []
        for i in range(len(vals)):
            start = max(0, i - window + 1)
            counts.append(vals[start:i+1].count(vals[i]))
        return counts
    
    final_df['ct_state_ttl'] = global_count(merged_df['State'].astype(str) + "_" + merged_df['sTtl'].astype(str))
    final_df['ct_dst_ltm'] = global_count(merged_df['id.resp_h'])
    final_df['ct_src_ltm'] = global_count(merged_df['id.orig_h']) 
    final_df['ct_srv_src'] = global_count(merged_df['service'].astype(str) + "_" + merged_df['id.orig_h'].astype(str))
    final_df['ct_srv_dst'] = global_count(merged_df['service'].astype(str) + "_" + merged_df['id.resp_h'].astype(str))
    final_df['ct_src_dport_ltm'] = global_count(merged_df['id.orig_h'].astype(str) + "_" + merged_df['id.resp_p'].astype(str))
    final_df['ct_dst_sport_ltm'] = global_count(merged_df['id.resp_h'].astype(str) + "_" + merged_df['id.orig_p'].astype(str))
    final_df['ct_dst_src_ltm'] = global_count(merged_df['id.orig_h'].astype(str) + "_" + merged_df['id.resp_h'].astype(str))
    
    final_df = final_df.fillna(0).round(4)
    
    if not df_http.empty and 'uid' in df_http.columns:
        h_agg = df_http.groupby('uid').agg({
            'trans_depth': 'max', 
            'response_body_len': 'sum'
        }).to_dict()
        final_df['trans_depth'] = merged_df['uid'].map(h_agg.get('trans_depth', {})).fillna(0)
        final_df['res_bdy_len'] = merged_df['uid'].map(h_agg.get('response_body_len', {})).fillna(0)
        final_df['ct_flw_http_mthd'] = global_count(merged_df['service'])
        final_df.loc[merged_df['service'] != 'http', 'ct_flw_http_mthd'] = 0

    if not df_ftp.empty and 'uid' in df_ftp.columns:
        f_login_map = df_ftp.groupby('uid').apply(
            lambda x: 1 if (x['user'].notnull().any() and x['password'].notnull().any()) else 0
        ).to_dict()
        final_df['is_ftp_login'] = merged_df['uid'].map(f_login_map).fillna(0).astype(int)
        final_df['ct_ftp_cmd'] = global_count(merged_df['service'])
        final_df.loc[merged_df['service'] != 'ftp', 'ct_ftp_cmd'] = 0
        
    final_df.to_csv(output_csv, index=False)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python feature_extractor.py <argus_input.csv> <output_csv>")
    else:
        process_pipeline(sys.argv[1], sys.argv[2])