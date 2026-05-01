# =====================================================
# CLOUDGUARD BACKEND: LIVE LOG MONITORING SERVICE
# Continuously fetches new VPC flow logs, processes through ML model,
# and stores predictions in Supabase with timestamps
# =====================================================

import boto3
import pandas as pd
import numpy as np
from catboost import CatBoostClassifier
import joblib
from supabase import create_client
import time
from datetime import datetime, timezone
import json
import os
import requests
import ipaddress

# ---------------- CONFIGURATION ----------------
LOG_GROUP = "/aws/vpc/flowlogs"
REGION = "ap-south-1"
POLL_INTERVAL = 30  # seconds between polls
STATE_FILE = "cloudguard_state.json"  # File to store last processed timestamp

# ---------------- AWS CLIENT ----------------
client = boto3.client("logs", region_name=REGION)

# ---------------- SUPABASE CONFIG ----------------
SUPABASE_URL = "https://mynvptcdzwebyialuzpu.supabase.co"
SUPABASE_KEY = "sb_publishable_rhR-0ukNAf5xWfD1ZPQIrQ_CG5UsaKI"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------- VPC FLOW LOG COLUMNS ----------------
COLUMNS = [
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "tcp_flags",
    "pkt_srcaddr",
    "pkt_dstaddr",
    "region",
    "flow_direction",
    "traffic_path",
    "interface_id",
    "log_status"
]

# ---------------- LABEL MAPPING ----------------
LABEL_MAP = {
    0: "Normal",
    1: "DoS",
    2: "DDoS",
    3: "PortScan",
    4: "BruteForce",
    5: "WebAttack"
}

# =====================================================
# IP LOCATION CACHE & LOOKUP
# =====================================================
IP_CACHE = {}

def get_ip_region(src_ip, dst_ip):
    """Determine the public IP and fetch its geographical region."""
    def is_public(ip):
        try:
            return not ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    target_ip = None
    if is_public(src_ip):
        target_ip = src_ip
    elif is_public(dst_ip):
        target_ip = dst_ip
    
    if not target_ip:
        return "Private Network"
        
    if target_ip in IP_CACHE:
        return IP_CACHE[target_ip]
        
    try:
        response = requests.get(f"http://ip-api.com/json/{target_ip}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                region = data.get("regionName", data.get("country", "Unknown"))
                IP_CACHE[target_ip] = region
                return region
    except Exception as e:
        print(f"⚠️  Error fetching IP location for {target_ip}: {e}")
        
    IP_CACHE[target_ip] = "Unknown"
    return "Unknown"

# =====================================================
# STATE MANAGEMENT (TRACK LAST PROCESSED TIMESTAMP)
# =====================================================

def load_state():
    """Load the last processed timestamp from state file"""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                state = json.load(f)
                return state.get('last_timestamp', None)
        except Exception as e:
            print(f"⚠️  Error loading state: {e}")
            return None
    return None

def save_state(timestamp):
    """Save the last processed timestamp to state file"""
    try:
        state = {
            'last_timestamp': timestamp,
            'last_updated': datetime.now(timezone.utc).isoformat()
        }
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"⚠️  Error saving state: {e}")

# =====================================================
# MODEL LOADING (LOAD ONCE AT STARTUP)
# =====================================================

print("🔄 Loading ML model and scaler...")
scaler = joblib.load("scaler.pkl")
model = CatBoostClassifier()
model.load_model("catboost_model.cbm")
print("✅ Model and scaler loaded successfully")

# =====================================================
# LOG PROCESSING FUNCTIONS
# =====================================================

def get_latest_log_stream():
    """Get the most recent log stream"""
    try:
        streams = client.describe_log_streams(
            logGroupName=LOG_GROUP,
            orderBy="LastEventTime",
            descending=True,
            limit=1
        )
        if streams["logStreams"]:
            return streams["logStreams"][0]["logStreamName"]
        return None
    except Exception as e:
        print(f"❌ Error fetching log stream: {e}")
        return None

def fetch_new_logs(log_stream_name, start_time=None):
    """Fetch new log events since start_time"""
    try:
        params = {
            "logGroupName": LOG_GROUP,
            "logStreamName": log_stream_name,
            "startFromHead": False,
            "limit": 10000  # Maximum events per call
        }
        
        if start_time:
            params["startTime"] = start_time
        
        response = client.get_log_events(**params)
        return response.get("events", [])
    except Exception as e:
        print(f"❌ Error fetching logs: {e}")
        return []

def process_logs(events):
    """Process log events through ML model and return predictions"""
    if not events:
        return pd.DataFrame()
    
    rows = []
    event_timestamps = []
    
    # Parse log lines
    for event in events:
        fields = event["message"].split()
        if len(fields) == len(COLUMNS):
            rows.append(fields)
            # Store event timestamp for later use
            event_timestamps.append(event.get("ingestionTime", int(time.time() * 1000)))
    
    if not rows:
        return pd.DataFrame()
    
    # Create dataframe
    df = pd.DataFrame(rows, columns=COLUMNS)
    
    # Convert numeric fields
    numeric_cols = [
        "srcport", "dstport", "protocol",
        "packets", "bytes", "start", "end", "tcp_flags"
    ]
    
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    
    # Drop rows with missing values
    df.dropna(inplace=True)
    
    if df.empty:
        return pd.DataFrame()
    
    # Add event timestamps
    df["event_timestamp"] = event_timestamps[:len(df)]
    
    # Feature engineering
    df_feat = df[[
        "dstport",
        "protocol",
        "packets",
        "bytes",
        "start",
        "end"
    ]].copy()
    
    df_feat["Flow Duration"] = df_feat["end"] - df_feat["start"]
    df_feat["Flow Duration"] = df_feat["Flow Duration"].replace(0, 1)
    
    df_feat["Flow Byts/s"] = df_feat["bytes"] / df_feat["Flow Duration"]
    df_feat["Flow Pkts/s"] = df_feat["packets"] / df_feat["Flow Duration"]
    df_feat["Pkt Size Avg"] = df_feat["bytes"] / df_feat["packets"]
    
    df_feat.replace([np.inf, -np.inf], 0, inplace=True)
    
    # Prepare model input
    X = df_feat[[
        "dstport",
        "protocol",
        "Flow Duration",
        "packets",
        "bytes",
        "Flow Byts/s",
        "Flow Pkts/s",
        "Pkt Size Avg"
    ]]
    
    X.columns = [
        "Dst Port",
        "Protocol",
        "Flow Duration",
        "Tot Fwd Pkts",
        "TotLen Fwd Pkts",
        "Flow Byts/s",
        "Flow Pkts/s",
        "Pkt Size Avg"
    ]
    
    # Scale and predict
    X_scaled = scaler.transform(X)
    df["Predicted_Label"] = model.predict(X_scaled)
    df["Confidence"] = model.predict_proba(X_scaled).max(axis=1)
    df["Attack_Type"] = df["Predicted_Label"].map(lambda x: LABEL_MAP.get(x, f"Unknown({x})"))
    
    # Add processing timestamp
    df["processed_at"] = datetime.now(timezone.utc).isoformat()
    
    return df

def save_to_supabase(df):
    """Save processed logs to Supabase"""
    if df.empty:
        return
    
    records = []
    
    for _, row in df.iterrows():
        record = {
            "srcaddr": row["srcaddr"],
            "dstaddr": row["dstaddr"],
            "srcport": int(row["srcport"]),
            "dstport": int(row["dstport"]),
            "protocol": int(row["protocol"]),
            "packets": int(row["packets"]),
            "bytes": int(row["bytes"]),
            "start": int(row["start"]),
            "end": int(row["end"]),
            "action": row["action"],
            "tcp_flags": int(row["tcp_flags"]),
            "pkt_srcaddr": row["pkt_srcaddr"],
            "pkt_dstaddr": row["pkt_dstaddr"],
            "region": get_ip_region(row["srcaddr"], row["dstaddr"]),
            "datacenter": row["region"],
            "flow_direction": row["flow_direction"],
            "traffic_path": row["traffic_path"],
            "interface_id": row["interface_id"],
            "log_status": row["log_status"],
            "predicted_label": int(row["Predicted_Label"]),
            "confidence": float(row["Confidence"]),
            "attack_type": row["Attack_Type"]
        }
        records.append(record)
    
    try:
        # First try with processed_at timestamp (if column exists in Supabase)
        records_with_timestamp = []
        for i, record in enumerate(records):
            record_copy = record.copy()
            record_copy["processed_at"] = df.iloc[i]["processed_at"]
            records_with_timestamp.append(record_copy)
        
        result = supabase.table("cloudguard_logs").insert(records_with_timestamp).execute()
        print(f"✅ Saved {len(records)} records to Supabase (with timestamps)")
        return True
    except Exception as e:
        # If timestamp column doesn't exist, try without it
        error_msg = str(e)
        if "processed_at" in error_msg or "event_timestamp" in error_msg or "PGRST204" in error_msg:
            try:
                print("⚠️  Timestamp columns not found in Supabase schema, saving without timestamps...")
                result = supabase.table("cloudguard_logs").insert(records).execute()
                print(f"✅ Saved {len(records)} records to Supabase")
                return True
            except Exception as e2:
                print(f"❌ Error saving to Supabase: {e2}")
                return False
        else:
            print(f"❌ Error saving to Supabase: {e}")
            return False

# =====================================================
# MAIN MONITORING LOOP
# =====================================================

def main():
    """Main backend service loop"""
    print("\n" + "="*60)
    print("🚀 CLOUDGUARD BACKEND SERVICE STARTING")
    print("="*60)
    print(f"📊 Log Group: {LOG_GROUP}")
    print(f"🌍 Region: {REGION}")
    print(f"⏱️  Poll Interval: {POLL_INTERVAL} seconds")
    print("="*60 + "\n")
    
    # Load last processed timestamp
    last_timestamp = load_state()
    if last_timestamp:
        print(f"📅 Resuming from timestamp: {last_timestamp}")
    else:
        print("🆕 Starting fresh - will process all new logs")
    
    iteration = 0
    
    try:
        while True:
            iteration += 1
            current_time = datetime.now(timezone.utc)
            print(f"\n[{current_time.strftime('%Y-%m-%d %H:%M:%S')}] Iteration #{iteration}")
            print("-" * 60)
            
            # Get latest log stream
            log_stream = get_latest_log_stream()
            if not log_stream:
                print("⚠️  No log stream found, waiting...")
                time.sleep(POLL_INTERVAL)
                continue
            
            print(f"📝 Processing log stream: {log_stream}")
            
            # Fetch new logs
            events = fetch_new_logs(log_stream, start_time=last_timestamp)
            
            if not events:
                print("ℹ️  No new logs found")
            else:
                print(f"📥 Fetched {len(events)} new log events")
                
                # Process through model
                df = process_logs(events)
                
                if not df.empty:
                    print(f"🔍 Processed {len(df)} logs through ML model")
                    
                    # Show attack type distribution
                    attack_counts = df["Attack_Type"].value_counts()
                    print("\n📊 Attack Type Distribution:")
                    for attack_type, count in attack_counts.items():
                        print(f"   {attack_type}: {count}")
                    
                    # Save to Supabase
                    if save_to_supabase(df):
                        # Update last timestamp (use the latest event timestamp)
                        max_timestamp = df["event_timestamp"].max()
                        if max_timestamp:
                            last_timestamp = int(max_timestamp) + 1  # Add 1ms to avoid reprocessing
                            save_state(last_timestamp)
                            print(f"💾 Updated state - last timestamp: {last_timestamp}")
                else:
                    print("⚠️  No valid logs to process after filtering")
            
            # Wait before next poll
            print(f"⏳ Waiting {POLL_INTERVAL} seconds before next poll...")
            time.sleep(POLL_INTERVAL)
            
    except KeyboardInterrupt:
        print("\n\n" + "="*60)
        print("🛑 CLOUDGUARD BACKEND SERVICE STOPPED")
        print("="*60)
        print("👋 Shutting down gracefully...")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
