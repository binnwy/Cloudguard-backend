# =====================================================
# CLOUDGUARD BACKEND: LIVE LOG MONITORING SERVICE
# =====================================================

import boto3
import pandas as pd
import numpy as np
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
POLL_INTERVAL = 30
STATE_FILE = "cloudguard_state.json"

# ---------------- AWS CLIENT ----------------
client = boto3.client("logs", region_name=REGION)

# ---------------- SUPABASE CONFIG ----------------
SUPABASE_URL = "https://mynvptcdzwebyialuzpu.supabase.co"
SUPABASE_KEY = "sb_publishable_rhR-0ukNAf5xWfD1ZPQIrQ_CG5UsaKI"
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------- VPC FLOW LOG COLUMNS ----------------
COLUMNS = [
    "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
    "packets", "bytes", "start", "end", "action",
    "tcp_flags", "pkt_srcaddr", "pkt_dstaddr",
    "region", "flow_direction", "traffic_path",
    "interface_id", "log_status"
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
# CUSTOM ENSEMBLE CLASS (MUST MATCH TRAINING FILE)
# =====================================================

class WeightedEnsembleModel:

    def __init__(self, xgboost_model, catboost_model, catboost_weight=0.7, xgboost_weight=0.3):
        self.xgboost_model = xgboost_model
        self.catboost_model = catboost_model
        self.catboost_weight = catboost_weight
        self.xgboost_weight = xgboost_weight

        total_weight = catboost_weight + xgboost_weight
        self.catboost_weight = catboost_weight / total_weight
        self.xgboost_weight = xgboost_weight / total_weight

    def predict(self, X):

        if self.xgboost_weight == 0.0:
            return self.catboost_model.predict(X)

        catboost_proba = self.catboost_model.predict_proba(X)
        xgboost_proba = self.xgboost_model.predict_proba(X)

        ensemble_proba = (
            self.catboost_weight * catboost_proba +
            self.xgboost_weight * xgboost_proba
        )

        return np.argmax(ensemble_proba, axis=1)

    def predict_proba(self, X):

        if self.xgboost_weight == 0.0:
            return self.catboost_model.predict_proba(X)

        catboost_proba = self.catboost_model.predict_proba(X)
        xgboost_proba = self.xgboost_model.predict_proba(X)

        ensemble_proba = (
            self.catboost_weight * catboost_proba +
            self.xgboost_weight * xgboost_proba
        )

        return ensemble_proba

# =====================================================
# STATE MANAGEMENT
# =====================================================

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            state = json.load(f)
            return state.get('last_timestamp', None)
    return None

def save_state(timestamp):
    state = {
        'last_timestamp': timestamp,
        'last_updated': datetime.now(timezone.utc).isoformat()
    }
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

# =====================================================
# MODEL LOADING
# =====================================================

print("🔄 Loading Ensemble model and scaler...")
scaler = joblib.load("scaler.pkl")
model = joblib.load("ensemble_model.pkl")
print("✅ Ensemble model and scaler loaded successfully")

# =====================================================
# LOG FUNCTIONS
# =====================================================

def get_latest_log_stream():
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
    try:
        params = {
            "logGroupName": LOG_GROUP,
            "logStreamName": log_stream_name,
            "startFromHead": False,
            "limit": 10000
        }
        if start_time:
            params["startTime"] = start_time

        response = client.get_log_events(**params)
        return response.get("events", [])
    except Exception as e:
        print(f"❌ Error fetching logs: {e}")
        return []

# =====================================================
# PROCESS LOGS
# =====================================================

def process_logs(events):
    if not events:
        return pd.DataFrame()

    rows = []
    timestamps = []

    for event in events:
        fields = event["message"].split()
        if len(fields) == len(COLUMNS):
            rows.append(fields)
            timestamps.append(event.get("ingestionTime", int(time.time()*1000)))

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows, columns=COLUMNS)

    numeric_cols = [
        "srcport","dstport","protocol",
        "packets","bytes","start","end","tcp_flags"
    ]

    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df.dropna(inplace=True)

    if df.empty:
        return pd.DataFrame()

    df["event_timestamp"] = timestamps[:len(df)]

    df_feat = df[["dstport","protocol","packets","bytes","start","end"]].copy()

    df_feat["Flow Duration"] = df_feat["end"] - df_feat["start"]
    df_feat["Flow Duration"] = df_feat["Flow Duration"].replace(0,1)

    df_feat["Flow Byts/s"] = df_feat["bytes"] / df_feat["Flow Duration"]
    df_feat["Flow Pkts/s"] = df_feat["packets"] / df_feat["Flow Duration"]
    df_feat["Pkt Size Avg"] = df_feat["bytes"] / df_feat["packets"]

    df_feat.replace([np.inf,-np.inf],0,inplace=True)

    X = df_feat[[
        "dstport","protocol","Flow Duration",
        "packets","bytes",
        "Flow Byts/s","Flow Pkts/s","Pkt Size Avg"
    ]]

    X.columns = [
        "Dst Port","Protocol","Flow Duration",
        "Tot Fwd Pkts","TotLen Fwd Pkts",
        "Flow Byts/s","Flow Pkts/s","Pkt Size Avg"
    ]

    X_scaled = scaler.transform(X)

    predictions = model.predict(X_scaled)
    probabilities = model.predict_proba(X_scaled)

    df["Predicted_Label"] = predictions
    df["Confidence"] = probabilities.max(axis=1)
    df["Attack_Type"] = df["Predicted_Label"].map(
        lambda x: LABEL_MAP.get(int(x), f"Unknown({x})")
    )

    df["processed_at"] = datetime.now(timezone.utc).isoformat()

    return df

# =====================================================
# SAVE TO SUPABASE
# =====================================================

def save_to_supabase(df):
    if df.empty:
        return False

    BATCH_SIZE = 10

    total = len(df)
    print(f"🚀 Saving {total} records in batches of {BATCH_SIZE}")

    for start in range(0, total, BATCH_SIZE):
        batch_df = df.iloc[start:start+BATCH_SIZE]

        records = []

        for _, row in batch_df.iterrows():

            # 🌍 region lookup (only 10 at a time now)
            region = get_ip_region(row["srcaddr"], row["dstaddr"])

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
                "region": region,
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
            supabase.table("cloudguard_logs").insert(records).execute()
            print(f"✅ Inserted batch {start//BATCH_SIZE + 1}")

        except Exception as e:
            print(f"❌ Error inserting batch: {e}")

    return True
# =====================================================
# MAIN LOOP
# =====================================================

def main():

    print("\n" + "="*60)
    print("🚀 CLOUDGUARD BACKEND SERVICE STARTING")
    print("="*60)

    last_timestamp = load_state()

    iteration = 0

    try:
        while True:
            iteration += 1
            print(f"\n🔄 Iteration #{iteration}")

            log_stream = get_latest_log_stream()

            if not log_stream:
                print("⚠️ No log stream found")
                time.sleep(POLL_INTERVAL)
                continue

            events = fetch_new_logs(log_stream, start_time=last_timestamp)

            if events:
                print(f"📥 Fetched {len(events)} logs")

                df = process_logs(events)

                if not df.empty:

                    print(f"🔍 Processed {len(df)} logs")

                    attack_counts = df["Attack_Type"].value_counts()

                    print("\n📊 Attack Type Distribution:")
                    for attack_type, count in attack_counts.items():
                        print(f"   {attack_type}: {count}")

                    if any(df["Attack_Type"] != "Normal"):
                        print("🚨 ALERT: Suspicious traffic detected!")

                    save_to_supabase(df)

                    max_timestamp = df["event_timestamp"].max()
                    if max_timestamp:
                        last_timestamp = int(max_timestamp) + 1
                        save_state(last_timestamp)
            else:
                print("ℹ️ No new logs")

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n🛑 Service Stopped")

if __name__ == "__main__":
    main()
