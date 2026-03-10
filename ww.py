# =====================================================
# CLOUDGUARD: LIVE VPC FLOW LOG FETCH + ML PREDICTION
# + SUPABASE STORAGE
# =====================================================

import boto3
import pandas as pd
import numpy as np
from catboost import CatBoostClassifier
import joblib
from supabase import create_client

# ---------------- AWS CONFIG ----------------
LOG_GROUP = "/aws/vpc/flowlogs"
REGION = "ap-south-1"

client = boto3.client("logs", region_name=REGION)

# ---------------- SUPABASE CONFIG ----------------
SUPABASE_URL = "https://mynvptcdzwebyialuzpu.supabase.co"
SUPABASE_KEY = "sb_publishable_rhR-0ukNAf5xWfD1ZPQIrQ_CG5UsaKI"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------- FETCH LATEST LOG STREAM ----------------
streams = client.describe_log_streams(
    logGroupName=LOG_GROUP,
    orderBy="LastEventTime",
    descending=True,
    limit=1
)

log_stream = streams["logStreams"][0]["logStreamName"]

# ---------------- FETCH LOG EVENTS ----------------
response = client.get_log_events(
    logGroupName=LOG_GROUP,
    logStreamName=log_stream,
    startFromHead=False
)

# ---------------- VPC FLOW LOG COLUMNS ----------------
columns = [
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

rows = []

# ---------------- PARSE LOG LINES ----------------
for event in response["events"]:
    fields = event["message"].split()
    if len(fields) == len(columns):
        rows.append(fields)

# ---------------- CREATE DATAFRAME ----------------
df = pd.DataFrame(rows, columns=columns)

# ---------------- CONVERT NUMERIC FIELDS ----------------
numeric_cols = [
    "srcport", "dstport", "protocol",
    "packets", "bytes", "start", "end", "tcp_flags"
]

for col in numeric_cols:
    df[col] = pd.to_numeric(df[col], errors="coerce")

df.dropna(inplace=True)

# =====================================================
# ESSENTIAL FEATURES (USED ONLY FOR MODEL INPUT)
# =====================================================

df_feat = df[[
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end"
]].copy()

# ---------------- FEATURE ENGINEERING ----------------
df_feat["Flow Duration"] = df_feat["end"] - df_feat["start"]
df_feat["Flow Duration"] = df_feat["Flow Duration"].replace(0, 1)

df_feat["Flow Byts/s"] = df_feat["bytes"] / df_feat["Flow Duration"]
df_feat["Flow Pkts/s"] = df_feat["packets"] / df_feat["Flow Duration"]
df_feat["Pkt Size Avg"] = df_feat["bytes"] / df_feat["packets"]

df_feat.replace([np.inf, -np.inf], 0, inplace=True)

# ---------------- FINAL MODEL INPUT (ORDER MATTERS) ----------------
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

# =====================================================
# LOAD SCALER + MODEL
# =====================================================

scaler = joblib.load("scaler.pkl")
X_scaled = scaler.transform(X)

model = CatBoostClassifier()
model.load_model("catboost_model.cbm")

# =====================================================
# PREDICTION
# =====================================================

df["Predicted_Label"] = model.predict(X_scaled)
df["Confidence"] = model.predict_proba(X_scaled).max(axis=1)

label_map = {
    0: "Benign",
    1: "DoS",
    2: "Probe",
    3: "R2L",
    4: "U2R"
}

df["Attack_Type"] = df["Predicted_Label"].map(label_map)

# =====================================================
# INSERT FULL LOGS + PREDICTIONS INTO SUPABASE
# =====================================================

records = []

for _, row in df.iterrows():
    records.append({
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
        "region": row["region"],
        "flow_direction": row["flow_direction"],
        "traffic_path": row["traffic_path"],
        "interface_id": row["interface_id"],
        "log_status": row["log_status"],
        "predicted_label": int(row["Predicted_Label"]),
        "confidence": float(row["Confidence"]),
        "attack_type": row["Attack_Type"]
    })

# Batch insert
supabase.table("cloudguard_logs").insert(records).execute()

# =====================================================
# OPTIONAL: SAVE LOCAL CSV (CAN REMOVE IF NOT NEEDED)
# =====================================================

df.to_csv("cloudguard_live_predictions.csv", index=False)

print("\n✅ CLOUDGUARD LIVE PREDICTIONS STORED IN SUPABASE\n")
print(df.head())
print("\n📁 Supabase table: cloudguard_logs")
