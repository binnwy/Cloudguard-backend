import boto3
import pandas as pd

LOG_GROUP = "/aws/vpc/flowlogs"
REGION = "ap-south-1"

client = boto3.client("logs", region_name=REGION)

# 1️⃣ Get latest log stream
streams = client.describe_log_streams(
    logGroupName=LOG_GROUP,
    orderBy="LastEventTime",
    descending=True,
    limit=1
)

log_stream = streams["logStreams"][0]["logStreamName"]

# 2️⃣ Fetch log events
response = client.get_log_events(
    logGroupName=LOG_GROUP,
    logStreamName=log_stream,
    startFromHead=False
)

# 3️⃣ Define column headers (MATCHES YOUR CUSTOM FORMAT)
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

# 4️⃣ Parse each log line
for event in response["events"]:
    fields = event["message"].split()

    if len(fields) == len(columns):
        rows.append(fields)

# 5️⃣ Create DataFrame
df = pd.DataFrame(rows, columns=columns)

# 6️⃣ Convert numeric fields
numeric_cols = [
    "srcport", "dstport", "protocol",
    "packets", "bytes", "start", "end", "tcp_flags"
]

for col in numeric_cols:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# 7️⃣ Display result
print("\nVPC FLOW LOGS WITH HEADERS:\n")
print(df.head())

# 8️⃣ (Optional) Save to CSV
df.to_csv("vpc_flow_logs.csv", index=False)
print("\nSaved as vpc_flow_logs.csv")
