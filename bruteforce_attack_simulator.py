# =====================================================
# BRUTE FORCE ATTACK SIMULATOR
# Generates suspicious brute force attack logs and uploads
# predictions to Supabase
# =====================================================

import pandas as pd
import numpy as np
from catboost import CatBoostClassifier
from supabase import create_client
from datetime import datetime, timezone
import random
import time
import requests
import ipaddress

# ---------------- SUPABASE CONFIG ----------------
SUPABASE_URL = "https://mynvptcdzwebyialuzpu.supabase.co"
SUPABASE_KEY = "sb_publishable_rhR-0ukNAf5xWfD1ZPQIrQ_CG5UsaKI"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------- LABEL MAPPING ----------------
LABEL_MAP = {
    0: "Benign",
    1: "DoS",
    2: "DDoS",
    3: "PortScan",
    4: "BruteForce",
    5: "WebAttack"
}

# ---------------- COMMON BRUTE FORCE PORTS ----------------
BRUTEFORCE_PORTS = [22, 3389, 21, 23, 1433, 3306, 5432, 5900]  # SSH, RDP, FTP, Telnet, MSSQL, MySQL, PostgreSQL, VNC

# ---------------- SUSPICIOUS IP RANGES (for simulation) ----------------
SUSPICIOUS_IP_POOL = [
    "8.8.8.{}",
    "114.114.114.{}",
    "45.33.94.{}",
    "93.177.102.{}",  # Example public IPs
    "198.51.100.{}",
    "185.220.100.{}",  # More attacker IPs
    "45.67.230.{}"
]

# =====================================================
# IP LOCATION CACHE & LOOKUP
# =====================================================
IP_CACHE = {}

def get_ip_region(src_ip, dst_ip):
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
    except Exception:
        pass
        
    IP_CACHE[target_ip] = "Unknown"
    return "Unknown"

# ---------------- LOAD MODEL ----------------
print("🔄 Loading ML model...")
model = CatBoostClassifier()
model.load_model("catboost_model.cbm")
print("✅ Model loaded successfully\n")

# =====================================================
# BRUTE FORCE ATTACK SAMPLE (ALREADY SCALED)
# =====================================================

bf_attack_sample = pd.DataFrame([{
    "Dst Port": 0.477214,
    "Protocol": 0.955075,
    "Flow Duration": 0.115259,
    "Tot Fwd Pkts": -0.006775,
    "TotLen Fwd Pkts": 0.332535,
    "Flow Byts/s": 0.966205,
    "Flow Pkts/s": 1.063181,
    "Pkt Size Avg": -0.434789
}])

# =====================================================
# REVERSE ENGINEER SUSPICIOUS VALUES FROM SCALED FEATURES
# =====================================================

def generate_suspicious_log_entry(scaled_features, attack_num=1):
    """
    Generate a suspicious log entry that matches the scaled features.
    For brute force attacks, we want:
    - Multiple rapid connection attempts
    - Short duration connections (failed attempts)
    - High packet/byte rates
    - Common brute force target ports
    """
    row = scaled_features.iloc[0]
    
    # Extract approximate values (reverse engineering from scaled values)
    # These are estimates based on typical scaling ranges
    
    # Dst Port: 0.477214 scaled -> likely around port 22-3389 (common brute force targets)
    dst_port = random.choice(BRUTEFORCE_PORTS)
    
    # Protocol: 0.955075 -> TCP (6) is most common for brute force
    protocol = 6  # TCP
    
    # Flow Duration: 0.115259 -> very short duration (failed connection attempts)
    # Assuming min=0, max=3600000ms (1 hour), scaled 0.115259 ≈ 414 seconds
    # But for brute force, we want much shorter - let's use 1-5 seconds
    flow_duration_ms = random.randint(1000, 5000)  # 1-5 seconds
    
    # Tot Fwd Pkts: -0.006775 -> very few packets (connection attempt but no data)
    # For brute force, typically 2-10 packets per attempt
    packets = random.randint(2, 10)
    
    # TotLen Fwd Pkts: 0.332535 -> moderate bytes
    # For brute force attempts, typically 100-500 bytes
    bytes_total = random.randint(100, 500)
    
    # Flow Byts/s: 0.966205 -> high byte rate (rapid attempts)
    # Flow Pkts/s: 1.063181 -> high packet rate (rapid attempts)
    # Pkt Size Avg: -0.434789 -> small packet size
    
    # Calculate start and end times
    current_time = int(time.time())
    start_time = current_time - flow_duration_ms // 1000
    end_time = current_time
    
    # Generate suspicious source IP (multiple different IPs for brute force)
    src_ip_template = random.choice(SUSPICIOUS_IP_POOL)
    src_ip = src_ip_template.format(random.randint(100, 254))
    
    # Target IP (internal server)
    dst_ip = "10.0.1.100"  # Target server
    
    # Source port (random high port)
    src_port = random.randint(49152, 65535)
    
    # TCP flags for connection attempts (SYN, SYN-ACK, RST)
    tcp_flags = random.choice([2, 18, 4])  # SYN=2, SYN-ACK=18, RST=4
    
    # Action (ACCEPT for failed attempts, REJECT for blocked)
    action = random.choice(["ACCEPT", "REJECT"])
    
    # Generate log entry
    log_entry = {
        "srcaddr": src_ip,
        "dstaddr": dst_ip,
        "srcport": src_port,
        "dstport": dst_port,
        "protocol": protocol,
        "packets": packets,
        "bytes": bytes_total,
        "start": start_time,
        "end": end_time,
        "action": action,
        "tcp_flags": tcp_flags,
        "pkt_srcaddr": src_ip,
        "pkt_dstaddr": dst_ip,
        "region": "ap-south-1",
        "flow_direction": "ingress",
        "traffic_path": "external",
        "interface_id": f"eni-{''.join([str(random.randint(0,9)) for _ in range(16)])}",
        "log_status": "OK"
    }
    
    return log_entry

# =====================================================
# PREDICT AND UPLOAD TO SUPABASE
# =====================================================

def simulate_bruteforce_attack(num_attacks=10):
    """
    Simulate multiple brute force attack attempts and upload to Supabase
    """
    print(f"🎯 Simulating {num_attacks} brute force attack attempts...\n")
    
    # Prepare model input (already scaled)
    X_scaled = bf_attack_sample[[
        "Dst Port",
        "Protocol",
        "Flow Duration",
        "Tot Fwd Pkts",
        "TotLen Fwd Pkts",
        "Flow Byts/s",
        "Flow Pkts/s",
        "Pkt Size Avg"
    ]]
    
    # Get predictions
    predictions = model.predict(X_scaled)
    probabilities = model.predict_proba(X_scaled)
    
    # Get prediction for the sample (fix deprecation warning)
    if isinstance(predictions, np.ndarray):
        predicted_label = int(predictions.item() if predictions.size == 1 else predictions[0])
    else:
        predicted_label = int(predictions[0])
    
    # Handle probabilities array
    if len(probabilities.shape) > 1:
        prob_array = probabilities[0]
    else:
        prob_array = probabilities
    
    confidence = float(np.max(prob_array))
    attack_type = LABEL_MAP.get(predicted_label, f"Unknown({predicted_label})")
    
    print(f"📊 Prediction Results:")
    print(f"   Attack Type: {attack_type}")
    print(f"   Label: {predicted_label}")
    print(f"   Confidence: {confidence:.4f}")
    print(f"   Probability Distribution:")
    for i, prob in enumerate(prob_array):
        label_name = LABEL_MAP.get(i, f"Unknown({i})")
        print(f"      {label_name}: {prob:.4f}")
    print()
    
    # Generate multiple suspicious log entries
    records = []
    processed_at = datetime.now(timezone.utc).isoformat()
    
    for i in range(num_attacks):
        log_entry = generate_suspicious_log_entry(bf_attack_sample, attack_num=i+1)
        
        # Add prediction results
        record = {
            "srcaddr": log_entry["srcaddr"],
            "dstaddr": log_entry["dstaddr"],
            "srcport": log_entry["srcport"],
            "dstport": log_entry["dstport"],
            "protocol": log_entry["protocol"],
            "packets": log_entry["packets"],
            "bytes": log_entry["bytes"],
            "start": log_entry["start"],
            "end": log_entry["end"],
            "action": log_entry["action"],
            "tcp_flags": log_entry["tcp_flags"],
            "pkt_srcaddr": log_entry["pkt_srcaddr"],
            "pkt_dstaddr": log_entry["pkt_dstaddr"],
            "region": get_ip_region(log_entry["srcaddr"], log_entry["dstaddr"]),
            "datacenter": log_entry["region"],
            "flow_direction": log_entry["flow_direction"],
            "traffic_path": log_entry["traffic_path"],
            "interface_id": log_entry["interface_id"],
            "log_status": log_entry["log_status"],
            "predicted_label": predicted_label,
            "confidence": confidence,
            "attack_type": attack_type
        }
        
        records.append(record)
        
        # Small delay to simulate real-time attacks
        time.sleep(0.1)
    
    # Upload to Supabase
    try:
        # Try with timestamp first
        records_with_timestamp = []
        for record in records:
            record_copy = record.copy()
            record_copy["processed_at"] = processed_at
            records_with_timestamp.append(record_copy)
        
        result = supabase.table("cloudguard_logs").insert(records_with_timestamp).execute()
        print(f"✅ Successfully uploaded {len(records)} brute force attack records to Supabase (with timestamps)")
        return True
    except Exception as e:
        # Fall back without timestamp if column doesn't exist
        error_msg = str(e)
        if "processed_at" in error_msg or "PGRST204" in error_msg:
            try:
                print("⚠️  Timestamp column not found, uploading without timestamps...")
                result = supabase.table("cloudguard_logs").insert(records).execute()
                print(f"✅ Successfully uploaded {len(records)} brute force attack records to Supabase")
                return True
            except Exception as e2:
                print(f"❌ Error uploading to Supabase: {e2}")
                return False
        else:
            print(f"❌ Error uploading to Supabase: {e}")
            return False

# =====================================================
# MAIN FUNCTION
# =====================================================

def main():
    """Main function to run brute force attack simulation"""
    print("="*60)
    print("🔥 BRUTE FORCE ATTACK SIMULATOR")
    print("="*60)
    print()
    
    # Number of attack attempts to simulate
    num_attacks = 10
    
    print(f"🚨 Simulating {num_attacks} brute force attack attempts...")
    print("   Target ports: SSH (22), RDP (3389), FTP (21), etc.")
    print("   Characteristics: Short duration, rapid attempts, multiple source IPs")
    print()
    
    success = simulate_bruteforce_attack(num_attacks)
    
    if success:
        print("\n" + "="*60)
        print("✅ BRUTE FORCE ATTACK SIMULATION COMPLETE")
        print("="*60)
        print(f"📊 Check Supabase table 'cloudguard_logs' for {num_attacks} new attack records")
        print()
    else:
        print("\n❌ Simulation failed. Please check the error messages above.")

if __name__ == "__main__":
    main()
