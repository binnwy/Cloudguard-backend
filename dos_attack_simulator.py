# =====================================================
# DoS (DENIAL OF SERVICE) ATTACK SIMULATOR
# Generates suspicious DoS attack logs and uploads
# predictions to Supabase
# =====================================================

import pandas as pd
import numpy as np
from catboost import CatBoostClassifier
from supabase import create_client
from datetime import datetime, timezone
import random
import time

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

# ---------------- COMMON DoS TARGET PORTS ----------------
DOS_TARGET_PORTS = [80, 443, 8080, 8443, 53, 22, 3389]  # HTTP, HTTPS, DNS, SSH, RDP

# ---------------- ATTACKER IP RANGES (for simulation) ----------------
ATTACKER_IP_POOL = [
    "192.168.1.{}",
    "10.0.0.{}",
    "172.16.0.{}",
    "203.0.113.{}",  # Example public IPs
    "198.51.100.{}",
    "185.220.100.{}",  # More attacker IPs
    "45.67.230.{}"
]

# ---------------- LOAD MODEL ----------------
print("🔄 Loading ML model...")
model = CatBoostClassifier()
model.load_model("catboost_model.cbm")
print("✅ Model loaded successfully\n")

# =====================================================
# DoS ATTACK SAMPLE (ALREADY SCALED)
# =====================================================

dos_attack_sample = pd.DataFrame([{
    "Dst Port": 0.132751,
    "Protocol": -0.435226,
    "Flow Duration": -0.011893,
    "Tot Fwd Pkts": -0.018265,
    "TotLen Fwd Pkts": -0.014035,
    "Flow Byts/s": -0.049256,
    "Flow Pkts/s": -0.273198,
    "Pkt Size Avg": -0.072536
}])

# =====================================================
# GENERATE SUSPICIOUS DoS ATTACK LOG ENTRIES
# =====================================================

def generate_dos_log_entry(scaled_features, attack_num=1):
    """
    Generate a suspicious DoS attack log entry.
    DoS attacks typically have:
    - High volume of traffic (many packets/bytes)
    - Multiple source IPs targeting single destination
    - High packet/byte rates (flooding)
    - Common web ports (80, 443) or random ports
    - TCP SYN floods, UDP floods, or ICMP floods
    - Short to medium duration floods
    """
    row = scaled_features.iloc[0]
    
    # DoS attack characteristics based on scaled features
    # Negative scaled values suggest lower than average, but for DoS we want high volume
    
    # Dst Port: 0.132751 -> common web ports for DoS
    dst_port = random.choice(DOS_TARGET_PORTS)
    
    # Protocol: -0.435226 -> could be TCP (6), UDP (17), or ICMP (1)
    # DoS attacks can use various protocols
    protocol = random.choice([6, 17, 1])  # TCP, UDP, ICMP
    
    # Flow Duration: -0.011893 -> very short duration (rapid flood)
    # DoS floods are typically short bursts
    flow_duration_ms = random.randint(100, 3000)  # 0.1-3 seconds
    
    # Tot Fwd Pkts: -0.018265 -> but for DoS we want HIGH packet count
    # DoS floods send many packets rapidly
    packets = random.randint(1000, 10000)  # High packet count
    
    # TotLen Fwd Pkts: -0.014035 -> but for DoS we want HIGH byte count
    # DoS floods send large amounts of data
    bytes_total = random.randint(50000, 500000)  # High byte count
    
    # Flow Byts/s: -0.049256 -> but DoS has HIGH byte rate
    # Flow Pkts/s: -0.273198 -> but DoS has HIGH packet rate
    # These will be high due to short duration and high packet/byte counts
    
    # Calculate start and end times
    current_time = int(time.time())
    start_time = current_time - flow_duration_ms // 1000
    end_time = current_time
    
    # Generate multiple attacker IPs (DoS uses many sources)
    attacker_ip_template = random.choice(ATTACKER_IP_POOL)
    src_ip = attacker_ip_template.format(random.randint(100, 254))
    
    # Target IP (victim server)
    dst_ip = "10.0.1.100"  # Target server
    
    # Source port (random high port)
    src_port = random.randint(49152, 65535)
    
    # TCP flags for DoS attacks
    if protocol == 6:  # TCP
        # SYN flood (most common DoS)
        tcp_flags = random.choice([2, 18, 4])  # SYN, SYN-ACK, RST
    else:
        tcp_flags = 0  # No flags for UDP/ICMP
    
    # Action (ACCEPT for successful flood, REJECT for blocked)
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

def simulate_dos_attack(num_attacks=15):
    """
    Simulate multiple DoS attack attempts and upload to Supabase
    """
    print(f"🎯 Simulating {num_attacks} DoS attack attempts...\n")
    
    # Prepare model input (already scaled)
    X_scaled = dos_attack_sample[[
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
        log_entry = generate_dos_log_entry(dos_attack_sample, attack_num=i+1)
        
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
            "region": log_entry["region"],
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
        time.sleep(0.05)  # Faster than brute force (DoS is more rapid)
    
    # Upload to Supabase
    try:
        # Try with timestamp first
        records_with_timestamp = []
        for record in records:
            record_copy = record.copy()
            record_copy["processed_at"] = processed_at
            records_with_timestamp.append(record_copy)
        
        result = supabase.table("cloudguard_logs").insert(records_with_timestamp).execute()
        print(f"✅ Successfully uploaded {len(records)} DoS attack records to Supabase (with timestamps)")
        return True
    except Exception as e:
        # Fall back without timestamp if column doesn't exist
        error_msg = str(e)
        if "processed_at" in error_msg or "PGRST204" in error_msg:
            try:
                print("⚠️  Timestamp column not found, uploading without timestamps...")
                result = supabase.table("cloudguard_logs").insert(records).execute()
                print(f"✅ Successfully uploaded {len(records)} DoS attack records to Supabase")
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
    """Main function to run DoS attack simulation"""
    print("="*60)
    print("🔥 DoS (DENIAL OF SERVICE) ATTACK SIMULATOR")
    print("="*60)
    print()
    
    # Number of attack attempts to simulate
    num_attacks = 15
    
    print(f"🚨 Simulating {num_attacks} DoS attack attempts...")
    print("   Target ports: HTTP (80), HTTPS (443), DNS (53), etc.")
    print("   Characteristics: High volume, rapid floods, multiple protocols")
    print("   Attack types: SYN flood, UDP flood, ICMP flood")
    print()
    
    success = simulate_dos_attack(num_attacks)
    
    if success:
        print("\n" + "="*60)
        print("✅ DoS ATTACK SIMULATION COMPLETE")
        print("="*60)
        print(f"📊 Check Supabase table 'cloudguard_logs' for {num_attacks} new DoS attack records")
        print()
    else:
        print("\n❌ Simulation failed. Please check the error messages above.")

if __name__ == "__main__":
    main()
