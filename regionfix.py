import os
import time
import requests
import ipaddress
from supabase import create_client

# ---------------- SUPABASE CONFIG ----------------
SUPABASE_URL = "https://mynvptcdzwebyialuzpu.supabase.co"
SUPABASE_KEY = "sb_publishable_rhR-0ukNAf5xWfD1ZPQIrQ_CG5UsaKI"
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

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
            elif data.get("status") == "fail" and data.get("message") == "rate limited":
                # Rate limited -> Back off
                print("⚠️ Rate limit hit. Sleeping for 20 seconds...")
                time.sleep(20)
                return get_ip_region(src_ip, dst_ip)
    except Exception as e:
        print(f"⚠️  Error fetching IP location for {target_ip}: {e}")
        
    IP_CACHE[target_ip] = "Unknown"
    return "Unknown"

def fix_all_records():
    print("🚀 Starting regionfix for existing Supabase records...")
    
    # We fetch records in batches to avoid overwhelming memory and limits.
    # Looking for rows where datacenter is still null or same as region.
    # We will just sequentially query all rows using a pagination trick.
    page_size = 1000
    offset = 0
    
    total_updated = 0

    while True:
        print(f"Fetching rows {offset} to {offset + page_size - 1}...")
        response = supabase.table("cloudguard_logs").select("*").range(offset, offset + page_size - 1).execute()
        records = response.data
        
        if not records:
            print("✅ All existing records evaluated!")
            break
            
        updated_in_batch = 0
            
        for row in records:
            # We only want to update if it hasn't been migrated yet.
            # E.g. if datacenter is missing/null, or if region still looks like "ap-south-1" 
            # We assume it hasn't been fixed if datacenter is None.
            if row.get("datacenter") is None:
                original_region = row.get("region", "ap-south-1")
                src_ip = row.get("srcaddr")
                dst_ip = row.get("dstaddr")
                
                new_geographic_region = get_ip_region(src_ip, dst_ip)
                
                # Setup Update Payload
                update_payload = {
                    "region": new_geographic_region,
                    "datacenter": original_region
                }
                
                # We need a way to uniquely identify the row to update it.
                # Usually there's an `id` column in Supabase...
                if "id" in row:
                    try:
                        supabase.table("cloudguard_logs").update(update_payload).eq("id", row["id"]).execute()
                        updated_in_batch += 1
                    except Exception as e:
                        print(f"❌ Failed to update record ID {row['id']}: {e}")
                else:
                    # In case there's no primary key 'id', we try to match on unique combinations like timestamps
                    try:
                        supabase.table("cloudguard_logs").update(update_payload).match({
                            "srcaddr": src_ip, 
                            "dstaddr": dst_ip, 
                            "start": row.get("start")
                        }).execute()
                        updated_in_batch += 1
                    except Exception as e:
                         print(f"❌ Failed exact-match update: {e}")
                         
                # To be absolutely careful regarding API Rate Limits
                if updated_in_batch % 40 == 0:
                    time.sleep(1) # IP-API allows ~45 loc/minute normally, but let's delay softly anyway. We cached them heavily.

        total_updated += updated_in_batch
        print(f"🔄 Finished batch. Migrated {updated_in_batch} out of {len(records)} records.")
        offset += page_size
        
    print(f"\n🎉 Region Fix Complete! Migrated {total_updated} rows successfully.")

if __name__ == "__main__":
    fix_all_records()
