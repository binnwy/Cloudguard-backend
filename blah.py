from supabase import create_client

url = "https://mynvptcdzwebyialuzpu.supabase.co"
key = "sb_publishable_rhR-0ukNAf5xWfD1ZPQIrQ_CG5UsaKI"

supabase = create_client(url, key)

data = supabase.table("cloudguard_logs").select("*").execute()
print(data)
