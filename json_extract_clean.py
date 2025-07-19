import json, os
from config import *


INPUT_FILE = os.path.join(RAW_DATA_PATH, 'PairVul/full-dataset/Linux_kernel_clean_data.json')
OUTPUT_FILE = os.path.join(RESULT_SAVE_PATH, "clean_data.json")     

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

filtered = []
for item in data:
    cwe_list = item.get("cwe", [])
    if not any(cwe in CWE_ID for cwe in cwe_list):
        filtered.append(item)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(filtered, f, ensure_ascii=False, indent=4)

print(f"Filtered {len(filtered)} samples and saved to {OUTPUT_FILE}")

