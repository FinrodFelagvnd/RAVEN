import json, os
from config import *

DATASET_SUBPATH = "PairVul/full-dataset/Linux_kernel_clean_data_top5_CWEs.json"
DATASET_PATH = os.path.join(RAW_DATA_PATH, DATASET_SUBPATH)

def find_project_by_cve_cwe_id(cve_id: str, cwe: str, target_id: int):

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    target_list = data.get(cwe, [])
    
    index = next(
        (i for i, item in enumerate(target_list)
         if item.get("cve_id") == cve_id and item.get("id") == target_id),
        -1
    )
    
    if index != -1:
        return f"Target is the {index + 1}th in {cwe}."
    else:
        return "Not found."

def count_projects_per_cwe():
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    cwe_counts = {}
    
    for cwe_key, target_list in data.items():
        cwe_counts[cwe_key] = len(target_list)
    
    for cwe, count in cwe_counts.items():
        print(f"CWE {cwe} has {count} projects.")

count_projects_per_cwe()


# CVE-2020-36557_CWE-362_2766_20250511151953
cve_id = "CVE-2020-36557"
cwe = "CWE-362"
target_id = 2766
# result = find_project_by_cve_cwe_id(cve_id, cwe, target_id)
# print(result)
