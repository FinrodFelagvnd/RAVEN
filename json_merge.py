import json
from config import *
import os

file1_path = os.path.join(RESULT_SAVE_PATH, "a.json")
with open(file1_path, 'r', encoding='utf-8') as f1:
    data1 = json.load(f1)

file2_path = os.path.join(RESULT_SAVE_PATH, "b.json")
with open(file2_path, 'r', encoding='utf-8') as f2:
    data2 = json.load(f2)

merged_data = data1 + data2

output_path = os.path.join(RESULT_SAVE_PATH, "c.json")
with open(output_path, 'w', encoding='utf-8') as f_out:
    json.dump(merged_data, f_out, indent=4, ensure_ascii=False)

print("Merge Complete!")
