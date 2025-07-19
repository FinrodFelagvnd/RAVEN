# match_all.py

import json, os, re
import numpy as np
import collections
from vector_match import vector_match_fuse
from graph_match import load_embeddings, graph_match, graph_match_ged
from knowledge_extractor import gen_message
from config import *
from prompt import *

def normalize_scores(score_dict):
    """
    normalize to [0,1]
    """
    if not score_dict:
        return {}

    scores = list(score_dict.values())
    max_score, min_score = max(scores), min(scores)
    if max_score == min_score:
        return {k: 1.0 for k in score_dict}
    return {k: (v - min_score) / (max_score - min_score) for k, v in score_dict.items()}

def convert_numpy(obj):
    if isinstance(obj, np.generic):
        return obj.item() 
    if isinstance(obj, np.ndarray):
        return obj.tolist()  
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

def query_embedding(json_file, cve_id, cwe_id, id):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    for key, item in data.items():
        if (
            str(item.get("cve_id")) == str(cve_id)
            and str(item.get("cwe_id")) == str(cwe_id)
            and str(item.get("project_id")) == str(id)
        ):
            embedding_str = item.get("embedding")
            if isinstance(embedding_str, str):
                return np.fromstring(embedding_str.strip("[]"), sep=' ').tolist()

    return []


def fuse_results(vector_results, graph_results, top_n=10, k=60):
    """
    fuse vector and graph matching results
    weights: (vector_score_weight, graph_score_weight)
    return top-n all_result list
    """
    vector_map = {
        (item["cve_id"], item["cwe_id"], str(item["project_id"])): item for item in vector_results
    }
    graph_map = {
        (item["cve_id"], item["cwe_id"], str(item["project_id"])): item for item in graph_results
    }

    vec_rank = {
        (item["cve_id"], item["cwe_id"], str(item["project_id"])): rank + 1
        for rank, item in enumerate(sorted(vector_results, key=lambda x: x["vector_score"], reverse=True))
    }
    graph_rank = {
        (item["cve_id"], item["cwe_id"], str(item["project_id"])): rank + 1
        for rank, item in enumerate(sorted(graph_results, key=lambda x: x["graph_score"], reverse=True))
    }
    all_keys = set(vec_rank.keys()) | set(graph_rank.keys())

    # print("ALL VECTOR KEYS:", list(vector_map.keys()))
    # print("ALL GRAPH KEYS:", list(graph_map.keys()))
    # print("ALL_KEYS:", list(all_keys))
    # print("VECTOR KEYS COUNT:", len(vector_map))
    # print("GRAPH KEYS COUNT:", len(graph_map))
    # print("UNION (ALL_KEYS) COUNT:", len(all_keys))
    # vector_keys = set(vector_map.keys())
    # graph_keys = set(graph_map.keys())  
    # print("INTERSECTION COUNT:", len(vector_keys & graph_keys))   
    # print("ONLY IN VECTOR:", len(vector_keys - graph_keys))       
    # print("ONLY IN GRAPH:", len(graph_keys - vector_keys))        


    fused = []
    for key in all_keys:
        vec_item = vector_map.get(key)
        graph_item = graph_map.get(key)

        vector_score = vec_item["vector_score"] if vec_item else 0.0
        graph_score = graph_item["graph_score"] if graph_item else 0.0

        # total_score = weights[0] * vector_score + weights[1] * graph_score    
        r_vec = vec_rank.get(key, float('inf')) 
        r_graph = graph_rank.get(key, float('inf'))
        rrf_score = (1 / (k + r_vec)) + (1 / (k + r_graph))

        graph_embedding = graph_item.get("graph_embedding", []) if graph_item else []

        if not graph_embedding:
            graph_embedding = query_embedding(os.path.join(RESULT_SAVE_PATH, "graph_embeddings.json"), key[0], key[1], key[2])

        result_item = {
            "project_id": key[2],
            "cwe_id": key[1],       # vec_item.get("cwe_id", "") if vec_item else graph_item.get("cwe_id", ""),
            "cve_id": key[0],
            "total_score": rrf_score,
            "vector_rank": r_vec if r_vec != float('inf') else None,
            "graph_rank": r_graph if r_graph != float('inf') else None,
            "vector_score": vector_score,
            "graph_score": graph_score,
            "purpose": vec_item.get("purpose", "") if vec_item else "",
            "functions": vec_item.get("functions", "") if vec_item else "",
            "vulnerability_cause": vec_item.get("vulnerability_cause", "") if vec_item else "",
            "score_detail": vec_item.get("score_detail", {}) if vec_item else {},
            "graph_embedding": graph_embedding,
        }

        fused.append(result_item)

    fused_sorted = sorted(fused, key=lambda x: x["total_score"], reverse=True)

    return fused_sorted[:top_n]

def fuse_all_test(top_l = 80, top_m = 100, top_n = 10, alpha=0.6, w_purpose=0.6, w_function=0.4):
    # 1. load vector match results
    # sample = VECTOR_MATCH_SAMPLE
    # vec_results = vector_match_fuse(sample['purpose'], sample['functions'], top_k=top_l, alpha=alpha, weights=(w_purpose, w_function))
    # print(vec_results)

    # 2. load graph embeddings and get graph match results
    path = os.path.join(RESULT_SAVE_PATH, "graph_embeddings.json")
    embeddings,  meta = load_embeddings(path)
    target_uid = "CVE-2006-3635_CWE-119_1_20250511142120"
    target_embed = embeddings[target_uid]
    # graph_results = graph_match(embeddings, meta, target_embed, k=top_m)
    graph_results = graph_match_ged(target_uid, meta, k=top_m, timeout=2)
    print(graph_results)

    # 3. fuse results
    # fused_top_n = fuse_results(vec_results, graph_results, top_n=top_n, weights=(beta, 1-beta))
    # print(fused_top_n)

    # output_path = os.path.join(RESULT_SAVE_PATH, "test_CVE-2006-3635_result.json")
    # with open("fused_results.json", "w", encoding="utf-8") as f:
    #     json.dump(fused_top_n, f, ensure_ascii=False, indent=4, default=convert_numpy)
    # print(f"[+] fused results: {output_path}")

def query_embeddings(json_file, cve_id, cwe_id, id):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    for key, item in data.items():
        if (
            str(item.get("cve_id")) == str(cve_id) and
            str(item.get("cwe_id")) == str(cwe_id) and
            str(item.get("project_id")) == str(id)
        ):
            embedding_str = item.get("embedding")
            if isinstance(embedding_str, str):
                return np.fromstring(embedding_str.strip("[]"), sep=' ')

    return None 

def query_target_item(json_file, cve_id, cwe_id, id):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    for item in data:
        if str(item.get("cve")) == str(cve_id) and str(item.get("cwe")) == str(cwe_id) and str(item.get("id")) == str(id):
            return item 

    return None 

def query_target_clean_item(json_file, cve_id, cwe_id, id):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    for item in data:
        if (
            str(item.get("cve")) == str(cve_id)
            and str(id) == str(item.get("id"))
            and cwe_id in item.get("cwe", [])
        ):
            return item 

    return None

def query_code(cve_id, cwe_id, id, path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        cwe_items = data.get(cwe_id)
        if not cwe_items:
            return f"No data found for CWE ID: {cwe_id}"
        # print(f"Found data for CWE ID: {cwe_id}, matching CVE IDs: {[item['cve_id'] for item in cwe_items]}") 
        for item in cwe_items:
            # print(f"Checking: CVE ID {item['cve_id']} with ID {item['id']}")
            if str(item["cve_id"]) == str(cve_id) and str(item["id"]) == str(id):
                print(f"Found matching item: {item['cve_id']} with ID {item['id']}")
                return item.get("code_before_change","")
        return f"No data found for CWE ID: {cwe_id}"
     
def query_clean_code(cve_id, cwe_id, id, path):
    def safe_first(lst):
        return lst[0] if isinstance(lst, list) and len(lst) > 0 else ""

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)  
        for item in data:
            cwe = safe_first(item.get("cwe", []))
            cve = item.get("cve_id")
            pid = item.get("id")
            if (
                str(cwe) == str(cwe_id) and
                str(cve) == str(cve_id) and
                str(pid) == str(id)
            ):
                print(f"Found matching item: {cve} with ID {pid}")
                return item.get("code_before_change", "")
        
        return f"No data found for CWE ID: {cwe_id}, CVE ID: {cve_id}, ID: {id}"

def query_llm(target_item, candidate):
    prompt = gen_analyze_prompt_CWE(target_item, candidate)
    # print(f"Prompt:\n{prompt}")
    query_message = gen_message(prompt, MODEL_DS_CHAT)
    return query_message

def append_json_list(output_path, new_items, default=None, flush_interval=100):
    if os.path.exists(output_path):
        with open(output_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    if isinstance(new_items, list):
        data.extend(new_items)
    else:
        data.append(new_items)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4, default=default)
        if len(new_items) % flush_interval == 0:
            f.flush()   # flush buffer 

def batch_match(top_l = 80, top_m = 200, top_n = 5, alpha=0.6, w_purpose=0.6, w_function=0.4, k=60):
    '''
    top_l:     vec num
    top_m:     graph num
    top_n:     final num

    alpha:      vec db, vec weight
    1-alpha:    vec db, text weight
    w_purpose:  vec db, purpose weight
    w_function: vec db, function weight
    '''
    N = 0
    batch_dir = "uid_batches"
    # batch_dir = "clean_uid"     

    # start from batch N_start, index batch_idx
    N_start= 0
    batch_idx = 0

    skipped_uids = [] 

    for i in range(N):
        if i < N_start:
            continue

        uids = []
        file_path = os.path.join(batch_dir, f"{i}.txt")
        if not os.path.exists(file_path):
            print(f"file do not exist: {file_path}")
            continue
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
            uids.extend(lines)
        print(f"Reading: {file_path}, total {len(lines)} UID")

        for idx, uid in enumerate(uids):
            if i == N_start and idx < batch_idx:
                continue

            print(f"Processing UID: {uid}"+"==="*30)
            # 0.1 parse UID
            parts = uid.split('_')
            cve_id = parts[0]
            cwe_id = parts[1]
            project_id = parts[2]
            # 0.2 search information of target_item, attach code,cpg
            target_item = query_target_item(os.path.join(RESULT_SAVE_PATH, "merged_extraction.json"), cve_id, cwe_id, project_id) 
            # target_item = query_target_clean_item(os.path.join(RESULT_SAVE_PATH, "clean_all3800_extraction.json"), cve_id, cwe_id, project_id) 
            if target_item is None:
                print(f"Matched item unfound, skipping UID: {uid}")
                skipped_uids.append(uid)
                continue  

            target_item["code"] = query_code(cve_id, cwe_id, project_id, os.path.join(RAW_DATA_PATH, "PairVul/full-dataset/Linux_kernel_clean_data_top5_CWEs.json")) 
            # target_item["code"] = query_clean_code(cve_id, cwe_id, project_id, os.path.join(RESULT_SAVE_PATH, "clean_data.json")) 
            target_item["cpg"] = query_embeddings(os.path.join(RESULT_SAVE_PATH, "graph_embeddings.json"), cve_id, cwe_id, project_id)  

            if target_item:
                # 1. vec match
                print(f"Begin vec match" + "="*20)
                vec_results = vector_match_fuse(cwe_id, cve_id, project_id, target_item['purpose'], target_item['functions'], top_k=top_l, alpha=alpha, weights=(w_purpose, w_function))

                # 2. graph match
                print(f"Begin graph match" + "="*20)
                path = os.path.join(RESULT_SAVE_PATH, "graph_embeddings.json")
                embeddings,  meta = load_embeddings(path)
                # graph_results = graph_match_ged(uid, meta, k=top_m)
                graph_results = graph_match(embeddings, meta, target_item.get("cpg"), uid, k=top_m)
                
                # 3. fuse results
                print(f"Begin fuse results" + "="*20)
                fused_top_n = fuse_results(vec_results, graph_results, top_n=top_n, k=60)
                # fused_top_n =  graph_results

                # 4. query LLM
                print(f"Begin query LLM" + "="*20)

                yes_count = 0
                no_count = 0
                cwe_counter = collections.Counter()

                vulnerable_flag = False 
                for rank, candidate in enumerate(fused_top_n, start=1):
                    candidate["code"] = query_code(candidate["cve_id"], candidate["cwe_id"], candidate["project_id"], os.path.join(RAW_DATA_PATH, "PairVul/full-dataset/Linux_kernel_clean_data_top5_CWEs.json"))
                    candidate["rank"] = rank
                    # print(f"Candidate: {candidate}")
                    # print(json.dumps(candidate, indent=2, ensure_ascii=False, default=convert_numpy))
                    llm_answer = query_llm(target_item, candidate)
                    # if "YES" in llm_answer:
                    #     vulnerable_flag = True
                    #     matched_cwe = re.findall(r"CWE-\d+", llm_answer)
                    #     predicted_cwe = matched_cwe[0] if matched_cwe else "UNKNOWN"
                    #     target_item["candidate"] = candidate
                    #     break

                    # update
                    if "YES" in llm_answer.upper():
                        yes_count += 1
                        matched_cwes = re.findall(r"CWE-\d+", llm_answer)
                        cwe_counter.update(matched_cwes)
                    elif "NO" in llm_answer.upper():
                        no_count += 1
                
                if yes_count > 0 and len(cwe_counter) > 0:
                    most_common_cwe, freq = cwe_counter.most_common(1)[0]
                    print(f"\nDetection result: Vulnerable, most possible CWE: {most_common_cwe} (Frequency: {freq})")
                    target_item["predicted_cwe"] = most_common_cwe
                else:
                    print("\nDetection result: No obvious vulnerability detected.")
                    target_item["predicted_cwe"] = "NO"

                target_item["result"] = llm_answer
                # target_item["predicted_cwe"] = predicted_cwe
                output_path = os.path.join(RESULT_SAVE_PATH, "query05_results.json")
                append_json_list(output_path, target_item, default=convert_numpy)

            else:
                print(f"Matched item unfound: {uid}")

    if skipped_uids:
        with open(os.path.join(RESULT_SAVE_PATH, "skipped_uids.json"), 'w', encoding='utf-8') as f:
            json.dump(skipped_uids, f, indent=2, ensure_ascii=False)
        print(f"\nSkipping {len(skipped_uids)} UIDs, saved to skipped_uids.json")

if __name__ == "__main__":
    # fuse_all_test()
    batch_match()