import json
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
from config import *
import os
from sklearn.preprocessing import MinMaxScaler

from rank_bm25 import BM25Okapi
import nltk
from nltk.tokenize import word_tokenize

nltk.download("punkt")
nltk.download('punkt_tab')
model = SentenceTransformer(EMBEDDING_MODEL)

metadata_json_path = os.path.join(RESULT_SAVE_PATH, "embed_metadata.json")
purpose_index = faiss.read_index(os.path.join(RESULT_SAVE_PATH, "purpose.index"))
vulncause_index = faiss.read_index(os.path.join(RESULT_SAVE_PATH, "vulncause.index") )
functions_index = faiss.read_index(os.path.join(RESULT_SAVE_PATH, "functions.index"))

with open(metadata_json_path, 'r', encoding='utf-8') as f:
    metadata = json.load(f)

# BM25 indexing
purpose_corpus = [item["Purpose"] for item in metadata]
functions_corpus = [item["Functions"] for item in metadata]
tokenized_purpose = [word_tokenize(doc.lower()) for doc in purpose_corpus]
tokenized_functions = [word_tokenize(doc.lower()) for doc in functions_corpus]
bm25_purpose = BM25Okapi(tokenized_purpose)
bm25_functions = BM25Okapi(tokenized_functions)

# vector search
def search(query_text, index, top_k=5):
    query_embedding = model.encode([query_text], normalize_embeddings=True)
    D, I = index.search(query_embedding, top_k)
    return D[0], I[0]
def BM25_search(query_text, bm25_index, top_k=5):
    query_tokens = word_tokenize(query_text.lower()) 
    scores = bm25_index.get_scores(query_tokens)
    # Maximum value normalization
    max_score = np.max(scores)
    if max_score > 0:
        scores = scores / max_score
    else:
        scores = np.zeros_like(scores)

    top_indices = np.argsort(scores)[::-1][:top_k]
    top_scores = [scores[i] for i in top_indices]
    return top_scores, top_indices

def min_max_normalize(scores):
    # Normalize scores to [0, 1]
    scaler = MinMaxScaler(feature_range=(0, 1))
    scores = np.array(scores).reshape(-1, 1)
    normalized_scores = scaler.fit_transform(scores)
    return normalized_scores.flatten()

def vector_match_fuse(target_cwe, target_cve, target_id, purpose, functions, top_k=5, alpha=0.6, weights=(0.6, 0.4)):
    """
    alpha: 向量 权重
    weights:  purpose 和 functions 权重(分别含向量和文本)
    """
    # vector matching
    purpose_result_vec = search(purpose, purpose_index, top_k=top_k*2)
    functions_result_vec = search(functions, functions_index, top_k=top_k*2)
    # BM25 text matching
    purpose_result_bm25 = BM25_search(purpose, bm25_purpose, top_k=top_k*2)
    functions_result_bm25 = BM25_search(functions, bm25_functions, top_k=top_k*2)

    # Min-Max normalization
    # purpose_result_vec_scores = min_max_normalize(purpose_result_vec[0])
    # functions_result_vec_scores = min_max_normalize(functions_result_vec[0])
    # purpose_result_bm25_scores = min_max_normalize(purpose_result_bm25[0])
    # functions_result_bm25_scores = min_max_normalize(functions_result_bm25[0])

    combined_scores = {}
    # fuse matching scores
    for (vec_scores, vec_idxs, bm_scores, bm_idxs, weight) in [
        # (purpose_result_vec_scores, purpose_result_vec[1], purpose_result_bm25_scores, purpose_result_bm25[1], weights[0]),
        # (functions_result_vec_scores, functions_result_vec[1], functions_result_bm25_scores, functions_result_bm25[1], weights[1])
        (purpose_result_vec[0], purpose_result_vec[1], purpose_result_bm25[0], purpose_result_bm25[1], weights[0]),
        (functions_result_vec[0], functions_result_vec[1], functions_result_bm25[0], functions_result_bm25[1], weights[1])
    ]:
        for score, idx in zip(vec_scores, vec_idxs):
            combined_scores[idx] = combined_scores.get(idx, 0) + weight * alpha * score
        for score, idx in zip(bm_scores, bm_idxs):
            combined_scores[idx] = combined_scores.get(idx, 0) + weight * (1 - alpha) * score

    sorted_items = sorted(combined_scores.items(), key=lambda x: x[1], reverse=True)

    top_k_results = []
    collected = 0
    i = 0
    
    while collected < top_k and i < len(sorted_items):
    # for i, (idx, total_score) in enumerate(sorted_items[:top_k]):
        idx, total_score = sorted_items[i]
        i += 1

        # exclude the target itself
        cwe = metadata[idx].get('Full Item', {}).get('cwe', 'N/A')
        cve = metadata[idx].get('Full Item', {}).get('cve', 'N/A')
        project_id = metadata[idx].get('Full Item', {}).get('id', 'N/A')
        if cwe == target_cwe and cve == target_cve and project_id == target_id:
            continue

        item = metadata[idx]

        # Safely get sub-scores (default to 0 if not in candidate list)
        def safe_score(score_list, idx_list, target_idx):
            try:
                return score_list[idx_list.tolist().index(target_idx)]
            except ValueError:
                return 0.0

        pv_score = safe_score(purpose_result_vec[0], purpose_result_vec[1], idx)
        pb_score = safe_score(purpose_result_bm25[0], purpose_result_bm25[1], idx)
        fv_score = safe_score(functions_result_vec[0], functions_result_vec[1], idx)
        fb_score = safe_score(functions_result_bm25[0], functions_result_bm25[1], idx)

        result = {
            # "uid": item["key"],
            "cwe_id": item.get('Full Item', {}).get('cwe', 'N/A'),
            "cve_id": item.get('Full Item', {}).get('cve', 'N/A'),
            "project_id": item.get('Full Item', {}).get('id', 'N/A'),
            "vector_score": total_score,
            # "timestamp": item["timestamp"],
            "purpose": item.get("Purpose", ""),
            "functions": item.get("Functions", ""),
            "vulnerability_cause": item.get("Vulnerability Cause", ""),
            "score_detail": {
                "purpose_vector": pv_score,
                "purpose_bm25": pb_score,
                "functions_vector": fv_score,
                "functions_bm25": fb_score
            }
        }

        top_k_results.append(result)
        collected += 1

    return top_k_results

    # output_path = "match_results.txt"
    # with open(output_path, "w", encoding="utf-8") as f:
    #     f.write(f" Match results Top-{top_k}:\n")

    #     for i, (idx, total_score) in enumerate(sorted_items):   # [:top_k]
    #         item = metadata[idx]

    #         # Safely get sub-scores (default to 0 if not in candidate list)
    #         def safe_score(score_list, idx_list, target_idx):
    #             try:
    #                 return score_list[idx_list.tolist().index(target_idx)]
    #             except ValueError:
    #                 return 0.0

    #         pv_score = safe_score(purpose_result_vec[0], purpose_result_vec[1], idx)
    #         pb_score = safe_score(purpose_result_bm25[0], purpose_result_bm25[1], idx)
    #         fv_score = safe_score(functions_result_vec[0], functions_result_vec[1], idx)
    #         fb_score = safe_score(functions_result_bm25[0], functions_result_bm25[1], idx)

    #         f.write(f"\n=== Rank {i+1} | Match Score: {total_score:.4f} ===\n")
    #         f.write(f"pv_score     : {pv_score:.4f}\n")
    #         f.write(f"pb_score     : {pb_score:.4f}\n")
    #         f.write(f"fv_score     : {fv_score:.4f}\n")
    #         f.write(f"fb_score     : {fb_score:.4f}\n")
    #         f.write(f"Purpose      : {item.get('Purpose', '')}\n")
    #         f.write(f"CWE          : {item.get('Full Item', {}).get('cwe', 'N/A')}\n")
    #         f.write(f"CVE          : {item.get('Full Item', {}).get('cve', 'N/A')}\n")

def test():
    sample = VECTOR_MATCH_SAMPLE2
    # vector_match_fuse(sample['Purpose'], sample['Vulnerability Cause'], sample['Functions'], top_k=10)
    vector_match_fuse(sample['purpose'], sample['functions'], top_k=10)

if __name__ == "__main__":
    test()