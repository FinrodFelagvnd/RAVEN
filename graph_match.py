import json
import numpy as np
import faiss
import os
from config import RESULT_SAVE_PATH
from pathlib import Path
from sklearn.metrics.pairwise import cosine_similarity
from networkx.algorithms.similarity import graph_edit_distance

from graph_embed import load_graphs

def load_embeddings(json_path):
    """
    Load embeddings from JSON file
    """
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    embeddings = {}
    meta = []

    for key, value in data.items():
        emb_str = value["embedding"]
        emb = np.fromstring(emb_str.strip("[]").replace("\n", " "), sep=" ")
        embeddings[key] = emb.astype(np.float32)
        meta.append({
            "key": key,
            "cve_id": value["cve_id"],
            "cwe_id": value["cwe_id"],
            "project_id": value["project_id"],
            "timestamp": value["timestamp"]
        })

    return embeddings, meta

def build_faiss_index(embeddings):
    dim = embeddings.shape[1]
    index = faiss.IndexFlatL2(dim)
    index.add(embeddings)
    return index

def search_graphs(query_vector, index, meta, top_k=5):
    query_vector = np.array(query_vector, dtype=np.float32).reshape(1, -1)
    D, I = index.search(query_vector, top_k)
    results = []
    for i, score in zip(I[0], D[0]):
        item = meta[i].copy()
        item["score"] = float(score)
        results.append(item)
    return results


def compute_similarity(embedding_a, embedding_b):
    return cosine_similarity([embedding_a], [embedding_b])[0][0]

def graph_match_with_uid(embeddings, target_uid, k=5):
    target_vec = embeddings[target_uid]
    similarities = []

    for uid, vec in embeddings.items():
        if uid == target_uid:
            continue
        sim = compute_similarity(target_vec, vec)
        similarities.append((uid, sim))

    similarities.sort(key=lambda x: x[1], reverse=True)
    return similarities[:k]

def graph_match(embeddings, meta, target_embed, target_uid, k=5):
    similarities = []

    for uid, vec in embeddings.items():
        if uid == target_uid:
            continue
        sim = compute_similarity(target_embed, vec)
        similarities.append((uid, sim))

    similarities.sort(key=lambda x: x[1], reverse=True)

    results = []
    meta_map = {m["key"]: m for m in meta}

    for uid, sim in similarities[:k]:
        info = meta_map.get(uid, {})
        result_item = {
            "uid": uid,
            "cwe_id": info.get("cwe_id", ""),
            "cve_id": info.get("cve_id", ""),
            "project_id": info.get("project_id", ""),
            "graph_score": sim,
            "graph_embedding": embeddings[uid].tolist(),
            # "timestamp": info.get("timestamp", "")
        }
        results.append(result_item)

    # GED
    # results = graph_finematch_ged(target_uid, results, k=k, timeout=2)

    return results

# Discarded function, kept for reference
def graph_finematch_ged(target_uid, embed_results, k=5, timeout=30):
    """
    Graph Edit Distance fine-matching.

    Parameters:
        - target_uid: str, the unique identifier of the target graph.
        - embed_results: List[dict], the graph information obtained from the initial vector matching.
        - k: int, the number of most similar graphs to return.
        - timeout: float, the maximum time (in seconds) for a single GED match.

    Returns:
        - List[dict], the results sorted by GED similarity.
    """
    all_graphs, uids = load_graphs(Path("batch_xml_export"))

    uid_to_graph = dict(zip(uids, all_graphs))

    if target_uid not in uid_to_graph:
        raise ValueError(f"Target UID {target_uid} not found in loaded graphs.")

    target_graph = uid_to_graph[target_uid]

    similarities = []
    i = 0

    for item in embed_results:
        uid = item.get("uid") #or item.get("project_id")
        if uid not in uid_to_graph:
            print(f"Graph for UID {uid} not found, skipping.")
            continue

        g = uid_to_graph[uid]
        try:
            print(f"Computing GED for {uid} ({i+1}/{len(embed_results)})")
            ged = graph_edit_distance(target_graph, g, timeout=timeout)
            if ged is None:
                continue
            score = 1 / (1 + ged)  
            similarities.append((uid, score))
        except Exception as e:
            print(f"Failed to compute GED for {uid}: {e}")
        i += 1

    similarities.sort(key=lambda x: x[1], reverse=True)
    top_matches = similarities[:k]

    new_results = []
    sim_map = dict(top_matches)

    for item in embed_results:
        uid = item.get("uid") #or item.get("project_id")
        if uid in sim_map:
            new_item = item.copy()
            new_item["graph_ged_score"] = float(sim_map[uid])
            new_item["uid"] = uid
            new_results.append(new_item)

    # new_results.sort(key=lambda x: x["graph_score"], reverse=True)
    return new_results


def compute_graph_edit_distance(G1, G2, timeout=5):
    def node_match(n1, n2):
        return n1.get('labelV') == n2.get('labelV')
    
    def edge_match(e1, e2):
        return e1.get('labelE') == e2.get('labelE')
    
    return graph_edit_distance(G1, G2, timeout=timeout, node_match=node_match, edge_match=edge_match)

# Discarded
def graph_match_ged(target_uid, meta, k=5, timeout=30): 
    """
    Graph Edit Distance

    Parameters:
        - target_graph: networkx.Graph, the target graph.
        - all_graphs: dict, keys are uid and values are networkx.Graph.
        - meta: list, contains metadata for each graph.
        - k: int, the number of most similar graphs to return.
        - timeout: float, the maximum time (in seconds) for a single GED match.

    Returns:
        - List[dict], the matching results.
    """
    all_graphs, uids = load_graphs(Path("batch_xml_export"))
    uid_to_graph = dict(zip(uids, all_graphs))
    if target_uid not in uid_to_graph:
        raise ValueError(f"Target UID {target_uid} not found in loaded graphs.")
    target_graph = uid_to_graph[target_uid]
    # index = uids.index(target_uid)
    # target_graph = all_graphs[index]
    # uids.pop(index)
    # all_graphs.pop(index) 

    meta_map = {m["key"]: m for m in meta}
    similarities = []
    i = 0

    for uid, g in zip(uids, all_graphs):
        try:
            print(f"Computing GED for {uid} ({i}/{len(uids)})")
            # print(f"--- {uid} ---")
            # print("Nodes:", g.nodes(data=True))
            # print("Edges:", g.edges(data=True))
            # print("Target nodes:", target_graph.nodes(data=True))
            # print("Target edges:", target_graph.edges(data=True))
            # print("Compare nodes:", g.nodes(data=True))
            # print("Compare edges:", g.edges(data=True))

            i += 1
            ged = graph_edit_distance(target_graph, g, timeout=timeout)  #  timeout=timeout
            if ged is None:
                continue  
            score = 1 / (1 + ged)
            similarities.append((uid, score))
        except Exception as e:
            print(f"Failed to compute GED for {uid}: {e}")
            continue

    similarities.sort(key=lambda x: x[1], reverse=True)
    top_matches = similarities[:k]

    results = []
    for uid, sim in top_matches:
        info = meta_map.get(uid, {})
        results.append({
            "cwe_id": info.get("cwe_id", ""),
            "cve_id": info.get("cve_id", ""),
            "project_id": info.get("project_id", ""),
            "graph_score": float(sim),  
            "timestamp": info.get("timestamp", ""),
            "uid": uid
        })

    return results

def main():
    path = os.path.join(RESULT_SAVE_PATH, "graph_embeddings.json")
    embeddings,  meta = load_embeddings(path)
    target_uid = "CVE-2006-3635_CWE-119_1_20250511142120"
    top_k = graph_match_with_uid(embeddings, target_uid, k=15)

    print(f"[+] Top 5 similar graphs to: {target_uid}")
    for uid, sim in top_k:
        print(f"UID: {uid} | Similarity: {sim:.4f}")

def test():
    embeddings, meta = load_embeddings(os.path.join(RESULT_SAVE_PATH, "graph_embeddings.json"))
    index = build_faiss_index(embeddings)

    query_vec = np.random.rand(128).astype(np.float32)  

    results = search_graphs(query_vec, index, meta, top_k=5)

    for i, r in enumerate(results):
        print(f"Top-{i+1}: {r['key']} | Score: {r['score']:.4f} | CVE: {r['cve_id']} | CWE: {r['cwe_id']}")

if __name__ == "__main__":
    main()
