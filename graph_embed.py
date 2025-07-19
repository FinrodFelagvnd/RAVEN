from pathlib import Path
import networkx as nx
from karateclub import Graph2Vec
from sklearn.metrics.pairwise import cosine_similarity

import numpy as np
import pickle, os
import re
import json
import csv
from datetime import datetime
from config import *

XML_PATH = Path("clean_batch_xml") 

def load_graphs(root_dir: Path):
    graphs = []
    uids = []

    for subdir in root_dir.iterdir():
        if subdir.is_dir():
            uid = subdir.name
            graphml_file = subdir / "export.xml"
            if graphml_file.exists():
                try:
                    G = nx.read_graphml(graphml_file)
                    graphs.append(G)
                    uids.append(uid)
                except Exception as e:
                    print(f"[-] Failed to read {graphml_file}: {e}")
            else:
                print(f"[!] File not found: {graphml_file}")

    return graphs, uids

def compute_graph_embeddings(graphs):
    """
    Graph2Vec graph embedding
    """
    model = Graph2Vec(dimensions=128, wl_iterations=2)
    model.fit(graphs)
    embeddings = model.get_embedding()

    # graph_embeddings = {uid: embedding for uid, embedding in zip(uids, embeddings)}
    return embeddings

def save_embeddings(embeddings, file_path):
    with open(file_path, 'wb') as f:
        pickle.dump(embeddings, f)
    print(f"Embeddings saved to {file_path}")

def parse_uid(uid):
    """
    Parse UID, obtain CVE ID, CWE, project ID and timestamp
    Sample UID: CVE-2020-36557_CWE-362_2766_20250511151953
    """
    parts = uid.split("_")
    if len(parts) != 4:
        raise ValueError(f"Invalid UID format: {uid}")

    cve_id = parts[0]
    cwe_id = parts[1]
    project_id = parts[2]
    timestamp = parts[3]
    timestamp_obj = datetime.strptime(timestamp, "%Y%m%d%H%M%S")

    return {
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "project_id": project_id,
        "timestamp": timestamp_obj,
    }
    
def embeddings_with_info(uids, embeddings):
    graph_embeddings = {}
    for uid, embedding in zip(uids, embeddings):
        parsed_info = parse_uid(uid)
        graph_embeddings[uid] = {
            "embedding": embedding,
            **parsed_info
        }
    return graph_embeddings

def save_to_json(graph_embeddings, file_path):
    with open(file_path, 'w') as f:
        json.dump(graph_embeddings, f, default=str, indent=2)

def relabel_graphs_preserve_original(graphs):
    relabeled_graphs = []
    for g in graphs:
        mapping = {old_id: new_id for new_id, old_id in enumerate(g.nodes())}
        g_relabel = nx.relabel_nodes(g, mapping)
        for old_id, new_id in mapping.items():
            g_relabel.nodes[new_id]['orig_id'] = old_id
        relabeled_graphs.append(g_relabel)
    return relabeled_graphs


def main():
    graphs, uids = load_graphs(XML_PATH)
    print(f"[+] Loaded {len(graphs)} graphs.")

    graphs = relabel_graphs_preserve_original(graphs)

    embeddings = compute_graph_embeddings(graphs)
    embeddings_info = embeddings_with_info(uids, embeddings)
    save_to_json(embeddings_info, os.path.join(RESULT_SAVE_PATH, "clean_graph_embeddings.json"))  

if __name__ == "__main__":
    main()
