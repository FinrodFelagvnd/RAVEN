import json
import os
from tqdm import tqdm
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
from typing import List, Dict
import re
from config import *

def load_json(json_path: str) -> List[Dict]:
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

def build_faiss_index(embeddings, dim):
    index = faiss.IndexFlatIP(dim) 
    index.add(embeddings)
    return index

def build_faiss_index_L2(embeddings, dim):
    faiss.normalize_L2(embeddings)  # normalize into unit vector
    index = faiss.IndexFlatIP(dim)  # Inner Product ≈ Cosine
    index.add(embeddings)
    return index

def clean_text(text):
    if not text:
        return ""
    text = re.sub(r'^(code purpose|vulnerability cause|functions):\s*', '', text, flags=re.IGNORECASE)

    text = re.sub(r'\s+', ' ', text)
    return text.strip()

def main():  
    model = SentenceTransformer(EMBEDDING_MODEL) 

    json_path = os.path.join(RESULT_SAVE_PATH, "merged_extraction.json")
    entries = load_json(json_path)

    purpose_texts = []
    vulncause_texts = []
    functions_texts = []

    metadata = []

    for item in tqdm(entries):
        purpose = clean_text(item.get('purpose', ''))
        cause = clean_text(item.get('vulnerability_cause', ''))
        functions = clean_text(item.get('functions', ''))
        # print(f"Purpose: {purpose}")
        # print(f"Vulnerability Cause: {cause}")
        # print(f"Functions: {functions}")
        # print("===" * 20)        
        purpose_texts.append(purpose)
        vulncause_texts.append(cause)
        functions_texts.append(functions)

        metadata.append({
            'Purpose': purpose,
            'Vulnerability Cause': cause,
            'Functions': functions,
            'Full Item': item  
        })

    purpose_embeddings = model.encode(purpose_texts, show_progress_bar=True, normalize_embeddings=True)
    vulncause_embeddings = model.encode(vulncause_texts, show_progress_bar=True, normalize_embeddings=True)
    functions_embeddings = model.encode(functions_texts, show_progress_bar=True, normalize_embeddings=True)

    purpose_index = build_faiss_index(purpose_embeddings, purpose_embeddings.shape[1])
    vulncause_index = build_faiss_index(vulncause_embeddings, vulncause_embeddings.shape[1])
    functions_index = build_faiss_index(functions_embeddings, functions_embeddings.shape[1])

    purpose_path = os.path.join(RESULT_SAVE_PATH, "purpose.index")
    vulncause_path = os.path.join(RESULT_SAVE_PATH, "vulncause.index")
    functions_path = os.path.join(RESULT_SAVE_PATH, "functions.index")
    faiss.write_index(purpose_index, purpose_path)
    faiss.write_index(vulncause_index, vulncause_path)
    faiss.write_index(functions_index, functions_path)

    output_json_path = os.path.join(RESULT_SAVE_PATH, "embed_metadata.json")
    with open(output_json_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

    print("Embedding completed successfully!")

if __name__ == "__main__":
    main()