## RAVEN: Retrieval Augmented Vulnerability Detection via Multimodal Knowledge Base

All required dependencies are listed in `requirements.txt`.

To reproduce the results of our paper, please follow the steps below:

### 0. Multimodal Knowledge Base Construction
Set the paths to the raw vulnerability dataset and output directory by configuring `RAW_DATA_PATH` and `RESULT_SAVE_PATH` in `config.py`.

#### 0.1 Semantic Knowledge Base
Configure your `OPENAI_API_KEY` and selected model in `config.py`.

Run `knowledge_extractor.py` to extract semantic information using an LLM. Use the `start_idx` argument to specify the starting batch index.

Run `embed.py` to convert the extracted text into embedding vectors.

<!-- These steps build the text-based corpus for the semantic knowledge base. -->

#### 0.2 Knowledge Graph Construction
Configure the path to Joern in `CPG_batch.py`.

Run `CPG_batch.py` to extract Code Property Graphs (CPGs) and export them as `.graphml` files.

Run `graph_embed.py` to embed the extracted graphs into vector representations.

### 1. Vulnerability Detection
Run `select_sample.py` to divide the data into batches based on IDs and save them into `.txt` files.

Run `match-all.py` to perform the vulnerability detection pipeline. The core function is `batch_match()`, where you can configure `batch_dir` and the starting index.

The detection process consists of the following stages:

#### 1.1 Semantic Matching
Calls the function `vector_match_fuse()` in `vector_match.py` to retrieve the Top-L semantic candidates.

#### 1.2 Graph Matching
Calls the function `graph_match()` in `graph_match.py` to retrieve the Top-M graph-based candidates.

#### 1.3 Fuse Matching Results
Calls the function `fuse_results()` in `match-all.py` to fuse semantic and graph-based candidates.

#### 1.4 LLM-based Vulnerability Detection
Calls the function `query_LLM()` in `match-all.py` to query the LLM with the fused results for final vulnerability judgment.

Prompt templates used for querying the LLM are defined in `prompt.py`.


### 2. Output and Evaluation
All final detection results will be saved in the path specified by `RESULT_SAVE_PATH`.

You can run `metric_count.py` to compute and summarize the detection metrics.

### 3. Additional Notes
The project's directory structure is summarized in `tree.txt`.

Intermediate files, such as `.c`, `.bin`, and `.graphml` for both positive and negative samples, are stored in the corresponding subdirectories for reproducibility.

The detailed information is provided below.

```
│  abla_topN.py             Visualize Top-N candidate fusion results
│  config.py                System config
│  CPG_batch.py             Leverage Joern to extract CPGs as .graphml files
│  embed.py                 Embed semantic vectors and save as .index files
│  GNNFilm.py               Graph match training (Discarded)
│  graph_embed.py           Graph embedding, save with metadata to .json
│  graph_match.py           Graph matching, including vector, and GED (Discarded)
│  json_count.py            
│  json_extract_clean.py    Negative sample extraction
│  json_merge.py            
│  knowledge_extractor.py   3D semantics extraction
│  match-all.py             RAVEN core entry
│  metric_count.py          
│  prompt.py     
│  Readme.md           
│  requirements.txt
│  select_sample.py         Extract IDs at epoch 10 and save them to a .txt file
│  tree.txt
│  vector_match.py          Semantic match
│  
├─cpg_export                Results and intermediate files during CPG extraction
│  ├─neg_cpg                Intermediate .c and .bin files for negative samples    
│  ├─neg_xml                .graphml files of CPGs for negative samples
│  ├─pos_cpg          
│  └─pos_xml
│              
├─multimodel_base           Extracted multimodel knowledge base
│      embed_metadata.json          Graph embeddings with corresponding metadata
│      functions.index              "Function relationship" embedded data 
│      neg_code.json                Original code for negative samples
│      neg_extraction.json          Extracted 3D information for negative samples
│      neg_graph_embeddings.json    Embeddings of CPGs for negative samples
│      pos_code.json
│      pos_extraction.json
│      pos_graph_embeddings.json
│      purpose.index                "Code purpose" embedded data
│      vulncause.index              "Vulnerability cause" embedded data
│      
└─outputs                   Results for experiments
    │  ablation_topn_line_chart.html    Visualized resulted for ablation of Top-N (Section 5.4.3)
    │  es_results.json                  Ablation results at "early stopping" strategy (Section 5.4.2)
    │  neg_graph_only.json              Ablation results with only knowledge graph for negative samples (Section 5.4.1)
    │  neg_result.json                  Results for negative samples (Section 5.2)
    │  neg_vec_only.json                Ablation results with only multimodal base for negative samples (Section 5.4.1)
    │  pos_graph_only.json
    │  pos_results.json
    │  pos_vec_only.json
    │  
    └─abla-topN                         Abaltion results at different settings of Top-N
            query05_results.json
            query10_results.json
            query15_results.json
            query20_results.json
            query25_results.json
            query30_results.json
```