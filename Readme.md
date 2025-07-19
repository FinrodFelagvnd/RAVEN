## RAVEN: Retrieval Augmented Vulnerability Detection via Multimodal Knowledge Base

Code dependencies are located `requirments.txt`

The file structure is as follows:

```
│  abla_topN.py             Top-N candidate fusion graph generating
│  config.py                system config
│  CPG_batch.py             Use Joern outputs graphml
│  embed.py                 Embed semantic vectors and save as .index
│  GNNFilm.py               Graph match training (Discarded)
│  graph_embed.py           Graph embedding, save with metadata to .json
│  graph_match.py           Graph match, including vector, and GED (Discarded)
│  json_count.py            
│  json_extract_clean.py    negative sample extraction
│  json_merge.py            
│  knowledge_extractor.py   3D semantics extraction
│  match-all.py             RAVEN core entry
│  metric_count.py          
│  prompt.py                
│  requirements.txt
│  select_sample.py         epoch=10，extratc id and save to .txt
│  tree.txt
│  vector_match.py          semantic match
│  
```



To reproduce the work of the our paper, please follow the steps below:

### 0. Multimodal Knowledge Base Construction

Configure vulnerability dataset path `RAW_DATA_PATH` and outputting path `RESULT_SAVE_PATH` in  `config.py` 

#### 0.1 Semantic Base Construction

Configure `OPENAI_API_KEY` and corresponding model in `config.py` 

Running `knowledge_extractor.py` to query LLM to extracting semantic information and save, use  `start_idx` to choose the start batch

Running `embed.py` to embed into vectors

The construction of text corpus are conducted in the following steps

#### 0.2 Knowledge Graph Construction

Configure Joren path in `CPG_batch.py` 

Running  `CPG_batch.py` to extract CPG，and save as .graphml

Running `graph_embed.py` to embed graphs



### 1. Vulnerability Detection

Running `select_sample.py` to divide the batches by ID and save to .txt

Running  `match-all.py` to conduct vulnerability detection. The core funtion is `batch_match()` ，allowing configure `batch_dir` and starting place. Specifically:

#### 1.1 Semantic Matching

Calling funtion `vector_match_fuse()` in `vector_match.py`, return Top-L semantic candidates

#### 1.2 Garph Matching

Calling function `graph_match()` in `graph_match.py`, return Top-M graph candidates

#### 1.3 Fuse Matching Results

Calling funtion `fuse_results()` in `match-all.py`, fuse matching results 

#### 1.4 Query LLM

Calling function `query_LLM()` in `match-all.py`, querying LLM and output detection results

Designed prompts are in `prompt.py`

All detection results will be output to `RESULT_SAVE_PATH`,  `metric_count.py` can be used to summarize detection statistics