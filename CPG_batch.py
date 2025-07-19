import json
import os
import uuid
import subprocess
import shutil
import pandas as pd
import re
import networkx as nx
from datetime import datetime
from pathlib import Path
from config import *

JOERN_PATH = r"D:/Code/ctf/joern-cli"
NEO4J_BIN = r"D:/disk/soft/neo4j/neo4j-community-5.12.0/bin/cypher-shell.bat"
NEO4J_IMPORT_DIR = Path(r"D:/disk/soft/neo4j/neo4j-community-5.12.0/import")
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "11111111"
EXPORT_ROOT = Path("clean_batch_cpg")
# DATASET_SUBPATH = "PairVul/full-dataset/Linux_kernel_clean_data_top5_CWEs.json"
# DATASET_PATH = os.path.join(RAW_DATA_PATH, DATASET_SUBPATH)
DATASET_PATH = os.path.join(RESULT_SAVE_PATH, "clean_data.json")
XML_PATH = Path("clean_batch_xml")

def save_code(code: str, output_dir: Path, tag: str):
    code_file = output_dir / f"{tag}.c"
    code_file.write_text(code, encoding="utf-8")
    return code_file

def run_joern_extract(code_file: Path, output_dir: Path, uid):
    cpg_path = output_dir / "cpg.bin"
    xml_export_dir = XML_PATH / f"{uid}"
    # export_dir.mkdir(exist_ok=True)

    print(f"[+] Running Joern on {code_file.name}..." + "==="*20)
    subprocess.run([os.path.join(JOERN_PATH, "joern-parse.bat"), str(code_file), "--output", cpg_path], check=True)
    print(f"[+] Exporting CPG to Neo4j CSV format..." + "==="*20)
    # neo4jcsv      graphml     graphson     dot
    subprocess.run([os.path.join(JOERN_PATH, "joern-export.bat"), "--repr", "all", "--format", "graphml", "--out", str(xml_export_dir)], check=True)

    # return xml_export_dir

def copy_csv_to_import(export_dir: Path):
    for f in NEO4J_IMPORT_DIR.glob("*.csv"):
        f.unlink()
    for f in export_dir.glob("*.csv"):
        shutil.copy(f, NEO4J_IMPORT_DIR / f.name)

def import_to_neo4j():
    csv_files = list(NEO4J_IMPORT_DIR.glob("*_cypher.csv"))
    for file in sorted(csv_files, key=lambda x: x.name):
        print(f"[+] Importing: {file.name}" + "==="*20)   
        subprocess.run(
            [NEO4J_BIN, "-u", NEO4J_USER, "-p", NEO4J_PASSWORD, "--file", str(file)],
            check=True
        )

def add_graph_id2csv(export_dir, graph_id):
    for csv_file in export_dir.glob("*.csv"):
        df = pd.read_csv(csv_file)
        df["graph_id"] = graph_id
        df.to_csv(csv_file, index=False)

def inject_graph_id2cypher(cypher_file: Path, graph_id: str):
    print(f"[+] Injecting graph_id into {cypher_file.name}..." + "==="*20)
    lines = cypher_file.read_text(encoding="utf-8").splitlines()
    new_lines = []
    for line in lines:
        if line.strip().startswith("CREATE") or line.strip().startswith("MERGE"):
            if "{" in line and "}" in line:
                prefix, props = line.split("{", 1)
                props = props.rstrip("}")
                if "graph_id:" not in props:
                    props += f", graph_id: '{graph_id}'"
                new_line = prefix + "{" + props + "})"
                new_lines.append(new_line)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    cypher_file.write_text("\n".join(new_lines), encoding="utf-8")

def add_graph_id(export_dir: Path, graph_id: str):
    for csv_file in export_dir.glob("*_data.csv"):
        df = pd.read_csv(csv_file, header=None) 
        df["graph_id"] = graph_id  
        df.to_csv(csv_file, header=False, index=False)  

        header_file = csv_file.with_name(csv_file.name.replace("_data.csv", "_header.csv"))
        if header_file.exists():
            with open(header_file, "r", encoding="utf-8") as f:
                header_line = f.readline().strip()
            if "graph_id" not in header_line:
                parts = header_line.split(",")
                parts.append(":graph_id")
                with open(header_file, "w", encoding="utf-8") as f:
                    f.write(",".join(parts))

        cypher_file = csv_file.with_name(csv_file.name.replace("_data.csv", "_cypher.csv"))
        if cypher_file.exists():
            with open(cypher_file, "r", encoding="utf-8") as f:
                cypher_content = f.read()

            if "node" in csv_file.name.lower():
                pattern = re.compile(r"(CREATE\s*\(.*?\{)(.*?)(\}\);)", re.DOTALL)

                def insert_props_node(match):
                    start, props, end = match.group(1), match.group(2).rstrip(), match.group(3)
                    new_props = f"{props},\ngraph_id: '{graph_id}'\n"
                    return f"{start}{new_props}{end}"

                cypher_content = pattern.sub(insert_props_node, cypher_content)

            elif "edge" in csv_file.name.lower():
                cypher_content = re.sub(
                    r"(\{.*?)(\})",
                    rf"\1, graph_id: '{graph_id}'\2",
                    cypher_content,
                    flags=re.DOTALL
                )

            with open(cypher_file, "w", encoding="utf-8") as f:
                f.writelines(cypher_content)

def process_dataset():
    EXPORT_ROOT.mkdir(exist_ok=True)
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    start_idx = 0
    idx = 0
    for cwe, items in data.items():   
        for entry in items:
            idx += 1
            if idx < start_idx:
                continue
            
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")  
            uid = f"{entry['cve_id']}_{cwe}_{entry['id']}_{timestamp}"
            case_dir = EXPORT_ROOT / uid
            case_dir.mkdir(exist_ok=True)

            before_file = save_code(entry["code_before_change"], case_dir, entry['cve_id'])

            print(f"[+] Processing: {uid}" + "==="*30)

            run_joern_extract(before_file, case_dir, uid)  

            # add_graph_id(export_dir, uid)
            # for cypher_file in export_dir.glob("*_cypher.csv"):
            #     inject_graph_id2cypher(cypher_file, uid)

            # copy_csv_to_import(export_dir)
            # import_to_neo4j()

def process_clean_dataset():
    EXPORT_ROOT.mkdir(exist_ok=True)
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    start_idx = 984
    idx = 0

    for entry in data:
        cve_id = entry.get("cve_id", "unknown")
        cwe_list = entry.get("cwe", ["Unknown"])
        entry_id = entry.get("id", 0)
        code_before = entry.get("code_before_change", "")

        for cwe in cwe_list:
            idx += 1
            if idx < start_idx:
                continue

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            uid = f"{cve_id}_{cwe}_{entry_id}_{timestamp}"
            case_dir = EXPORT_ROOT / uid
            case_dir.mkdir(exist_ok=True)

            before_file = save_code(code_before, case_dir, cve_id)

            print(f"[+] Processing: {uid}" + "===" * 30)
            run_joern_extract(before_file, case_dir, uid)  

def load_graphs_from_dir(graphml_dir: Path):
    graphs = []
    graph_names = []
    for file in graphml_dir.glob("*.xml"):
        G = nx.read_graphml(file)
        graphs.append(G)
        graph_names.append(file.stem)
    return graphs, graph_names

if __name__ == "__main__":
    process_clean_dataset()
