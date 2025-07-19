# Discarded

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import MessagePassing, global_mean_pool
from torch_geometric.data import Data, DataLoader

from xml.etree import ElementTree as ET
from pathlib import Path
import networkx as nx

from torch_geometric.data import InMemoryDataset
import os
from tqdm import tqdm

# -- FiLM layer --
class FiLMConv(MessagePassing):
    def __init__(self, in_channels, out_channels):
        super(FiLMConv, self).__init__(aggr='add')
        self.linear = nn.Linear(in_channels, out_channels)
        self.gamma = nn.Linear(in_channels, out_channels)
        self.beta = nn.Linear(in_channels, out_channels)

    def forward(self, x, edge_index):
        # Compute FiLM parameters
        gamma = self.gamma(x)
        beta = self.beta(x)

        # Apply linear transformation
        x = self.linear(x)
        out = self.propagate(edge_index, x=x)

        # Apply FiLM modulation
        return gamma * out + beta

    def message(self, x_j):
        return x_j


# -- GNNFiLM embedding model --
class GNNFiLM(nn.Module):
    def __init__(self, in_channels, hidden_channels, out_channels, num_layers=3):
        super(GNNFiLM, self).__init__()
        self.convs = nn.ModuleList()
        self.convs.append(FiLMConv(in_channels, hidden_channels))

        for _ in range(num_layers - 2):
            self.convs.append(FiLMConv(hidden_channels, hidden_channels))

        self.convs.append(FiLMConv(hidden_channels, out_channels))

    def forward(self, x, edge_index, batch):
        for conv in self.convs:
            x = F.relu(conv(x, edge_index))
        # Graph-level embedding
        return global_mean_pool(x, batch)

def generate_dummy_graph(num_graphs=10, num_nodes=20, in_dim=10):
    graphs = []
    for _ in range(num_graphs):
        x = torch.randn(num_nodes, in_dim)
        edge_index = torch.randint(0, num_nodes, (2, num_nodes * 2)) 
        data = Data(x=x, edge_index=edge_index)
        graphs.append(data)
    return graphs

class CPGDataset(InMemoryDataset):
    def __init__(self, root_dir):
        super(CPGDataset, self).__init__()
        self.data_list = []
        for fname in tqdm(os.listdir(root_dir)):
            if not fname.endswith(".xml"):
                continue
            data = parse_cpg_graphml(os.path.join(root_dir, fname))
            data.y = torch.tensor([0])  
            self.data_list.append(data)

    def len(self):
        return len(self.data_list)

    def get(self, idx):
        return self.data_list[idx]

def parse_cpg_graphml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    ns = {'graphml': 'http://graphml.graphdrawing.org/xmlns'}
    G = nx.DiGraph()

    # 解析节点及其属性
    for node in root.findall(".//graphml:node", ns):
        node_id = node.attrib["id"]
        data_tags = node.findall("graphml:data", ns)
        node_attrs = {}
        for data in data_tags:
            key = data.attrib.get("key")
            text = data.text.strip() if data.text else ""
            node_attrs[key] = text
        G.add_node(node_id, **node_attrs)

    for edge in root.findall(".//graphml:edge", ns):
        source = edge.attrib["source"]
        target = edge.attrib["target"]
        data_tags = edge.findall("graphml:data", ns)
        edge_attrs = {}
        for data in data_tags:
            key = data.attrib.get("key")
            text = data.text.strip() if data.text else ""
            edge_attrs[key] = text
        G.add_edge(source, target, **edge_attrs)

    return G

if __name__ == "__main__":
    dataset = generate_dummy_graph(num_graphs=100, num_nodes=30, in_dim=10)
    loader = DataLoader(dataset, batch_size=8, shuffle=True)

    model = GNNFiLM(in_channels=10, hidden_channels=64, out_channels=128)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)

    for epoch in range(10):
        for batch in loader:
            optimizer.zero_grad()
            batch.to('cpu')  
            out = model(batch.x, batch.edge_index, batch.batch)
            loss = F.mse_loss(out, torch.zeros_like(out)) 
            loss.backward()
            optimizer.step()

        print(f"Epoch {epoch}: loss = {loss.item():.4f}")