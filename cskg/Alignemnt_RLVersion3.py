# === IMPORTS ===
import torch
import torch.nn.functional as F
from torch import nn
import pandas as pd
import numpy as np
from torch_geometric.data import Data
from torch_geometric.nn import RGCNConv
from py2neo import Graph, NodeMatcher, Relationship
from sentence_transformers import SentenceTransformer, util
from sklearn.svm import SVC
import gym
from stable_baselines3 import PPO
import networkx as nx
import matplotlib.pyplot as plt

# === CONNEXION NEO4J ===
uri = "neo4j+s://1cb37128.databases.neo4j.io"
user = "neo4j"
password = "qUocbHeI6RTR3sqwFE6IhnAX5nk9N_KnQVFthB3E9S8"
graph = Graph(uri, auth=(user, password))
matcher = NodeMatcher(graph)

# === EXTRACTION DES TRIPLETS ===
query = """
MATCH (h)-[r]->(t)
WHERE h.name IS NOT NULL AND t.name IS NOT NULL
RETURN h.name AS head, type(r) AS relation, t.name AS tail
"""
triplets_df = pd.DataFrame(graph.run(query).data())
print(triplets_df.head())

# === ALIGNEMENT PAR FUZZY MATCHING ===
from fuzzywuzzy import fuzz

def align_cve_by_pattern(cve_nvd, cve_nessus):
    matches = []
    for cve1 in cve_nvd:
        for cve2 in cve_nessus:
            if fuzz.ratio(cve1['name'], cve2['name']) > 90:
                matches.append((cve1, cve2))
    return matches

# === ALIGNEMENT SÉMANTIQUE ===
model = SentenceTransformer('all-MiniLM-L6-v2')

def align_by_embeddings(cve_nvd, cve_nessus):
    emb_nvd = model.encode([c['description'] for c in cve_nvd])
    emb_nessus = model.encode([c['description'] for c in cve_nessus])
    return util.pytorch_cos_sim(emb_nvd, emb_nessus)

# === ROTATE MODEL ===
class RotatEModel(nn.Module):
    def __init__(self, num_entities, num_relations, embedding_dim=64):
        super().__init__()
        self.ent = nn.Embedding(num_entities, embedding_dim)
        self.rel = nn.Embedding(num_relations, embedding_dim)

    def forward(self, h_idx, r_idx, t_idx):
        pi = 3.141592653589793
        h, r, t = self.ent(h_idx), self.rel(r_idx) * pi, self.ent(t_idx)
        r_c = torch.stack([torch.cos(r), torch.sin(r)], dim=-1)
        h_c = torch.stack([h, torch.zeros_like(h)], dim=-1)
        h_r = torch.stack([h_c[..., 0]*r_c[..., 0] - h_c[..., 1]*r_c[..., 1],
                           h_c[..., 0]*r_c[..., 1] + h_c[..., 1]*r_c[..., 0]], dim=-1)
        t_c = torch.stack([t, torch.zeros_like(t)], dim=-1)
        return -torch.norm(h_r - t_c, dim=-1).sum(dim=-1)

# === ENCODAGE DES ENTITÉS & RELATIONS ===
entities = pd.Series(pd.concat([triplets_df["head"], triplets_df["tail"]]).unique()).reset_index()
entity2id = dict(zip(entities[0], entities["index"]))
relations = pd.Series(triplets_df["relation"].unique()).reset_index()
rel2id = dict(zip(relations[0], relations["index"]))

h_idx = torch.tensor([entity2id[h] for h in triplets_df["head"]])
r_idx = torch.tensor([rel2id[r] for r in triplets_df["relation"]])
t_idx = torch.tensor([entity2id[t] for t in triplets_df["tail"]])

rotate = RotatEModel(len(entity2id), len(rel2id))
opt = torch.optim.Adam(rotate.parameters(), lr=0.01)

for epoch in range(3):
    rotate.train()
    opt.zero_grad()
    loss = -rotate(h_idx, r_idx, t_idx).mean()
    loss.backward()
    opt.step()
    if epoch % 10 == 0:
        print(f"[RotatE] Epoch {epoch} - Loss: {loss.item():.4f}")

# === GRAPHE POUR R-GCN ===
x = torch.randn(len(entity2id), 64)
edge_index = torch.tensor([
    [entity2id[h] for h in triplets_df["head"]],
    [entity2id[t] for t in triplets_df["tail"]]
], dtype=torch.long)
edge_type = torch.tensor([rel2id[r] for r in triplets_df["relation"]], dtype=torch.long)

data = Data(x=x, edge_index=edge_index, edge_type=edge_type, num_nodes=len(entity2id))
data.y = torch.randint(0, 2, (len(entity2id),))
train_mask = torch.rand(len(entity2id)) > 0.3

# === R-GCN ===
class RGCN(nn.Module):
    def __init__(self, in_feat, hidden_feat, out_feat, num_rels):
        super().__init__()
        self.conv1 = RGCNConv(in_feat, hidden_feat, num_rels)
        self.conv2 = RGCNConv(hidden_feat, out_feat, num_rels)

    def forward(self, data):
        x = F.relu(self.conv1(data.x, data.edge_index, data.edge_type))
        return self.conv2(x, data.edge_index, data.edge_type)

rgcn = RGCN(64, 32, 2, len(rel2id))
opt_rgcn = torch.optim.Adam(rgcn.parameters(), lr=0.01)

for epoch in range(2):
    rgcn.train()
    opt_rgcn.zero_grad()
    out = rgcn(data)
    loss = F.cross_entropy(out[train_mask], data.y[train_mask])
    loss.backward()
    opt_rgcn.step()
    print(f"[R-GCN] Epoch {epoch} - Loss: {loss.item():.4f}")

# === INJECTION NEO4J ===
def inject_vulnerable_property(entity2id, out, threshold=0.5):
    for entity, idx in entity2id.items():
        prob = torch.softmax(out[idx], dim=0)[1].item()
        node = matcher.match(name=entity).first()
        if node:
            node["vulnerable"] = prob > threshold
            graph.push(node)

rgcn.eval()
with torch.no_grad():
    inject_vulnerable_property(entity2id, rgcn(data))


# === SVM ===
# Simulation de X_train/y_train depuis les embeddings du modèle R-GCN
X_train = data.x.numpy()
y_train = data.y.numpy()
svm_model = SVC(kernel='linear')
svm_model.fit(X_train, y_train)
y_pred = svm_model.predict(X_train[:5])
print("[SVM] Predictions:", y_pred)

# === ENVIRONNEMENT RL ===
class CyberSecurityEnv(gym.Env):
    def __init__(self):
        super().__init__()
        self.action_space = gym.spaces.Discrete(5)
        self.observation_space = gym.spaces.Discrete(100)
    def reset(self):
        return 0
    def step(self, action):
        return 0, -1, False, {}

env = CyberSecurityEnv()
rl_model = PPO("MlpPolicy", env, verbose=0)
rl_model.learn(total_timesteps=1000)

# === VISUALISATION GRAPHE ===
G = nx.DiGraph()
for _, row in triplets_df.iterrows():
    G.add_edge(row['head'], row['tail'], label=row['relation'])
#plt.figure(figsize=(10, 10))
#nx.draw(G, with_labels=True, node_size=2000, node_color='lightblue', font_size=8)
#plt.title("Knowledge Graph CSKG")
#plt.show()

plt.figure(figsize=(10, 10))
nx.draw(G, with_labels=True, node_size=2000, node_color='lightblue', font_size=8)
plt.title("Knowledge Graph CSKG")
plt.savefig("graph_cskg.png")  # ✅ Enregistre le graphe
# plt.show()  # ❌ Ne rien afficher
# === SIMULATION DE PROPAGATION ===
def simulate_vulnerability_propagation(G, entity2id, predictions, threshold=0.5, decay=0.6, steps=2):
    scores = {entity: torch.softmax(predictions[idx], dim=0)[1].item() for entity, idx in entity2id.items()}
    for _ in range(steps):
        new_scores = scores.copy()
        for src in G.nodes:
            if scores[src] > threshold:
                for dst in G.successors(src):
                    propagated = scores[src] * decay
                    new_scores[dst] = max(new_scores.get(dst, 0), propagated)
        scores = new_scores
    return scores

rgcn.eval()
with torch.no_grad():
    raw_out = rgcn(data)
    propagated_scores = simulate_vulnerability_propagation(G, entity2id, raw_out)

# Coloration selon vulnérabilité propagée
node_colors = ['red' if propagated_scores[node] > 0.5 else 'green' for node in G.nodes]
plt.figure(figsize=(10, 10))
nx.draw(G, with_labels=True, node_size=2000, node_color=node_colors, font_size=8)
plt.title("Propagation de la Vulnérabilité (rouge = propagé)")
plt.savefig("graph_cskg_propagation.png")
# === ÉVALUATION METRIQUES (Mean Rank, Hits@K) ===
def evaluate_ranking(model, h_idx, r_idx, t_idx, entity2id, top_k=10):
    ranks = []
    hits_at_k = 0

    for i in range(len(h_idx)):
        h = h_idx[i].unsqueeze(0)
        r = r_idx[i].unsqueeze(0)
        scores = []

        for candidate_t in range(len(entity2id)):
            t = torch.tensor([candidate_t])
            score = model(h, r, t).item()
            scores.append((candidate_t, score))

        scores.sort(key=lambda x: x[1])  # tri croissant (RotatE)
        true_tail = t_idx[i].item()
        rank = [x[0] for x in scores].index(true_tail) + 1
        ranks.append(rank)

        if rank <= top_k:
            hits_at_k += 1

    mean_rank = sum(ranks) / len(ranks)
    hits = hits_at_k / len(ranks)
    print(f"[EVAL] Mean Rank: {mean_rank:.2f} | Hits@{top_k}: {hits:.2f}")

evaluate_ranking(rotate, h_idx, r_idx, t_idx, entity2id)

# === Sauvegarde des scores propagés ===
import pickle
with open("propagated_scores.pkl", "wb") as f:
    pickle.dump(propagated_scores, f)

# === Sauvegarde des métriques (optionnel) ===
with open("metrics.txt", "w") as f:
    f.write(f"[EVAL] Mean Rank: {mean_rank:.2f} | Hits@{top_k}: {hits:.2f}\n")
