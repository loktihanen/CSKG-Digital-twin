import torch
import torch.nn.functional as F
from torch import nn
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
from torch_geometric.data import Data
from torch_geometric.nn import RGCNConv
from py2neo import Graph, NodeMatcher, Relationship
import numpy as np

# --- Connexion à Neo4j
uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
graph = Graph(uri, auth=(user, password))

try:
    info = graph.run("RETURN 1").data()
    print("Connexion Neo4j réussie :", info)
except Exception as e:
    print("Erreur de connexion Neo4j :", e)

# --- Étape 1 : Extraction des triplets depuis Neo4j
query_cskg1 = """ 
MATCH (h)-[r]->(t) 
WHERE h.name IS NOT NULL AND t.name IS NOT NULL AND r.source = 'NVD' 
RETURN h.name AS head, type(r) AS relation, t.name AS tail, r.cvss AS cvss, r.exploitability AS exploitability
"""
query_cskg2 = """ 
MATCH (h)-[r]->(t) 
WHERE h.name IS NOT NULL AND t.name IS NOT NULL AND r.source = 'Nessus' 
RETURN h.name AS head, type(r) AS relation, t.name AS tail, r.cvss AS cvss, r.exploitability AS exploitability
"""
# Extraire les triplets des deux graphes
results_cskg1 = graph.run(query_cskg1).data()
results_cskg2 = graph.run(query_cskg2).data()

# Convertir en DataFrame
triplets_cskg1_df = pd.DataFrame(results_cskg1)
triplets_cskg2_df = pd.DataFrame(results_cskg2)

# Vérification des données extraites
if triplets_cskg1_df.empty or triplets_cskg2_df.empty:
    raise ValueError("Aucun triplet récupéré depuis Neo4j. Vérifiez votre base.")

print(f"✅ {len(triplets_cskg1_df)} triplets récupérés de CSKG1 (NVD)")
print(f"✅ {len(triplets_cskg2_df)} triplets récupérés de CSKG2 (Nessus)")

# --- Étape 2 : Mapping des entités et relations
entities = pd.Series(pd.concat([triplets_cskg1_df["head"], triplets_cskg1_df["tail"], 
                                triplets_cskg2_df["head"], triplets_cskg2_df["tail"]]).unique()).reset_index()
entity2id = dict(zip(entities[0], entities["index"]))

relations = pd.Series(pd.concat([triplets_cskg1_df["relation"], triplets_cskg2_df["relation"]]).unique()).reset_index()
rel2id = dict(zip(relations[0], relations["index"]))

h_idx_cskg1 = torch.tensor([entity2id[h] for h in triplets_cskg1_df["head"]])
r_idx_cskg1 = torch.tensor([rel2id[r] for r in triplets_cskg1_df["relation"]])
t_idx_cskg1 = torch.tensor([entity2id[t] for t in triplets_cskg1_df["tail"]])

h_idx_cskg2 = torch.tensor([entity2id[h] for h in triplets_cskg2_df["head"]])
r_idx_cskg2 = torch.tensor([rel2id[r] for r in triplets_cskg2_df["relation"]])
t_idx_cskg2 = torch.tensor([entity2id[t] for t in triplets_cskg2_df["tail"]])

# --- Étape 3 : Modèle RotatE pour prédiction des relations
class RotatEModel(nn.Module):
    def __init__(self, num_entities, num_relations, embedding_dim=64):
        super().__init__()
        self.ent = nn.Embedding(num_entities, embedding_dim)
        self.rel = nn.Embedding(num_relations, embedding_dim)

    def forward(self, h_idx, r_idx, t_idx):
        pi = 3.141592653589793
        h = self.ent(h_idx)
        r = self.rel(r_idx) * pi
        t = self.ent(t_idx)
        r_complex = torch.stack([torch.cos(r), torch.sin(r)], dim=-1)
        h_complex = torch.stack([h, torch.zeros_like(h)], dim=-1)
        h_r = torch.stack([h_complex[..., 0]*r_complex[..., 0] - h_complex[..., 1]*r_complex[..., 1],
                           h_complex[..., 0]*r_complex[..., 1] + h_complex[..., 1]*r_complex[..., 0]], dim=-1)
        t_complex = torch.stack([t, torch.zeros_like(t)], dim=-1)
        score = -torch.norm(h_r - t_complex, dim=-1).sum(dim=-1)
        return score

rotate_model = RotatEModel(len(entity2id), len(rel2id), embedding_dim=64)
optimizer_rotate = torch.optim.Adam(rotate_model.parameters(), lr=0.01)

# Entraînement du modèle RotatE
print("🛠️ Entraînement RotatE...")
for epoch in range(100):
    rotate_model.train()
    optimizer_rotate.zero_grad()
    loss = -torch.mean(rotate_model(h_idx_cskg1, r_idx_cskg1, t_idx_cskg1))
    loss.backward()
    optimizer_rotate.step()
    if epoch % 10 == 0 or epoch == 2:
        print(f"[RotatE] Epoch {epoch} - Loss: {loss.item():.4f}")

# --- Étape 4 : Prédiction avec RotatE et injection dans Neo4j
matcher = NodeMatcher(graph)

def inject_at_risk_of(predictions, entity2id, rel2id, model, threshold=0.0):
    rel_name = "at_risk_of"
    for h, r, t in predictions:
        if h not in entity2id or r not in rel2id or t not in entity2id:
            print(f"⚠️ Entité ou relation inconnue : {h}, {r}, {t}")
            continue
        score = model(
            torch.tensor([entity2id[h]]),
            torch.tensor([rel2id[r]]),
            torch.tensor([entity2id[t]]),
        ).item()
        print(f"Score({h}, {r}, {t}) = {score:.4f}")
        if score > threshold:
            node_h = matcher.match(name=h).first()
            node_t = matcher.match(name=t).first()
            if node_h and node_t:
                rel = Relationship(node_h, rel_name, node_t)
                graph.merge(rel)
                print(f"✅ Relation ({h})-[:{rel_name}]->({t}) injectée (score {score:.4f})")

# --- Étape 5 : Calcul de la matrice de risques à partir des données réelles
def compute_risk_matrix():
    risk_matrix = np.zeros((len(entity2id), len(entity2id)))

    # En prenant en compte le CVSS pour calculer un risque pour chaque relation
    for _, row in triplets_cskg1_df.iterrows():
        head, tail, relation, cvss, exploitability = row['head'], row['tail'], row['relation'], row.get('cvss', 0), row.get('exploitability', 0)
        head_idx, tail_idx = entity2id[head], entity2id[tail]
        
        # Calculer le risque en fonction du score CVSS et de la probabilité d'exploitation
        risk_score = float(cvss) * float(exploitability) if cvss and exploitability else 1.0  # Combinaison des deux critères
        risk_matrix[head_idx, tail_idx] = risk_score

    for _, row in triplets_cskg2_df.iterrows():
        head, tail, relation, cvss, exploitability = row['head'], row['tail'], row['relation'], row.get('cvss', 0), row.get('exploitability', 0)
        head_idx, tail_idx = entity2id[head], entity2id[tail]
        
        # Calculer le risque en fonction du score CVSS et de la probabilité d'exploitation
        risk_score = float(cvss) * float(exploitability) if cvss and exploitability else 1.0  # Combinaison des deux critères
        risk_matrix[head_idx, tail_idx] = risk_score

    return risk_matrix

# Générer la matrice de risques réelle
risk_matrix = compute_risk_matrix()

# --- Visualisation de la heatmap des risques
def plot_heatmap(risk_matrix):
    plt.figure(figsize=(10, 8))
    plt.imshow(risk_matrix, cmap='hot', interpolation='nearest')
    plt.title('Simulation de Risque')
    plt.colorbar(label="Risque")
    plt.xlabel('Hôtes')
    plt.ylabel('CVE')
    plt.show()

plot_heatmap(risk_matrix)

# --- Simulation de l'attaque et injection dans Neo4j
def simulate_attack():
    print("\nSimulation d'attaque... ")
    # Simuler l'attaque (exemple fictif)
    predictions = [("host-001", "at_risk_of", "CVE-2024-99999")]
    inject_at_risk_of(predictions, entity2id, rel2id, rotate_model)

simulate_attack()

# --- Visualisation du Graphe avec NetworkX
def plot_network():
    G = nx.Graph()
    for h, t in zip(triplets_cskg1_df["head"], triplets_cskg1_df["tail"]):
        G.add_edge(h, t)
    pos = nx.spring_layout(G)
    plt.figure(figsize=(12, 12))
    nx.draw(G, pos, with_labels=True, node_size=500, node_color='skyblue', font_size=10)
    plt.title("Réseau de Vulnérabilité - Simulation d'attaque")
    plt.show()

plot_network()
