import torch
import torch.nn.functional as F
from torch import nn
import pandas as pd
from torch_geometric.data import Data
from torch_geometric.nn import RGCNConv
from py2neo import Graph, NodeMatcher, Relationship

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

# --- Étape 1 : Extraction des triplets depuis Neo4j (adapté pour CSKG1 et CSKG2)
query_cskg1 = """
MATCH (h)-[r]->(t)
WHERE h.name IS NOT NULL AND t.name IS NOT NULL AND r.source = 'NVD'
RETURN h.name AS head, type(r) AS relation, t.name AS tail
"""
query_cskg2 = """
MATCH (h)-[r]->(t)
WHERE h.name IS NOT NULL AND t.name IS NOT NULL AND r.source = 'Nessus'
RETURN h.name AS head, type(r) AS relation, t.name AS tail
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
        h_r = torch.stack([
            h_complex[..., 0]*r_complex[..., 0] - h_complex[..., 1]*r_complex[..., 1],
            h_complex[..., 0]*r_complex[..., 1] + h_complex[..., 1]*r_complex[..., 0]
        ], dim=-1)
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

# --- Étape 4 : Prédiction avec RotatE et injection dans Neo4j pour CSKG2
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

# --- Étape 5 : Préparation pour R-GCN
x = torch.randn(len(entity2id), 64)
edge_index = torch.tensor([
    [entity2id[h] for h in triplets_cskg1_df["head"] + triplets_cskg2_df["head"]],
    [entity2id[t] for t in triplets_cskg1_df["tail"] + triplets_cskg2_df["tail"]]
], dtype=torch.long)
edge_type = torch.tensor([rel2id[r] for r in triplets_cskg1_df["relation"].tolist() + triplets_cskg2_df["relation"].tolist()], dtype=torch.long)

data = Data(x=x, edge_index=edge_index, edge_type=edge_type, num_nodes=len(entity2id))
data.y = torch.randint(0, 2, (len(entity2id),))  # Dummy labels
train_mask = torch.rand(len(entity2id)) > 0.3

# --- Étape 6 : R-GCN
class RGCN(nn.Module):
    def __init__(self, in_feat, hidden_feat, out_feat, num_rels):
        super().__init__()
        self.conv1 = RGCNConv(in_feat, hidden_feat, num_rels)
        self.conv2 = RGCNConv(hidden_feat, out_feat, num_rels)

    def forward(self, data):
        x, edge_index, edge_type = data.x, data.edge_index, data.edge_type
        x = F.relu(self.conv1(x, edge_index, edge_type))
        return self.conv2(x, edge_index, edge_type)

rgcn = RGCN(in_feat=64, hidden_feat=32, out_feat=2, num_rels=len(rel2id))
optimizer_rgcn = torch.optim.Adam(rgcn.parameters(), lr=0.01)

# Entraînement du modèle R-GCN
print("\n🛠️ Entraînement R-GCN...")
for epoch in range(50):
    rgcn.train()
    optimizer_rgcn.zero_grad()
    out = rgcn(data)
    loss = F.cross_entropy(out[train_mask], data.y[train_mask])
    loss.backward()
    optimizer_rgcn.step()
    if epoch % 10 == 0 or epoch == 1:
        acc = (out.argmax(dim=1) == data.y).float().mean().item()
        print(f"[R-GCN] Epoch {epoch} - Loss: {loss.item():.4f} - Acc: {acc:.2%}")

# --- Étape 7 : Injection des résultats dans Neo4j pour marquer les entités vulnérables
def inject_vulnerable_property(entity2id, rgcn_out, threshold=0.5):
    for entity, idx in entity2id.items():
        prob_vuln = torch.softmax(rgcn_out[idx], dim=0)[1].item()
        vulnerable = prob_vuln > threshold
        node = matcher.match(name=entity).first()
        if node:
            node["vulnerable"] = vulnerable
            graph.push(node)
            print(f"🛡️ Noeud {entity} : vulnérable = {vulnerable}")

# --- Pipeline principal
if __name__ == "__main__":
    print("\n▶️ Injection relations at_risk_of (RotatE)...")
    inject_at_risk_of([("host-001", "at_risk_of", "CVE-2024-99999")], entity2id, rel2id, rotate_model)

    print("\n▶️ Injection propriétés vulnérables (R-GCN)...")
    rgcn.eval()
    with torch.no_grad():
        out = rgcn(data)
    inject_vulnerable_property(entity2id, out)
