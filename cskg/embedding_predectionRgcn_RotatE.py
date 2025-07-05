import torch
import torch.nn.functional as F
from torch import nn
import pandas as pd
from torch_geometric.data import Data
from torch_geometric.nn import RGCNConv
from py2neo import Graph, NodeMatcher, Relationship
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# --- Device
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"🖥️ Utilisation du device : {device}")

# --- Connexion à Neo4j
uri = "neo4j+s://1cb37128.databases.neo4j.io"
user = "neo4j"
password = "qUocbHeI6RTR3sqwFE6IhnAX5nk9N_KnQVFthB3E9S8"
graph = Graph(uri, auth=(user, password))
matcher = NodeMatcher(graph)

# --- Extraction des triplets
query = """
MATCH (h)-[r]->(t)
WHERE h.name IS NOT NULL AND t.name IS NOT NULL
RETURN h.name AS head, type(r) AS relation, t.name AS tail
"""
triplets_df = pd.DataFrame(graph.run(query).data())
if triplets_df.empty:
    raise ValueError("Aucun triplet trouvé.")
print(f"✅ {len(triplets_df)} triplets récupérés")

# --- Mapping entités/relations
entities = pd.Series(pd.concat([triplets_df["head"], triplets_df["tail"]]).unique()).reset_index()
entity2id = dict(zip(entities[0], entities["index"]))
relations = pd.Series(triplets_df["relation"].unique()).reset_index()
rel2id = dict(zip(relations[0], relations["index"]))

h_idx = torch.tensor([entity2id[h] for h in triplets_df["head"]], dtype=torch.long).to(device)
r_idx = torch.tensor([rel2id[r] for r in triplets_df["relation"]], dtype=torch.long).to(device)
t_idx = torch.tensor([entity2id[t] for t in triplets_df["tail"]], dtype=torch.long).to(device)

# --- Split train/test
indices = list(range(len(h_idx)))
train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42)
h_train, r_train, t_train = h_idx[train_idx], r_idx[train_idx], t_idx[train_idx]
h_test, r_test, t_test = h_idx[test_idx], r_idx[test_idx], t_idx[test_idx]

# --- Modèle RotatE
class RotatEModel(nn.Module):
    def __init__(self, num_entities, num_relations, embedding_dim=64):
        super().__init__()
        self.ent = nn.Embedding(num_entities, embedding_dim)
        self.rel = nn.Embedding(num_relations, embedding_dim)

    def forward(self, h, r, t):
        pi = 3.141592653589793
        h_e = self.ent(h)
        r_e = self.rel(r) * pi
        t_e = self.ent(t)
        r_complex = torch.stack([torch.cos(r_e), torch.sin(r_e)], dim=-1)
        h_complex = torch.stack([h_e, torch.zeros_like(h_e)], dim=-1)
        h_r = torch.stack([
            h_complex[..., 0]*r_complex[..., 0] - h_complex[..., 1]*r_complex[..., 1],
            h_complex[..., 0]*r_complex[..., 1] + h_complex[..., 1]*r_complex[..., 0]
        ], dim=-1)
        t_complex = torch.stack([t_e, torch.zeros_like(t_e)], dim=-1)
        score = -torch.norm(h_r - t_complex, dim=-1).sum(dim=-1)
        return score

rotate_model = RotatEModel(len(entity2id), len(rel2id), embedding_dim=64).to(device)
optimizer_rotate = torch.optim.Adam(rotate_model.parameters(), lr=0.01)

# --- Entraînement RotatE
print("🛠️ Entraînement RotatE...")
for epoch in range(100):
    rotate_model.train()
    optimizer_rotate.zero_grad()
    loss = -torch.mean(rotate_model(h_train, r_train, t_train))
    loss.backward()
    optimizer_rotate.step()
    if epoch % 10 == 0:
        print(f"[RotatE] Epoch {epoch} - Loss: {loss.item():.4f}")

# --- Évaluation RotatE
def evaluate_rotate_model(model, h_idx, r_idx, t_idx, num_entities, k_list=[1, 3, 10]):
    model.eval()
    ranks = []
    hits = {k: 0 for k in k_list}

    with torch.no_grad():
        for h, r, true_t in zip(h_idx, r_idx, t_idx):
            candidates = torch.arange(num_entities).to(device)
            h_batch = h.expand(num_entities)
            r_batch = r.expand(num_entities)

            scores = model(h_batch, r_batch, candidates)
            _, indices = torch.sort(scores, descending=True)
            rank = (indices == true_t).nonzero(as_tuple=True)[0].item() + 1
            ranks.append(rank)
            for k in k_list:
                if rank <= k:
                    hits[k] += 1

    mr = sum(ranks) / len(ranks)
    mrr = sum(1.0 / r for r in ranks) / len(ranks)
    print("\n📊 Évaluation RotatE:")
    print(f"Mean Rank (MR): {mr:.2f}")
    print(f"Mean Reciprocal Rank (MRR): {mrr:.4f}")
    for k in k_list:
        print(f"Hits@{k}: {hits[k]/len(ranks):.2%}")

evaluate_rotate_model(rotate_model, h_test, r_test, t_test, len(entity2id))

# --- Données pour R-GCN
x = torch.randn(len(entity2id), 64).to(device)
edge_index = torch.tensor([
    [entity2id[h] for h in triplets_df["head"]],
    [entity2id[t] for t in triplets_df["tail"]]
], dtype=torch.long).to(device)
edge_type = torch.tensor([rel2id[r] for r in triplets_df["relation"]], dtype=torch.long).to(device)
data = Data(x=x, edge_index=edge_index, edge_type=edge_type, num_nodes=len(entity2id)).to(device)
data.y = torch.randint(0, 2, (len(entity2id),), device=device)  # Fictif
train_mask = torch.rand(len(entity2id), device=device) > 0.3

# --- Modèle R-GCN
class RGCN(nn.Module):
    def __init__(self, in_feat, hidden_feat, out_feat, num_rels):
        super().__init__()
        self.conv1 = RGCNConv(in_feat, hidden_feat, num_rels)
        self.conv2 = RGCNConv(hidden_feat, out_feat, num_rels)

    def forward(self, data):
        x = F.relu(self.conv1(data.x, data.edge_index, data.edge_type))
        return self.conv2(x, data.edge_index, data.edge_type)

rgcn = RGCN(64, 32, 2, len(rel2id)).to(device)
optimizer_rgcn = torch.optim.Adam(rgcn.parameters(), lr=0.01)

print("\n🛠️ Entraînement R-GCN...")
for epoch in range(50):
    rgcn.train()
    optimizer_rgcn.zero_grad()
    out = rgcn(data)
    loss = F.cross_entropy(out[train_mask], data.y[train_mask])
    loss.backward()
    optimizer_rgcn.step()
    if epoch % 10 == 0:
        acc = (out.argmax(dim=1) == data.y).float().mean().item()
        print(f"[R-GCN] Epoch {epoch} - Loss: {loss.item():.4f} - Acc: {acc:.2%}")

# --- Évaluation R-GCN
def evaluate_rgcn_model(model, data, mask=None):
    model.eval()
    with torch.no_grad():
        out = model(data)
        pred = out.argmax(dim=1)
        y_true = data.y
        y_pred = pred
        if mask is not None:
            y_true = y_true[mask]
            y_pred = y_pred[mask]
        acc = accuracy_score(y_true.cpu(), y_pred.cpu())
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true.cpu(), y_pred.cpu(), average="binary", zero_division=0
        )
        print("\n📊 Évaluation R-GCN:")
        print(f"Accuracy: {acc:.2%}")
        print(f"Precision: {precision:.2f}")
        print(f"Recall: {recall:.2f}")
        print(f"F1-score: {f1:.2f}")

evaluate_rgcn_model(rgcn, data, mask=train_mask)


