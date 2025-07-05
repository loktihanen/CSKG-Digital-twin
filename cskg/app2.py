

# app.py
import streamlit as st
import pandas as pd
import networkx as nx
from pyvis.network import Network
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from py2neo import Graph
import tempfile  # ✅ import requis pour NamedTemporaryFile
import os 

from PIL import Image
import torch
import base64
import pickle
# ======================== 📦 INSTALL ========================
import os
os.system("pip install nvdlib pyattck transformers --quiet")

# ======================== 📥 IMPORTS ========================
import nvdlib
from pyattck import Attck
from transformers import pipeline
from rdflib import Graph as RDFGraph, Namespace
from rdflib.plugins.sparql import prepareQuery

@st.cache_resource
def connect_neo4j():
    try:
        uri = "neo4j+s://1cb37128.databases.neo4j.io"
        user = "neo4j"
        password = "qUocbHeI6RTR3sqwFE6IhnAX5nk9N_KnQVFthB3E9S8"
        graph = Graph(uri, auth=(user, password))
        graph.run("RETURN 1").evaluate()
        st.success("✅ Connexion Neo4j Aura réussie")
        return graph
    except Exception as e:
        st.error(f"❌ Erreur de connexion Neo4j : {e}")
        st.stop()

graph_db = connect_neo4j()

st.set_page_config(page_title="CSKG Dashboard", layout="wide")

# ========== SIDEBAR MENU ==========
menu = st.sidebar.radio("📌 Menu", [
    "CSKG1 – NVD",
    "CSKG2 – Nessus",
    "CSKG3 – Fusionné",
    "Simulation",
    "Recommandation",
    "Heatmap",
    "Graphes CSKG",
    "Prédictions SVM / R-GCN",
    "Propagation des Vulnérabilités",
    "Évaluation RotatE"
])

# ========== CSKG1 – NVD =========
if menu == "CSKG1 – NVD":
    import networkx as nx
    from pyvis.network import Network
    import pandas as pd
    import tempfile
    import os

    st.header("📌 CSKG1 – Graphe basé sur la NVD")
    st.info("Ce module affiche les vulnérabilités extraites depuis la National Vulnerability Database (CVE, CWE, CPE).")

    # 🎛️ Filtres dynamiques
    st.sidebar.subheader("🎛️ Filtres spécifiques à KG1")
    min_cvss = st.sidebar.slider("Score CVSS minimum", 0.0, 10.0, 0.0)
    selected_entities = st.sidebar.multiselect("Entités à afficher", ["CVE", "CWE", "CPE", "Entity"], default=["CVE", "CWE", "CPE"])

    @st.cache_data
    def load_kg1_data(min_cvss):
        query = f"""
        MATCH (c:CVE)-[r]->(x)
        WHERE c.cvss_score >= {min_cvss}
        RETURN c.name AS source, type(r) AS relation, x.name AS target, labels(x)[0] AS target_type
        """
        return graph_db.run(query).to_data_frame()

    df = load_kg1_data(min_cvss)

    if df.empty:
        st.warning("⚠️ Aucune relation NVD trouvée pour les filtres donnés.")
        st.stop()

    # Filtres supplémentaires
    relations_list = df["relation"].unique().tolist()
    selected_relations = st.sidebar.multiselect("Relations à afficher", relations_list, default=relations_list)
    df = df[df["relation"].isin(selected_relations)]

    # 🌐 Construction du graphe
    G = nx.DiGraph()
    skipped_rows = 0

    for _, row in df.iterrows():
        src = row.get("source")
        tgt = row.get("target")
        tgt_type = row.get("target_type")

        if not src or not tgt or pd.isna(src) or pd.isna(tgt):
            skipped_rows += 1
            continue
        if tgt_type not in selected_entities:
            continue

        G.add_node(src, type="CVE", label=src)
        G.add_node(tgt, type=tgt_type, label=tgt)
        G.add_edge(src, tgt, label=row["relation"])

    # 🎨 Pyvis pour visualisation interactive
    st.subheader("🌐 Visualisation interactive (`pyvis`)")
    color_map = {
        "CVE": "#ff4d4d", "CWE": "#ffa500", "CPE": "#6699cc", "Entity": "#dddd00"
    }

    net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white")
    for node, data in G.nodes(data=True):
        net.add_node(node, label=data["label"], color=color_map.get(data["type"], "gray"))
    for src, tgt, data in G.edges(data=True):
        net.add_edge(src, tgt, title=data.get("label", ""))

    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
        net.save_graph(tmp_file.name)
        html = open(tmp_file.name, 'r', encoding='utf-8').read()
        st.components.v1.html(html, height=700, scrolling=True)

    # 📊 Statistiques
    st.markdown("### 📊 Statistiques du graphe")
    st.markdown(f"- **Nœuds** : {G.number_of_nodes()}")
    st.markdown(f"- **Arêtes** : {G.number_of_edges()}")
    st.markdown(f"- **Densité** : {nx.density(G):.4f}")
    st.markdown(f"- **Lignes ignorées** : {skipped_rows}")

    # 📥 Export GML
    nx.write_gml(G, "/tmp/kg1_filtered.gml")
    with open("/tmp/kg1_filtered.gml", "rb") as f:
        st.download_button("📥 Télécharger le graphe (GML)", f, file_name="kg1_nvd.gml")

    # 📄 Table des relations
    st.markdown("### 📄 Relations extraites")
    st.dataframe(df, use_container_width=True)

# ========== CSKG2 – Nessus ==========
elif menu == "CSKG2 – Nessus":
    st.header("🧩 CSKG2 – Graphe basé sur les scans Nessus")
    st.info("Ce module permet d'explorer les vulnérabilités détectées dans ton infrastructure via les résultats Nessus (hosts, plugins, CVE, etc.).")

    # 🎛️ Filtres
    st.sidebar.subheader("🎛️ Filtres spécifiques à KG2")
    selected_entities = st.sidebar.multiselect(
        "Types d'entités à afficher",
        ["Host", "Plugin", "CVE", "Service", "Port", "OperatingSystem", "Scanner", "Severity"],
        default=["Host", "Plugin", "CVE"]
    )
    enable_physics = st.sidebar.toggle("Activer l'animation (physique)", value=True)

    # 📥 Chargement des données
    @st.cache_data
    def load_kg2_data():
        query = """
        MATCH (a)-[r]->(b)
        WHERE labels(a)[0] IN ['Host', 'Plugin', 'Service', 'Port', 'OperatingSystem', 'Scanner', 'Severity']
          AND labels(b)[0] IN ['Plugin', 'CVE', 'Port', 'Service', 'OperatingSystem', 'Scanner', 'Severity']
        RETURN a.name AS source, type(r) AS relation, b.name AS target,
               labels(a)[0] AS source_type, labels(b)[0] AS target_type
        """
        return graph_db.run(query).to_data_frame()

    df = load_kg2_data()

    if df.empty:
        st.warning("Aucune relation Nessus trouvée dans Neo4j.")
        st.stop()

    import networkx as nx
    from pyvis.network import Network
    import pandas as pd

    st.subheader("🌐 Visualisation interactive (`pyvis`)")

    # 📊 Construction du graphe
    G = nx.DiGraph()
    skipped = 0
    for _, row in df.iterrows():
        src = row.get("source")
        tgt = row.get("target")
        src_type = row.get("source_type")
        tgt_type = row.get("target_type")

        if not src or not tgt or pd.isna(src) or pd.isna(tgt):
            skipped += 1
            continue

        # n'affiche que si au moins un des deux nœuds est sélectionné
        if src_type not in selected_entities and tgt_type not in selected_entities:
            continue

        G.add_node(src, type=src_type, label=src)
        G.add_node(tgt, type=tgt_type, label=tgt)
        G.add_edge(src, tgt, label=row["relation"])

    # 🎨 Couleurs selon type
    color_map = {
        "Host": "#00cc66",
        "Plugin": "#66ccff",
        "CVE": "#ff4d4d",
        "Service": "#ffaa00",
        "Port": "#9966cc",
        "OperatingSystem": "#cccccc",
        "Scanner": "#00b8d9",
        "Severity": "#ff9900"
    }

    # 🌐 Visualisation PyVis
    net = Network(height="700px", width="100%", bgcolor="#1e1e1e", font_color="white")

    if enable_physics:
        net.barnes_hut()
    else:
        net.set_options('''var options = { "physics": { "enabled": false } }''')

    for node, data in G.nodes(data=True):
        net.add_node(node, label=data["label"], color=color_map.get(data["type"], "gray"), title=data["type"])
    for src, tgt, data in G.edges(data=True):
        net.add_edge(src, tgt, title=data.get("label", ""))

    # 📤 Affichage HTML
    path = "/tmp/kg2_nessus.html"
    net.save_graph(path)
    with open(path, 'r', encoding='utf-8') as f:
        html = f.read()
    st.components.v1.html(html, height=700, scrolling=True)

    # 📈 Statistiques
    st.markdown("### 📊 Statistiques du graphe")
    st.markdown(f"- **Nœuds** : {G.number_of_nodes()}")
    st.markdown(f"- **Arêtes** : {G.number_of_edges()}")
    st.markdown(f"- **Densité** : {nx.density(G):.4f}")
    st.markdown(f"- **Lignes ignorées** : {skipped}")

    # 📄 Table des relations
    st.markdown("### 📄 Relations extraites")
    st.dataframe(df, use_container_width=True)

# ========== CSKG3 – Fusionné ==========
elif menu == "CSKG3 – Fusionné":
    st.header("🔀 CSKG3 – Graphe fusionné & enrichi")
    st.info("Visualisation du graphe résultant de la fusion entre les CVE issues de la NVD et celles issues des scans Nessus, via des relations SAME_AS vers des nœuds CVE_UNIFIED.")

    # Requête Neo4j pour récupérer les relations et les entités fusionnées
    query = """
    MATCH (a)-[r]->(b)
    WHERE labels(a)[0] IN ['CVE', 'CVE_UNIFIED', 'Plugin', 'Host', 'Service', 'Patch', 'Severity']
      AND labels(b)[0] IN ['CVE', 'CVE_UNIFIED', 'Plugin', 'Host', 'Service', 'Patch', 'Severity']
    RETURN a.name AS source, type(r) AS relation, b.name AS target,
           labels(a)[0] AS source_type, labels(b)[0] AS target_type
    LIMIT 500
    """
    data = graph_db.run(query).data()

    # Construction du graphe
    G = nx.DiGraph()
    color_map = {
        "CVE": "#ff4d4d",  # Rouge pour CVE
        "CVE_UNIFIED": "#ffcc00",  # Jaune pour CVE_UNIFIED
        "Plugin": "#66ccff",  # Bleu pour Plugin
        "Host": "#00cc66",  # Vert pour Host
        "Service": "#ffa500",  # Orange pour Service
        "Patch": "#aa33ff",  # Violet pour Patch
        "Severity": "#ff9900"  # Jaune pour Severity
    }

    skipped = 0
    for row in data:
        src = row.get("source")
        tgt = row.get("target")
        rel = row.get("relation")
        src_type = row.get("source_type")
        tgt_type = row.get("target_type")

        if not src or not tgt or not rel:
            skipped += 1
            continue

        G.add_node(src, type=src_type, label=src)
        G.add_node(tgt, type=tgt_type, label=tgt)
        G.add_edge(src, tgt, label=rel)

    # Récupération des statistiques des relations SAME_AS
    nb_unifies = graph_db.run("""
        MATCH (cveu:CVE_UNIFIED)-[:SAME_AS]->(:CVE)
        RETURN count(DISTINCT cveu) AS nb
    """).evaluate()

    total_fusionnees = graph_db.run("""
        MATCH (c:CVE)-[:SAME_AS]-(:CVE)
        RETURN count(DISTINCT c) AS total
    """).evaluate()

    same_as_total = graph_db.run("""
        MATCH (:CVE)-[r:SAME_AS]-(:CVE)
        RETURN count(r) AS total
    """).evaluate()

    # Fonction de dessin avec PyVis
    def draw_pyvis_graph(G):
        net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white")
        for node, data in G.nodes(data=True):
            node_type = data.get("type", "gray")
            color = color_map.get(node_type, "gray")
            net.add_node(node, label=data.get("label", node), color=color, title=node_type)
        for src, tgt, data in G.edges(data=True):
            net.add_edge(src, tgt, title=data.get("label", ""))
        tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
        net.save_graph(tmpfile.name)
        return tmpfile.name

    # Visualisation interactive avec PyVis
    st.subheader("🌐 Visualisation interactive (PyVis)")
    with st.spinner("🔄 Génération du graphe..."):
        html_path = draw_pyvis_graph(G)
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        st.components.v1.html(html, height=700, scrolling=True)

    # Statistiques du graphe CSKG3
    st.markdown("### 📈 Statistiques du graphe CSKG3")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🧠 Nœuds visibles", G.number_of_nodes())
    with col2:
        st.metric("🔗 Relations visibles", G.number_of_edges())
    with col3:
        st.metric("📊 Densité", f"{nx.density(G):.4f}")

    st.caption(f"⚠️ Lignes ignorées (valeurs nulles) : {skipped}")

    # Alignement & Fusion via CVE_UNIFIED
    st.markdown("### 🧬 Alignement & Fusion via CVE_UNIFIED")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🔀 Relations SAME_AS", same_as_total)
    with col2:
        st.metric("✅ CVE alignées", total_fusionnees)
    with col3:
        st.metric("🧬 Nœuds CVE_UNIFIED", nb_unifies)


# ======================== Simulation ==========================
elif menu == "Simulation":

    import streamlit as st
    from py2neo import Graph, NodeMatcher
    import pandas as pd
    import networkx as nx
    from pyvis.network import Network
    import tempfile
    import matplotlib.pyplot as plt
    import seaborn as sns
    from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal
    from owlrl import DeductiveClosure, OWLRL_Semantics
    from rdflib.plugins.sparql import prepareQuery

    st.header("🧪 Simulation basée sur le Jumeau Numérique")
    st.info("Ce module regroupe raisonnement OWL, analyse de risques, simulation What-If et visualisation interactive.")

    # ======================== 1. 🔄 Extraction Neo4j ========================
    uri = "neo4j+s://1cb37128.databases.neo4j.io"
    user = "neo4j"
    password = "qUocbHeI6RTR3sqwFE6IhnAX5nk9N_KnQVFthB3E9S8"
    graph = Graph(uri, auth=(user, password))
    matcher = NodeMatcher(graph)

    # Requête pour extraire les relations d'impact entre hôtes et services (selon NVD/Nessus)
    query = """
    MATCH (h:Host)-[r:IMPACTS]->(s:Service)
    WHERE h.name IS NOT NULL AND s.name IS NOT NULL
    RETURN h.name AS host, type(r) AS relation, s.name AS service, r.weight AS weight
    """
    df_impacts = graph.run(query).to_data_frame()

    # ======================== 2. 🧠 Raisonnement OWL ========================
    uploaded_file = st.file_uploader("📂 Uploader le fichier OWL enrichi (`cskg3_enriched.ttl`)", type="ttl")
    rdf_graph = RDFGraph()
    CYBER = Namespace("http://example.org/cyber#")
    rdf_graph.bind("cyber", CYBER)

    if uploaded_file:
        try:
            rdf_graph.parse(uploaded_file, format="turtle")
            DeductiveClosure(OWLRL_Semantics).expand(rdf_graph)
            rdf_graph.serialize("cskg3_inferenced.ttl", format="turtle")
            st.success("✅ Raisonnement OWL appliqué avec succès.")
        except Exception as e:
            st.error(f"Erreur lors de l’inférence OWL : {e}")
    else:
        st.warning("Veuillez uploader le fichier `cskg3_enriched.ttl` pour activer le raisonnement OWL.")

    # ======================== 3. 🔍 SPARQL: actifs à risque ========================
    try:
        query_sparql = prepareQuery("""
        PREFIX cyber: <http://example.org/cyber#>
        SELECT ?asset ?cve WHERE {
          ?asset cyber:at_risk_of ?cve .
        }
        """)
        risks = [(row.asset.split("#")[-1], row.cve.split("#")[-1]) for row in rdf_graph.query(query_sparql)]
        df_risks = pd.DataFrame(risks, columns=["Asset", "CVE"])

        if not df_risks.empty:
            st.subheader("🔍 Actifs à risque détectés par inférence")
            st.dataframe(df_risks, use_container_width=True)
        else:
            st.info("Aucun actif à risque détecté par inférence OWL.")
    except Exception as e:
        st.error(f"Erreur SPARQL ou inférence non disponible : {e}")

    # ======================== 4. 🌐 Vue interactive PyVis ========================
    st.subheader("🌐 Visualisation interactive Host → Service")
    G_nx = nx.DiGraph()

    # Construction du graphe à partir des impacts extraits
    for _, row in df_impacts.iterrows():
        host = row['host']
        service = row['service']
        weight = row['weight'] if pd.notnull(row['weight']) else 1.0
        try:
            weight = float(weight)
        except:
            weight = 1.0

        G_nx.add_node(host, label=host, color="#00cc66", type="Host")
        G_nx.add_node(service, label=service, color="#ffaa00", type="Service")
        G_nx.add_edge(host, service, weight=weight)

    net = Network(height="700px", width="100%", bgcolor="#1e1e1e", font_color="white", directed=True)
    for node, data in G_nx.nodes(data=True):
        net.add_node(node, label=data.get("label", node), color=data.get("color", "gray"), title=data.get("type", ""))
    for u, v, data in G_nx.edges(data=True):
        w = data.get("weight", 1.0)
        net.add_edge(u, v, value=w, title=f"Poids : {w:.2f}")

    tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
    net.save_graph(tmpfile.name)
    with open(tmpfile.name, "r", encoding="utf-8") as f:
        html = f.read()
    st.components.v1.html(html, height=700, scrolling=True)

    # ======================== 5. 🚀 Simulation What-If ========================
    st.subheader("🚀 Simulation What-If (Propagation de risque)")
    hosts = sorted(set(df_impacts["host"]))
    selected_host = st.selectbox("Choisir un hôte à simuler", hosts)
    decay = st.slider("Facteur de dissipation", 0.1, 1.0, 0.6, step=0.05)
    max_depth = st.slider("Profondeur max", 1, 5, 3)

    def simulate_propagation(G, start_node, decay=0.6, max_depth=3):
        scores = {start_node: 1.0}
        frontier = [start_node]
        for step in range(max_depth):
            next_frontier = []
            for node in frontier:
                for neighbor in G.successors(node):
                    weight = G[node][neighbor].get("weight", 1.0)
                    propagated_score = scores[node] * decay * weight
                    if propagated_score > scores.get(neighbor, 0):
                        scores[neighbor] = propagated_score
                        next_frontier.append(neighbor)
            frontier = next_frontier
            if not frontier:
                break
        return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))

    if st.button("🚀 Lancer la simulation"):
        results = simulate_propagation(G_nx, selected_host, decay, max_depth)
        st.success(f"Propagation depuis {selected_host} effectuée avec {len(results)} nœuds affectés.")

        # ======================== 7. 📊 Analyse & heatmap ========================
        st.subheader("📊 Heatmap des services impactés")
        service_scores = {n: s for n, s in results.items() if G_nx.nodes[n].get("type") == "Service"}
        if service_scores:
            df_heat = pd.DataFrame.from_dict(service_scores, orient="index", columns=["Score"])
            st.dataframe(df_heat.style.background_gradient(cmap="Reds"), use_container_width=True)
            plt.figure(figsize=(8, max(1, len(df_heat)*0.5)))
            sns.heatmap(df_heat.sort_values("Score", ascending=False), annot=True, cmap="Reds", fmt=".2f")
            plt.title(f"Propagation depuis {selected_host}")
            st.pyplot(plt.gcf())
            plt.clf()
        else:
            st.info("Aucun service impacté détecté.")

    # ======================== 6. 🔗 Chaîne d'attaque simulée ========================
    st.subheader("🔗 Chaîne d'attaque simulée (fictive)")
    attack_chain = [
        ("host-001", "connected_to", "host-002"),
        ("host-002", "connected_to", "host-003"),
        ("host-003", "at_risk_of", "CVE-2024-99999"),
        ("CVE-2024-99999", "targets", "CriticalAsset-01")
    ]
    G_attack = nx.DiGraph()
    for h, r, t in attack_chain:
        G_attack.add_edge(h, t, label=r)

    pos = nx.spring_layout(G_attack)
    plt.figure(figsize=(8, 4))
    nx.draw(G_attack, pos, with_labels=True, node_color="lightcoral", node_size=2000, font_size=9, edge_color="gray")
    edge_labels = nx.get_edge_attributes(G_attack, 'label')
    nx.draw_networkx_edge_labels(G_attack, pos, edge_labels=edge_labels)
    st.pyplot(plt.gcf())
    plt.clf()

    # ======================== 7. 🧨 Analyse de risque simulée ========================
    st.subheader("🧨 Analyse de Risque Étendue")

    if st.button("🧨 Lancer une attaque simulée ciblée"):
        target_asset = st.selectbox("🎯 Choisir l'actif critique cible", sorted(G_nx.nodes))
        impacted = simulate_propagation(G_nx, target_asset, decay=0.5, max_depth=4)
        critical_services = {n: s for n, s in impacted.items() if G_nx.nodes[n].get("type") == "Service"}
        
        if critical_services:
            df_critical = pd.DataFrame.from_dict(critical_services, orient="index", columns=["RiskScore"])
            df_critical.index.name = "Service"
            df_critical = df_critical.sort_values("RiskScore", ascending=False).head(10)

            st.subheader("🔥 TOP 10 services les plus vulnérables")
            st.bar_chart(df_critical)

            st.subheader("📉 Détails des services critiques")
            st.dataframe(df_critical.style.background_gradient(cmap="OrRd"), use_container_width=True)
        else:
            st.info("Aucun service vulnérable détecté dans cette simulation.")

# ======================= Recommandation ========================
elif menu == "Recommandation":

    import streamlit as st
    import pandas as pd
    import nvdlib
    from pyattck import Attck
    from transformers import pipeline
    from py2neo import Graph
    from rdflib import Graph as RDFGraph, Namespace, URIRef
    from owlrl import DeductiveClosure, OWLRL_Semantics
    from rdflib.plugins.sparql import prepareQuery

    st.header("🎯 Moteur de Recommandation Cybersécurité")
    st.info("Extraction depuis Neo4j + inférence OWL automatique + enrichissement NVD, mapping ATT&CK et recommandations NLP.")

    # Connexion Neo4j Aura
    uri = "neo4j+s://1cb37128.databases.neo4j.io"
    user = "neo4j"
    password = "qUocbHeI6RTR3sqwFE6IhnAX5nk9N_KnQVFthB3E9S8"
    graph = Graph(uri, auth=(user, password))

    st.write("⏳ Extraction des relations `IS_VULNERABLE_TO` depuis Neo4j...")

    # Requête adaptée pour extraire les relations IS_VULNERABLE_TO
    query = """
    MATCH (asset)-[r:IS_VULNERABLE_TO]->(cve)
    WHERE asset.name IS NOT NULL AND cve.name IS NOT NULL
    RETURN asset.name AS asset, cve.name AS cve
    """
    
    try:
        records = graph.run(query).data()
    except Exception as e:
        st.error(f"Erreur Neo4j : {e}")
        st.stop()

    if not records:
        st.warning("Aucune relation `IS_VULNERABLE_TO` trouvée dans la base Neo4j.")
        st.stop()

    # Construction RDF + inférence OWL
    rdf_graph = RDFGraph()
    CYBER = Namespace("http://example.org/cyber#")
    rdf_graph.bind("cyber", CYBER)

    for rec in records:
        asset_uri = URIRef(CYBER + rec["asset"].replace(" ", "_"))
        cve_uri = URIRef(CYBER + rec["cve"].replace(" ", "_"))
        rdf_graph.add((asset_uri, CYBER.is_vulnerable_to, cve_uri))  # note le prédicat en minuscules

    st.write("⏳ Application du raisonnement OWL...")
    try:
        DeductiveClosure(OWLRL_Semantics).expand(rdf_graph)
        rdf_graph.serialize("cskg3_inferenced.ttl", format="turtle")
        st.success("✅ Fichier `cskg3_inferenced.ttl` généré automatiquement.")
    except Exception as e:
        st.error(f"Erreur lors de l’inférence OWL : {e}")
        st.stop()

    # Requête SPARQL adaptée à la nouvelle relation
    query_sparql = prepareQuery("""
    PREFIX cyber: <http://example.org/cyber#>
    SELECT ?asset ?cve WHERE {
      ?asset cyber:is_vulnerable_to ?cve .
    }
    """)

    results = [(row.asset.split("#")[-1], row.cve.split("#")[-1]) for row in rdf_graph.query(query_sparql)]
    df_vuln = pd.DataFrame(results, columns=["Asset", "CVE"])

    if df_vuln.empty:
        st.warning("Aucune vulnérabilité détectée après inférence.")
        st.stop()

    st.subheader("✅ Vulnérabilités identifiées après inférence")
    st.dataframe(df_vuln)

    # Enrichissement des CVE via API NVD
    @st.cache_data(show_spinner=False)
    def enrich_cve(cve_id):
        try:
            cve = nvdlib.searchCVE(cveId=cve_id)[0]
            return {
                "cvss": cve.v31score,
                "desc": cve.descriptions[0].value
            }
        except Exception:
            return {"cvss": None, "desc": ""}

    st.write("⏳ Enrichissement des CVE via API NVD...")
    df_en = df_vuln["CVE"].apply(enrich_cve).apply(pd.Series)
    df = pd.concat([df_vuln, df_en], axis=1)

    st.subheader("📝 Détails NVD")
    st.dataframe(df[["CVE", "cvss"]])

    # Utilisation du modèle ATT&CK pour associer des techniques
    at = Attck()

    def map_attack(cve_id):
        # Exemple de mapping simplifié ATT&CK pour CVEs
        # Utilisez des mappages réels pour des techniques ATT&CK spécifiques à chaque CVE
        return ["T1078", "T1059"]  # Exemple simplifié de techniques

    df["MITRE"] = df["CVE"].apply(map_attack)
    st.subheader("🛡️ Techniques ATT&CK associées")
    st.dataframe(df[["CVE", "MITRE"]])

    st.write("⏳ Génération des recommandations NLP...")
    nlp = pipeline("text2text-generation", model="google/flan-t5-small")

    def recommend(row):
        prompt = (
            f"CVE: {row.CVE}\n"
            f"Score CVSS: {row.cvss}\n"
            f"Techniques ATT&CK: {', '.join(row.MITRE)}\n"
            "Que recommandes-tu ?"
        )
        out = nlp(prompt, max_length=64)[0]["generated_text"]
        return out

    df["Recommendation"] = df.apply(recommend, axis=1)

    st.subheader("✅ Recommandations générées")
    st.dataframe(df[["Asset", "CVE", "cvss", "MITRE", "Recommendation"]])

    csv_data = df.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Télécharger les recommandations CSV", data=csv_data, file_name="recommandations_cyber.csv", mime="text/csv")
    



# ========== Heatmap ==========
elif menu == "Heatmap":
    st.title("🔥 Heatmap des Vulnérabilités")
    st.info("Carte de chaleur représentant l’intensité des vulnérabilités par hôte.")

    # Connexion à Neo4j Aura
    uri = "neo4j+s://1cb37128.databases.neo4j.io"
    user = "neo4j"
    password = "qUocbHeI6RTR3sqwFE6IhnAX5nk9N_KnQVFthB3E9S8"
    graph = Graph(uri, auth=(user, password))

    # Requête pour obtenir les relations IS_VULNERABLE_TO avec les scores CVSS
    query = """
    MATCH (host:Host)-[r:VULNERABLE_TO]->(cve:CVE)
    WHERE host.name IS NOT NULL AND cve.cvssScore IS NOT NULL
    RETURN host.name AS host, cve.name AS cve, cve.cvssScore AS score
    """
    
    # Récupérer les données des relations vulnérabilités et scores CVSS
    try:
        records = graph.run(query).data()
    except Exception as e:
        st.error(f"Erreur Neo4j : {e}")
        st.stop()

    if not records:
        st.warning("Aucune relation `VULNERABLE_TO` avec des scores CVSS trouvée dans la base Neo4j.")
        st.stop()

    # Préparation des données pour la heatmap
    hosts = sorted(set([rec["host"] for rec in records]))
    cves = sorted(set([rec["cve"] for rec in records]))

    # Initialisation du DataFrame des scores CVSS
    data = np.zeros((len(hosts), len(cves)))

    # Mapping des hôtes et CVEs à leurs indices dans le DataFrame
    host_index = {host: idx for idx, host in enumerate(hosts)}
    cve_index = {cve: idx for idx, cve in enumerate(cves)}

    # Remplir le DataFrame avec les scores CVSS
    for rec in records:
        host_idx = host_index[rec["host"]]
        cve_idx = cve_index[rec["cve"]]
        data[host_idx, cve_idx] = rec["score"]

    # Convertir en DataFrame pandas
    df = pd.DataFrame(data, index=hosts, columns=cves)

    # Affichage de la heatmap avec seaborn
    st.subheader("📊 Carte de chaleur des vulnérabilités")
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.heatmap(df, annot=True, cmap="Reds", cbar=True, fmt=".2f", ax=ax)
    st.pyplot(fig)

    # Statistiques de la heatmap
    st.markdown("### 📊 Statistiques de la carte de chaleur")
    st.markdown(f"- **Hôtes** : {df.shape[0]}")
    st.markdown(f"- **Vulnérabilités (CVE)** : {df.shape[1]}")
    st.markdown(f"- **Score CVSS moyen** : {df.mean().mean():.2f}")










# === Pages ===


elif menu == "Graphes CSKG":
    st.subheader("📌 Graphe initial")
    try:
        img1 = Image.open("graph_cskg.png")
        st.image(img1, caption="Graphe original CSKG")
    except FileNotFoundError:
        st.error("graph_cskg.png non trouvé")

    st.subheader("🔥 Propagation des vulnérabilités")
    try:
        img2 = Image.open("graph_cskg_propagation.png")
        st.image(img2, caption="Propagation (rouge = vulnérabilité transmise)")
    except FileNotFoundError:
        st.error("graph_cskg_propagation.png non trouvé")

elif menu == "Prédictions SVM / R-GCN":
    st.subheader("📊 Résultats SVM")
    try:
        svm_df = pd.read_csv("predictions_svm.csv")
        st.dataframe(svm_df.head(10))
    except FileNotFoundError:
        st.warning("Fichier `predictions_svm.csv` manquant.")

elif menu == "Propagation des Vulnérabilités":
    st.subheader("🔬 Top entités vulnérables propagées")
    try:
        with open("propagated_scores.pkl", "rb") as f:
            propagated_scores = pickle.load(f)
        top_nodes = sorted(propagated_scores.items(), key=lambda x: x[1], reverse=True)
        df_top = pd.DataFrame(top_nodes, columns=["Node", "Score"])
        st.dataframe(df_top.head(20))
    except FileNotFoundError:
        st.warning("Fichier `propagated_scores.pkl` manquant.")

elif menu == "Évaluation RotatE":
    st.subheader("📈 Évaluation du modèle RotatE")
    try:
        with open("metrics.txt", "r") as f:
            lines = f.read().splitlines()
        for line in lines:
            st.text(line)
    except FileNotFoundError:
        st.warning("Fichier `metrics.txt` manquant.")









st.markdown("---")

st.markdown(
    """
    <div style='text-align: center; font-size: 16px; padding-top: 20px;'>
        © 2025 <strong>Hanen Lokti</strong> · 
        📧 <a href="mailto:hanenlokti2020@gmail.com" target="_blanc">hanenlokti2020@gmail.com</a> · 
        🔗 <a href="https://www.facebook.com/hanen.lakti.1274" target="https://www.facebook.com/hanen.lakti.1274">Facebook</a> · 
        💼 <a href="https://www.linkedin.com/in/hanen-lakti-660689203/" target="https://www.linkedin.com/in/hanen-lakti-660689203/">LinkedIn</a>
    </div>
    """,
    unsafe_allow_html=True
)
