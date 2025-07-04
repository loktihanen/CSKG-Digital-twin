# ======================== 1. IMPORTS ========================
from py2neo import Graph, Node, Relationship
from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal
from fuzzywuzzy import fuzz
from sentence_transformers import SentenceTransformer, util
import pandas as pd

# ======================== 2. CONNEXION NEO4J ========================
uri = "neo4j+s://1cb37128.databases.neo4j.io"
user = "neo4j"
password = "qUocbHeI6RTR3sqwFE6IhnAX5nk9N_KnQVFthB3E9S8"
graph = Graph(uri, auth=(user, password))

try:
    info = graph.run("RETURN 1").data()
    print("Connexion Neo4j réussie :", info)
except Exception as e:
    print("Erreur de connexion Neo4j :", e)
    exit(1)



# ======================== 3. ONTOLOGIE RDF EXPORT ========================
rdf_graph = RDFGraph()
UCO = Namespace("https://ontology.unifiedcyberontology.org/uco#")
STUCO = Namespace("http://w3id.org/sepses/vocab/ref/stuco#")
CYBER = Namespace("http://example.org/cyber#")
rdf_graph.bind("uco", UCO)
rdf_graph.bind("stuco", STUCO)
rdf_graph.bind("cyber", CYBER)

classes = [
    ("Host", CYBER.Host), ("Port", CYBER.Port), ("Service", CYBER.Service),
    ("OperatingSystem", CYBER.OperatingSystem), ("Plugin", CYBER.Plugin),
    ("Scanner", CYBER.Scanner), ("Severity", CYBER.Severity),
    ("CVE", STUCO.Vulnerability), ("Patch", CYBER.Patch),
    ("User", CYBER.User), ("Network_Segment", CYBER.NetworkSegment),
    ("Vulnerability_Report", CYBER.VulnerabilityReport),
    ("Attack_Scenario", CYBER.AttackScenario)
]

relations = [
    ("VULNERABLE_TO", CYBER.vulnerable_to), ("HAS_SERVICE", CYBER.has_service),
    ("RUNS_ON_PORT", CYBER.runs_on_port), ("HAS_OS", CYBER.has_OS),
    ("DETECTS", CYBER.detected_by), ("HAS_SEVERITY", CYBER.has_severity),
    ("SCANNED_BY", CYBER.scanned_by), ("EXPOSES", CYBER.exposes),
    ("RUNS_PLUGIN", CYBER.runs_plugin), ("RECOMMENDED_ACTION", CYBER.recommended_action),
    ("MITIGATED_BY", CYBER.mitigated_by), ("COMMUNICATES_WITH", CYBER.communicates_with),
    ("BELONGS_TO", CYBER.belongs_to), ("IMPACTS", CYBER.impacts),  # ✅ AJOUT
    ("SAME_AS", OWL.sameAs)
]

for label, uri in classes:
    rdf_graph.add((uri, RDF.type, OWL.Class))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

for label, uri in relations:
    rdf_graph.add((uri, RDF.type, OWL.ObjectProperty))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

rdf_graph.serialize(destination="kg3.ttl", format="turtle")
print("✅ Ontologie RDF KG3 exportée : kg3.ttl")

# ======================== 4. ALIGNEMENT PAR SIMILARITÉ ========================
model = SentenceTransformer("all-MiniLM-L6-v2")

def align_cve_nodes():
    cve_nvd = list(graph.nodes.match("CVE").where("_.source = 'NVD'"))
    cve_nessus = list(graph.nodes.match("CVE").where("_.source = 'Nessus'"))
    nvd_dict = {cve["name"]: cve for cve in cve_nvd}
    count_exact, count_fuzzy, count_embed = 0, 0, 0
    for nessus_cve in cve_nessus:
        name = nessus_cve.get("name")
        if not name:
            continue
        if name in nvd_dict:
            graph.merge(Relationship(nessus_cve, "SAME_AS", nvd_dict[name]))
            count_exact += 1
            continue
        best_match, best_score = None, 0
        for nvd_name in nvd_dict:
            score = fuzz.ratio(name, nvd_name)
            if score > best_score:
                best_score = score
                best_match = nvd_dict[nvd_name]
        if best_score > 90:
            graph.merge(Relationship(nessus_cve, "SAME_AS", best_match))
            count_fuzzy += 1
            continue
        desc1 = nessus_cve.get("description", "")
        desc2 = best_match.get("description", "") if best_match else ""
        if desc1 and desc2:
            emb1 = model.encode(desc1, convert_to_tensor=True)
            emb2 = model.encode(desc2, convert_to_tensor=True)
            sim = util.cos_sim(emb1, emb2).item()
            if sim > 0.85:
                graph.merge(Relationship(nessus_cve, "SAME_AS", best_match))
                count_embed += 1
    print(f"✅ Alignement : {count_exact} exacts, {count_fuzzy} fuzzy, {count_embed} embeddings.")

# ======================== 5. FUSION NODES & RELATIONS ========================
def merge_nodes(primary_node, secondary_node):
    for k, v in secondary_node.items():
        if k not in primary_node or not primary_node[k]:
            primary_node[k] = v
    graph.push(primary_node)
    for rel in graph.match(nodes=[secondary_node]):
        graph.merge(Relationship(primary_node, type(rel).__name__, rel.end_node))
        graph.separate(rel)
    for rel in graph.match(nodes=[None, secondary_node]):
        graph.merge(Relationship(rel.start_node, type(rel).__name__, primary_node))
        graph.separate(rel)
    graph.delete(secondary_node)

def fuse_cve_same_as():
    pairs = graph.run("""
    MATCH (c:CVE)-[:SAME_AS]->(c2:CVE)
    RETURN DISTINCT c.name AS name1, c2.name AS name2
    """).data()

    matched = set()
    for pair in pairs:
        name1, name2 = pair["name1"], pair["name2"]
        key = tuple(sorted([name1, name2]))
        if key in matched:
            continue
        matched.add(key)

        unified_name = name1 if name1 < name2 else name2
        unified_node = graph.nodes.match("CVE_UNIFIED", name=unified_name).first()
        if not unified_node:
            unified_node = Node("CVE_UNIFIED", name=unified_name)
            graph.create(unified_node)

        for name in [name1, name2]:
            node = graph.nodes.match("CVE", name=name).first()
            if node:
                for key in ["cvssScore", "description", "published", "lastModified"]:
                    if key in node and (key not in unified_node or unified_node[key] is None):
                        unified_node[key] = node[key]
                graph.merge(Relationship(unified_node, "SAME_AS", node))

        graph.push(unified_node)

# ======================== 6. AUTRES ALIGNEMENTS ========================
def align_and_merge_vendors_products():
    for label in ["Vendor", "Product"]:
        nessus_nodes = graph.nodes.match(label).where("_.source = 'Nessus'")
        for n_nessus in nessus_nodes:
            n_nvd = graph.nodes.match(label, name=n_nessus["name"], source="NVD").first()
            if n_nvd:
                if not graph.relationships.match((n_nessus, n_nvd), "SAME_AS").first():
                    graph.create(Relationship(n_nessus, "SAME_AS", n_nvd))
                merge_nodes(n_nvd, n_nessus)

def update_plugin_cve_relations():
    plugins = graph.nodes.match("Plugin").where("_.source = 'Nessus'")
    for plugin in plugins:
        for rel in list(graph.match((plugin,), r_type="detects")):
            cve_nessus = rel.end_node
            cve_nvd = graph.nodes.match("CVE", name=cve_nessus["name"], source="NVD").first()
            if cve_nvd and cve_nvd != cve_nessus:
                graph.separate(rel)
                graph.merge(Relationship(plugin, "detects", cve_nvd))
                if not graph.relationships.match((plugin, cve_nvd), "hasCVE").first():
                    graph.create(Relationship(plugin, "hasCVE", cve_nvd))

# ======================== 7. ENRICHISSEMENTS CYBER ========================
def create_network_links():
    graph.run("""
    MATCH (h1:Host), (h2:Host)
    WHERE h1.name <> h2.name AND split(h1.name, '.')[0..3] = split(h2.name, '.')[0..3]
    MERGE (h1)-[:COMMUNICATES_WITH]->(h2)
    """)

def recommend_patches():
    graph.run("""
    MATCH (c:CVE_UNIFIED)<-[:SAME_AS]-(:CVE)<-[:VULNERABLE_TO]-(h:Host)
    WITH DISTINCT h, c
    MERGE (p:Patch {name: 'apply-' + c.name})
    MERGE (h)-[:RECOMMENDED_ACTION]->(p)
    MERGE (c)-[:MITIGATED_BY]->(p)
    """)

def add_network_segments():
    graph.run("""
    MATCH (h:Host)
    WITH h, split(h.name, '.') AS parts
    WHERE size(parts) >= 3 AND h.name =~ '\\d+\\.\\d+\\.\\d+\\.\\d+'
    WITH h, parts[0] + '.' + parts[1] + '.' + parts[2] + '.0/24' AS subnet
    MERGE (s:Network_Segment {name: subnet})
    MERGE (h)-[:BELONGS_TO]->(s)
    """)

def enrich_impacts_relations():
    graph.run("""
    MATCH (c:CVE_UNIFIED)<-[:SAME_AS]-(:CVE)
    MATCH (s:Service)
    WHERE s.name CONTAINS c.name
    MERGE (c)-[:IMPACTS]->(s)
    """)

def debug_invalid_hosts():
    res = graph.run("""
    MATCH (h:Host)
    WHERE size(split(h.name, '.')) < 3 OR h.name IS NULL
    RETURN h.name AS invalid_host
    """).data()
    if res:
        print("⚠️ Hosts invalides :")
        for r in res:
            print("-", r["invalid_host"])

# ======================== 8. MAIN ========================
def main():
    align_cve_nodes()
    fuse_cve_same_as()
    align_and_merge_vendors_products()
    update_plugin_cve_relations()
    create_network_links()
    recommend_patches()
    add_network_segments()
    enrich_impacts_relations()  # ✅ appel ajout relation IMPACTS
    debug_invalid_hosts()
    print("✅ Pipeline de fusion CSKG1 + CSKG2 terminé avec enrichissement.")

if __name__ == "__main__":
    main()

