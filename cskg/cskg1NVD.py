# ======================== 1. IMPORTS ========================
from py2neo import Graph, Node, Relationship
from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal, URIRef
from transformers import pipeline
import requests
import time
from datetime import datetime


# ======================== 2. CONNEXION NEO4J ========================
uri = "bolt://localhost:7687"  # Connexion locale Neo4j
user = "neo4j"
password = "Hanen123"
graph = Graph(uri, auth=(user, password))

try:
    info = graph.run("RETURN 1").data()
    print("Connexion Neo4j locale réussie :", info)
except Exception as e:
    print("Erreur de connexion Neo4j :", e)

# ======================== 3. ONTOLOGIE RDF ========================
rdf_graph = RDFGraph()
STUCO = Namespace("http://w3id.org/sepses/vocab/ref/stuco#")
CYBER = Namespace("http://example.org/cyber#")
rdf_graph.bind("stuco", STUCO)
rdf_graph.bind("cyber", CYBER)

# ======================== 4. NER AVEC BERT ========================
ner = pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple")

# ======================== 5. API NVD ========================
def fetch_cve_nvd(start=0, results_per_page=2000):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    response.raise_for_status()
    return response.json()

# ======================== 6. INSERTION ========================
def insert_cve_neo4j(item):
    cve_id = item["cve"]["id"]
    descriptions = item["cve"].get("descriptions", [])
    description = descriptions[0]["value"] if descriptions else ""
    published = item["cve"].get("published")
    last_updated = item["cve"].get("lastModified") or published
    
    # Extraire l'année pour filtrer
    year = None
    if published:
        year = int(published[:4])

    # Ne pas insérer si hors plage
    if year is None or year < 1999 or year > 2025:
        return False

    existing_node = graph.nodes.match("CVE", name=cve_id).first()
    if existing_node:
        if existing_node.get("description") == description:
            print(f"⏭️ {cve_id} déjà présent et inchangé.")
            return True

    cve_node = Node("CVE", name=cve_id, description=description, source="NVD")
    cve_node["published"] = published
    cve_node["lastUpdated"] = last_updated
    cve_node["year"] = year
    cve_node["uri"] = f"http://example.org/cve/{cve_id}"

    # CVSS Metrics
    try:
        metrics = item["cve"].get("metrics", {})
        if "cvssMetricV31" in metrics:
            data = metrics["cvssMetricV31"][0]["cvssData"]
            cve_node["cvss_score"] = data["baseScore"]
            cve_node["severity"] = data["baseSeverity"]
            cve_node["attackVector"] = data.get("attackVector")
            cve_node["privilegesRequired"] = data.get("privilegesRequired")
            cve_node["userInteraction"] = data.get("userInteraction")
            cve_node["vectorString"] = data.get("vectorString")
    except Exception as e:
        print(f"⚠️ Problème CVSS sur {cve_id} : {e}")

    graph.merge(cve_node, "CVE", "name")

    rdf_cve = URIRef(cve_node["uri"])
    rdf_graph.add((rdf_cve, RDF.type, STUCO.Vulnerability))
    rdf_graph.add((rdf_cve, RDFS.label, Literal(cve_id)))
    rdf_graph.add((rdf_cve, RDFS.comment, Literal(description)))

    # NER sur la description (optionnel)
    try:
        entities = ner(description)
        for ent in entities:
            word = ent["word"]
            ent_type = ent["entity_group"]
            ent_node = Node("Entity", name=word, entityType=ent_type, source="NVD", uri=f"http://example.org/entity/{word.replace(' ', '_')}")
            graph.merge(ent_node, "Entity", "name")
            graph.merge(Relationship(cve_node, "mentions", ent_node))
    except Exception as e:
        print(f"⚠️ NER erreur sur {cve_id}: {e}")
    
    return True

# ======================== 7. PIPELINE ========================
def pipeline_cve_all_years():
    print("🚀 Extraction CVE NVD 1999-2025...")
    start = 0
    batch_size = 2000
    total_results = 1  # juste pour entrer dans la boucle

    while start < total_results:
        print(f"⬇️ Récupération CVE: startIndex={start}...")
        data = fetch_cve_nvd(start=start, results_per_page=batch_size)
        total_results = data.get("totalResults", 0)
        print(f"📊 Total CVE: {total_results}")

        count = 0
        for item in data.get("vulnerabilities", []):
            try:
                if insert_cve_neo4j(item):
                    count += 1
                time.sleep(0.1)  # Respect API NVD rate limit
            except Exception as e:
                print(f"[!] Erreur sur {item['cve']['id']}: {e}")

        print(f"✅ {count} CVE insérées ou mises à jour dans ce batch.")
        start += batch_size

    rdf_graph.serialize(destination="kg1.ttl", format="turtle")
    print("✅ KG1 RDF sauvegardé dans kg1.ttl")

# ======================== 8. EXÉCUTION ========================
if __name__ == "__main__":
    pipeline_cve_all_years()
