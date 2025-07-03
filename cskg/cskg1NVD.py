from py2neo import Graph, Node, Relationship
from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, Literal, URIRef
from transformers import pipeline
import requests
import time

# --- Connexion locale Neo4j ---
uri = "bolt://localhost:7687"
user = "neo4j"
password = "Hanen123"
graph = Graph(uri, auth=(user, password))

try:
    info = graph.run("RETURN 1").data()
    print("Connexion Neo4j locale réussie :", info)
except Exception as e:
    print("Erreur de connexion Neo4j :", e)

# --- RDF Namespaces ---
rdf_graph = RDFGraph()
STUCO = Namespace("http://w3id.org/sepses/vocab/ref/stuco#")
CYBER = Namespace("http://example.org/cyber#")
rdf_graph.bind("stuco", STUCO)
rdf_graph.bind("cyber", CYBER)

# --- NER pipeline ---
ner = pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple")

# --- Fonction API NVD ---
def fetch_cve_nvd(start=0, results_per_page=2000):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    response.raise_for_status()
    return response.json()

# --- Insertion CVE + relations dans Neo4j ---
def insert_cve_neo4j(item):
    cve_id = item["cve"]["id"]
    descriptions = item["cve"].get("descriptions", [])
    description = descriptions[0]["value"] if descriptions else ""
    published = item["cve"].get("published")
    last_updated = item["cve"].get("lastModified") or published
    
    year = None
    if published:
        year = int(published[:4])

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

    # CVSS Metrics (version 3.1 prioritaire)
    try:
        metrics = item["cve"].get("metrics", {})
        if "cvssMetricV31" in metrics:
            data = metrics["cvssMetricV31"][0]["cvssData"]
            cve_node["cvss_score"] = data["baseScore"]
            cve_node["severity"] = data["baseSeverity"]
            cve_node["attackVector"] = data.get("attackVector")
            cve_node["privilegesRequired"] = data.get("privilegesRequired")
            cve_node["userInteraction"] = data.get("userInteraction")
            cve_node["scope"] = data.get("scope")
            cve_node["confidentialityImpact"] = data.get("confidentialityImpact")
            cve_node["integrityImpact"] = data.get("integrityImpact")
            cve_node["availabilityImpact"] = data.get("availabilityImpact")
            cve_node["vectorString"] = data.get("vectorString")
        elif "cvssMetricV30" in metrics:
            data = metrics["cvssMetricV30"][0]["cvssData"]
            cve_node["cvss_score"] = data["baseScore"]
            cve_node["severity"] = data["baseSeverity"]
            cve_node["vectorString"] = data.get("vectorString")
    except Exception as e:
        print(f"⚠️ Problème CVSS sur {cve_id} : {e}")

    graph.merge(cve_node, "CVE", "name")

    # RDF triples CVE
    rdf_cve = URIRef(cve_node["uri"])
    rdf_graph.add((rdf_cve, RDF.type, STUCO.Vulnerability))
    rdf_graph.add((rdf_cve, RDFS.label, Literal(cve_id)))
    rdf_graph.add((rdf_cve, RDFS.comment, Literal(description)))

    # --- CPE (configurations) ---
    configurations = item["cve"].get("configurations", {}).get("nodes", [])
    for node in configurations:
        cpe_matches = node.get("cpeMatch", [])
        for cpe_entry in cpe_matches:
            cpe_uri = cpe_entry.get("criteria")
            if cpe_uri:
                cpe_id = cpe_uri.replace(":", "_").replace(" ", "_")
                cpe_node = Node("CPE", name=cpe_uri, source="NVD", uri=f"http://example.org/cpe/{cpe_id}")
                graph.merge(cpe_node, "CPE", "name")
                graph.merge(Relationship(cve_node, "AFFECTS", cpe_node))

    # --- CWE (faiblesses) ---
    weaknesses = item["cve"].get("weaknesses", [])
    for weakness in weaknesses:
        descs = weakness.get("description", [])
        for d in descs:
            cwe_id = d.get("value")
            if cwe_id:
                cwe_node = Node("CWE", name=cwe_id, source="NVD", uri=f"http://example.org/cwe/{cwe_id.replace(' ', '_')}")
                graph.merge(cwe_node, "CWE", "name")
                graph.merge(Relationship(cve_node, "HAS_WEAKNESS", cwe_node))

    # --- CAPEC (patterns d’attaque) ---
    capec_list = item["cve"].get("capec", [])
    for capec in capec_list:
        capec_id = capec.get("id") or capec.get("capecId") or capec.get("name")
        if capec_id:
            capec_node = Node("CAPEC", name=capec_id, source="NVD", uri=f"http://example.org/capec/{capec_id.replace(' ', '_')}")
            graph.merge(capec_node, "CAPEC", "name")
            graph.merge(Relationship(cve_node, "EXPLOITS", capec_node))

    # --- NER (optionnel) sur description ---
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


def pipeline_cve_all_years():
    print("🚀 Extraction CVE NVD 1999-2025...")
    start = 0
    batch_size = 2000
    total_results = 1

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
                time.sleep(0.1)  # Respect API rate limits
            except Exception as e:
                print(f"[!] Erreur sur {item['cve']['id']}: {e}")

        print(f"✅ {count} CVE insérées ou mises à jour dans ce batch.")
        start += batch_size

    rdf_graph.serialize(destination="kg1.ttl", format="turtle")
    print("✅ KG1 RDF sauvegardé dans kg1.ttl")

if __name__ == "__main__":
    pipeline_cve_all_years()

