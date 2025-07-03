# ======================== 1. IMPORTS ========================
from py2neo import Graph, Node, Relationship
from transformers import pipeline
from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal, URIRef
import requests
import time

# ======================== 2. CONNEXION NEO4J DESKTOP ========================
from py2neo import Graph

uri = "bolt://127.0.0.1:7687"
user = "neo4j"
password = "Hanen123"
graph = Graph(uri, auth=(user, password))

# Test de connexion simple
print(graph.run("RETURN 1").data())



# ======================== 3. ONTOLOGIE RDF ========================
rdf_graph = RDFGraph()
UCO = Namespace("https://ontology.unifiedcyberontology.org/uco#")
STUCO = Namespace("http://w3id.org/sepses/vocab/ref/stuco#")
CYBER = Namespace("http://example.org/cyber#")
CWE = Namespace("https://cwe.mitre.org/data/definitions/")
CPE = Namespace("http://example.org/cpe#")
CAPEC = Namespace("https://capec.mitre.org/data/definitions/")

rdf_graph.bind("uco", UCO)
rdf_graph.bind("stuco", STUCO)
rdf_graph.bind("cyber", CYBER)
rdf_graph.bind("cwe", CWE)
rdf_graph.bind("cpe", CPE)
rdf_graph.bind("capec", CAPEC)

classes = [
    ("CVE", STUCO.Vulnerability), ("CWE", STUCO.Weakness), ("CPE", STUCO.Platform),
    ("Entity", CYBER.Entity), ("CAPEC", CYBER.CAPEC), ("Vendor", CYBER.Vendor),
    ("Product", CYBER.Product), ("Version", CYBER.Version), ("Patch", CYBER.Patch)
]
for label, uri in classes:
    rdf_graph.add((uri, RDF.type, OWL.Class))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

rdf_graph.add((CYBER.vectorString, RDF.type, OWL.DatatypeProperty))
rdf_graph.add((CYBER.baseScore, RDF.type, OWL.DatatypeProperty))
rdf_graph.add((CYBER.cvssRiskLevel, RDF.type, OWL.DatatypeProperty))

# ======================== 4. NER AVEC BERT ========================
ner = pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple")

# ======================== 5. UTIL ========================
def parse_cpe(cpe_uri):
    try:
        parts = cpe_uri.split(":")
        return {
            "part": parts[2],
            "vendor": parts[3],
            "product": parts[4],
            "version": parts[5] if len(parts) > 5 else "unknown"
        }
    except:
        return {}

def classify_risk(score):
    if score >= 9: return "CRITICAL"
    elif score >= 7: return "HIGH"
    elif score >= 4: return "MEDIUM"
    elif score > 0: return "LOW"
    return "NONE"

# ======================== 6. FETCH NVD DATA ========================
def fetch_cve_nvd(start=0, results_per_page=20):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    return response.json()

# ======================== 7. INSERTION ENRICHIE ========================
def insert_cve_neo4j(item):
    cve_id = item["cve"]["id"]
    description = item["cve"]["descriptions"][0]["value"]
    published = item["cve"].get("published")
    last_updated = item["cve"].get("lastModified") or published

    cve_node = Node("CVE", name=cve_id, description=description, source="NVD")
    if published: cve_node["published"] = published
    if last_updated: cve_node["lastUpdated"] = last_updated
    cve_node["uri"] = f"http://example.org/cve/{cve_id}"
    rdf_cve = URIRef(cve_node["uri"])

    cvss_data = item["cve"].get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        if key in cvss_data:
            cvss = cvss_data[key][0].get("cvssData", {})
            score = cvss.get("baseScore")
            risk = classify_risk(score) if score is not None else None

            cve_node.update({
                "cvssVersion": key,
                "cvssBaseScore": score,
                "attackVector": cvss.get("attackVector"),
                "attackComplexity": cvss.get("attackComplexity"),
                "privilegesRequired": cvss.get("privilegesRequired"),
                "userInteraction": cvss.get("userInteraction"),
                "confidentialityImpact": cvss.get("confidentialityImpact"),
                "integrityImpact": cvss.get("integrityImpact"),
                "availabilityImpact": cvss.get("availabilityImpact"),
                "vectorString": cvss.get("vectorString"),
                "cvssRiskLevel": risk
            })
            rdf_graph.add((rdf_cve, CYBER.vectorString, Literal(cvss.get("vectorString"))))
            rdf_graph.add((rdf_cve, CYBER.baseScore, Literal(score)))
            rdf_graph.add((rdf_cve, CYBER.cvssRiskLevel, Literal(risk)))
            break

    graph.merge(cve_node, "CVE", "name")
    rdf_graph.add((rdf_cve, RDF.type, STUCO.Vulnerability))
    rdf_graph.add((rdf_cve, RDFS.label, Literal(cve_id)))
    rdf_graph.add((rdf_cve, RDFS.comment, Literal(description)))

    for weakness in item["cve"].get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_id = desc["value"]
            if "CWE" in cwe_id:
                cwe_node = Node("CWE", name=cwe_id, source="NVD")
                graph.merge(cwe_node, "CWE", "name")
                graph.merge(Relationship(cve_node, "associatedWith", cwe_node))
                rdf_cwe = URIRef(f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html")
                rdf_graph.add((rdf_cwe, RDF.type, STUCO.Weakness))
                rdf_graph.add((rdf_cwe, RDFS.label, Literal(cwe_id)))
                rdf_graph.add((rdf_cve, CYBER.associatedWith, rdf_cwe))

    for config in item["cve"].get("configurations", [{}])[0].get("nodes", []):
        for cpe in config.get("cpeMatch", []):
            cpe_uri = cpe["criteria"]
            cpe_node = Node("CPE", name=cpe_uri, source="NVD")
            graph.merge(cpe_node, "CPE", "name")
            graph.merge(Relationship(cve_node, "affects", cpe_node))

            parsed = parse_cpe(cpe_uri)
            vendor_node = Node("Vendor", name=parsed["vendor"], source="NVD")
            product_node = Node("Product", name=parsed["product"], source="NVD")
            version_node = Node("Version", name=parsed["version"], source="NVD")

            graph.merge(vendor_node, "Vendor", "name")
            graph.merge(product_node, "Product", "name")
            graph.merge(version_node, "Version", "name")
            graph.merge(Relationship(product_node, "hasVersion", version_node))
            graph.merge(Relationship(product_node, "publishedBy", vendor_node))
            graph.merge(Relationship(cpe_node, "identifies", product_node))
            graph.merge(Relationship(product_node, "hasCVE", cve_node))

            rdf_cpe = URIRef(f"http://example.org/cpe#{cpe_uri}")
            rdf_graph.add((rdf_cpe, RDF.type, STUCO.Platform))
            rdf_graph.add((rdf_cpe, RDFS.label, Literal(cpe_uri)))
            rdf_graph.add((rdf_cve, CYBER.affects, rdf_cpe))

    for ref in item["cve"].get("references", []):
        url = ref.get("url", "")
        if "CAPEC-" in url:
            capec_id = "CAPEC-" + url.split("CAPEC-")[-1].split(".")[0]
            capec_node = Node("CAPEC", name=capec_id, source="NVD")
            graph.merge(capec_node, "CAPEC", "name")
            graph.merge(Relationship(cve_node, "hasCapec", capec_node))
            capec_url = f"https://capec.mitre.org/data/definitions/{capec_id.replace('CAPEC-', '')}.html"
            rdf_capec = URIRef(capec_url)
            rdf_graph.add((rdf_capec, RDF.type, CYBER.CAPEC))
            rdf_graph.add((rdf_capec, RDFS.label, Literal(capec_id)))
            rdf_graph.add((rdf_cve, CYBER.hasCAPEC, rdf_capec))

    try:
        entities = ner(description)
        for ent in entities:
            word = ent["word"]
            ent_type = ent["entity_group"]
            ent_node = Node("Entity", name=word, entityType=ent_type, source="NVD")
            graph.merge(ent_node, "Entity", "name")
            graph.merge(Relationship(cve_node, "mentions", ent_node))
    except Exception as e:
        print(f"⚠️ NER erreur sur {cve_id}: {e}")

# ======================== 8. PIPELINE COMPLETE ========================
def pipeline_kg1_all(start_year=1999, end_year=2025, page_size=2000):
    start_index = 0
    while True:
        print(f"📦 Traitement à partir de l'index {start_index}")
        data = fetch_cve_nvd(start=start_index, results_per_page=page_size)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print("✅ Fin des données.")
            break
        for item in vulns:
            try:
                cve_id = item["cve"]["id"]
                year = int(cve_id.split("-")[1])
                if start_year <= year <= end_year:
                    insert_cve_neo4j(item)
                    time.sleep(0.2)
            except Exception as e:
                print(f"[!] Erreur: {e}")
        start_index += page_size
    rdf_graph.serialize(destination="kg1.ttl", format="turtle")
    print("✅ Insertion terminée et RDF sauvegardé.")

# ======================== 9. EXECUTION ========================
if __name__ == "__main__":
    pipeline_kg1_all(start_year=1999, end_year=2025, page_size=2000)


