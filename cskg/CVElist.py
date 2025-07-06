# ======================== 1. IMPORTS ========================
from py2neo import Graph, Node, Relationship
from transformers import pipeline
from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal, URIRef
import requests
import time

# ======================== 2. CONNEXION NEO4J ========================
uri = "neo4j+s://1cb37128.databases.neo4j.io"
user = "neo4j"
password = "qUocbHeI6RTR3sqwFE6IhnAX5nk9N_KnQVFthB3E9S8"
graph = Graph(uri, auth=(user, password))

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

rdf_graph.add((CYBER.vectorString, RDF.type, OWL.DatatypeProperty))
rdf_graph.add((CYBER.baseScore, RDF.type, OWL.DatatypeProperty))
rdf_graph.add((CYBER.cvssRiskLevel, RDF.type, OWL.DatatypeProperty))
rdf_graph.add((CYBER["source"], RDF.type, OWL.DatatypeProperty))  # ✅ Correction ici

classes = [
    ("CVE", STUCO.Vulnerability), ("CWE", STUCO.Weakness), ("CPE", STUCO.Platform),
    ("Entity", CYBER.Entity), ("CAPEC", CYBER.CAPEC), ("Vendor", CYBER.Vendor),
    ("Product", CYBER.Product), ("Version", CYBER.Version), ("Patch", CYBER.Patch)
]
for label, uri in classes:
    rdf_graph.add((uri, RDF.type, OWL.Class))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

# ======================== 4. NER AVEC BERT ========================
ner = pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple")

# ======================== 5. LISTE CVE CIBLÉES ========================
target_cves = {
    "CVE-1999-0517", "CVE-1999-0524", "CVE-2003-0001", "CVE-2004-2761",
    "CVE-2005-4900", "CVE-2011-3525", "CVE-2012-1675", "CVE-2012-1708",
    "CVE-2013-2566", "CVE-2014-3566", "CVE-2015-0204", "CVE-2015-2808",
    "CVE-2015-6358", "CVE-2015-7255", "CVE-2015-7256", "CVE-2015-7276",
    "CVE-2015-8251", "CVE-2016-0800", "CVE-2016-2183"
}

# ======================== 6. UTIL ========================
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

def cve_exists_with_source_nvd(cve_id):
    query = """
    MATCH (c:CVE {name: $cve_id, source: 'NVD'}) RETURN c LIMIT 1
    """
    result = graph.run(query, cve_id=cve_id).data()
    return len(result) > 0

# ======================== 7. FETCH NVD DATA ========================
def fetch_cve_nvd(start=0, results_per_page=20):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    return response.json()

# ======================== 8. INSERTION ENRICHIE ========================
def insert_cve_neo4j(item):
    cve_id = item["cve"]["id"]
    try:
        year = int(cve_id.split("-")[1])
    except Exception:
        print(f"⚠️ Année invalide pour {cve_id}, passage")
        return

    # Filtrer sur année entre 2015 et 2016
    if year < 2015 or year > 2016:
        return
    if cve_id not in target_cves:
        return

    if cve_exists_with_source_nvd(cve_id):
        print(f"⛔ CVE {cve_id} déjà présente avec source='NVD'. Insertion ignorée.")
        return

    description = item["cve"]["descriptions"][0]["value"]
    published = item["cve"].get("published")
    last_updated = item["cve"].get("lastModified") or published

    cve_node = Node("CVE", name=cve_id, description=description, source="NVD")
    if published: cve_node["published"] = published
    if last_updated: cve_node["lastUpdated"] = last_updated
    cve_node["uri"] = f"http://example.org/cve/{cve_id}"
    rdf_cve = URIRef(cve_node["uri"])
    rdf_graph.add((rdf_cve, CYBER["source"], Literal("NVD")))

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

    graph.create(cve_node)
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

# ======================== 9. PIPELINE PAGINÉE ========================
def pipeline_kg1_pagination(max_pages=140, page_size=1000):
    for i in range(max_pages):
        start = i * page_size
        print(f"📦 Page {i+1} – récupération de {page_size} CVE à partir de {start}")
        data = fetch_cve_nvd(start=start, results_per_page=page_size)
        if not data.get("vulnerabilities"):
            print("✅ Fin des données.")
            break
        for item in data["vulnerabilities"]:
            try:
                insert_cve_neo4j(item)
                time.sleep(0.2)
            except Exception as e:
                print(f"[!] Erreur {item['cve']['id']}: {e}")
    rdf_graph.serialize(destination="kg1.ttl", format="turtle")
    print("✅ Neo4j & RDF mis à jour.")

# ======================== 10. EXECUTION ========================
if __name__ == "__main__":
    pipeline_kg1_pagination(max_pages=140, page_size=1000)



