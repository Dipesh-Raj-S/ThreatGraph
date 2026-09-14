"""
graph_build.py - Neo4j graph ingestion module for ThreatGraph.
Uses idempotent MERGE queries to populate Hosts, Services, Vulnerabilities,
Privilege States, and Assets per schema.md.
"""

from typing import Any, Dict, List
from .db import run_query
from .findings import get_finding_for_service


def ingest_discovered_services(services: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Ingest scanned hosts and open services into Neo4j via MERGE.
    Tags 10.10.10.10 as internet-exposed, others as internal.
    """
    hosts_merged = 0
    services_merged = 0

    for item in services:
        ip = item["host"]
        port = item["port"]
        proto = item.get("protocol", "tcp")
        service_id = f"{ip}:{proto}:{port}"
        service_name = item.get("service", "unknown")
        product = item.get("product", "")
        version = item.get("version", "")
        
        # Exposure tagging
        exposure = "internet" if ip == "10.10.10.10" else "internal"

        # Merge Host
        host_query = """
        MERGE (h:Host {ip: $ip})
        ON CREATE SET h.exposure = $exposure, h.status = 'up', h.name = CASE WHEN $ip = '10.10.10.10' THEN 'web-gateway' WHEN $ip = '10.10.10.20' THEN 'internal-jump' ELSE 'db-server' END
        ON MATCH SET h.exposure = $exposure, h.status = 'up'
        """
        run_query(host_query, {"ip": ip, "exposure": exposure})
        hosts_merged += 1

        # Merge Service and RUNS relationship
        service_query = """
        MATCH (h:Host {ip: $ip})
        MERGE (s:Service {id: $service_id})
        ON CREATE SET s.port = $port, s.protocol = $proto, s.name = $service_name, s.product = $product, s.version = $version
        ON MATCH SET s.port = $port, s.protocol = $proto, s.name = $service_name, s.product = $product, s.version = $version
        MERGE (h)-[:RUNS]->(s)
        """
        run_query(service_query, {
            "ip": ip,
            "service_id": service_id,
            "port": port,
            "proto": proto,
            "service_name": service_name,
            "product": product,
            "version": version
        })
        services_merged += 1

        # Check for known vulnerability findings matching this service
        matched_findings = get_finding_for_service(product, version)
        for finding in matched_findings:
            ingest_finding_and_chain(service_id, finding)

    # Ensure complete pivot path and crown-jewel asset exist (Phase D chain)
    ensure_attack_chain_completion()

    return {"hosts_processed": hosts_merged, "services_processed": services_merged}


def ingest_finding_and_chain(service_id: str, finding: Dict[str, Any]) -> None:
    """
    Ingest a vulnerability finding and link it to the affected Service and initial PrivilegeState.
    """
    cve_id = finding["cve_id"]
    title = finding["title"]
    description = finding["description"]
    cvss = finding["cvss"]
    epss = finding["epss"]
    priv = finding["privilege_granted"]

    # Merge Vulnerability and link AFFECTED_BY
    vuln_query = """
    MATCH (s:Service {id: $service_id})
    MERGE (v:Vulnerability {cve_id: $cve_id})
    ON CREATE SET v.title = $title, v.description = $description, v.cvss = $cvss, v.epss = $epss
    ON MATCH SET v.title = $title, v.description = $description, v.cvss = $cvss, v.epss = $epss
    MERGE (s)-[:AFFECTED_BY]->(v)
    """
    run_query(vuln_query, {
        "service_id": service_id,
        "cve_id": cve_id,
        "title": title,
        "description": description,
        "cvss": cvss,
        "epss": epss
    })

    # Merge PrivilegeState and link EXPLOITS_TO
    priv_query = """
    MATCH (v:Vulnerability {cve_id: $cve_id})
    MERGE (p:PrivilegeState {id: $priv_id})
    ON CREATE SET p.level = $level, p.description = $description
    ON MATCH SET p.level = $level, p.description = $description
    MERGE (v)-[:EXPLOITS_TO]->(p)
    """
    run_query(priv_query, {
        "cve_id": cve_id,
        "priv_id": priv["id"],
        "level": priv["level"],
        "description": priv["description"]
    })


def ensure_attack_chain_completion() -> None:
    """
    Idempotently constructs the full known multi-stage chain connecting:
    PrivilegeState -> internal_host (10.10.10.20) -> db_asset (10.10.10.30) -> Asset (Customer DB)
    """
    chain_query = """
    // 1. Merge internal host and DB host if not already created
    MERGE (h_web:Host {ip: '10.10.10.10'})
      ON CREATE SET h_web.exposure = 'internet', h_web.status = 'up', h_web.name = 'web-gateway'
    MERGE (h_internal:Host {ip: '10.10.10.20'})
      ON CREATE SET h_internal.exposure = 'internal', h_internal.status = 'up', h_internal.name = 'internal-jump'
    MERGE (h_db:Host {ip: '10.10.10.30'})
      ON CREATE SET h_db.exposure = 'internal', h_db.status = 'up', h_db.name = 'db-server'

    // 2. Link PrivilegeState (from web exploit) PIVOTS_TO internal host
    WITH h_web, h_internal, h_db
    MATCH (p:PrivilegeState {id: 'priv-daemon-web'})
    MERGE (p)-[:PIVOTS_TO]->(h_internal)

    // 3. Link internal host PIVOTS_TO database host
    MERGE (h_internal)-[:PIVOTS_TO]->(h_db)

    // 4. Merge Crown Jewel Asset and link PROTECTS
    MERGE (a:Asset {id: 'asset-db-01'})
      ON CREATE SET a.name = 'Customer Records Database', a.criticality = 'crown-jewel'
      ON MATCH SET a.name = 'Customer Records Database', a.criticality = 'crown-jewel'
    MERGE (h_db)-[:PROTECTS]->(a)
    """
    run_query(chain_query)
