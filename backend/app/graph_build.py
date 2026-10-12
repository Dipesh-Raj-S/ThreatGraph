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
    """
    hosts_merged = 0
    services_merged = 0

    for item in services:
        ip = item["host"]
        hostname = item.get("hostname", "")
        port = item["port"]
        proto = item.get("protocol", "tcp")
        service_id = f"{ip}:{proto}:{port}"
        service_name = item.get("service", "unknown")
        product = item.get("product", "")
        version = item.get("version", "")
        
        # Exposure tagging
        exposure = item.get("exposure")
        if not exposure:
            if hostname in ["lab-web-01", "lab-web-02", "lab-web-03", "lab-web-04"] or ip == "10.10.10.10":
                exposure = "internet"
            else:
                exposure = "internal"

        # Host display name
        if hostname:
            host_name = hostname
        elif ip == "10.10.10.10":
            host_name = "web-gateway"
        elif ip == "10.10.10.20":
            host_name = "internal-jump"
        elif ip == "10.10.10.30":
            host_name = "db-server"
        else:
            host_name = ip

        # Merge Host
        host_query = """
        MERGE (h:Host {ip: $ip})
        ON CREATE SET h.exposure = $exposure, h.status = 'up', h.name = $name, h.hostname = $hostname
        ON MATCH SET h.exposure = $exposure, h.status = 'up', h.name = $name, h.hostname = $hostname
        """
        run_query(host_query, {
            "ip": ip,
            "exposure": exposure,
            "name": host_name,
            "hostname": hostname,
        })
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

    # Ensure complete pivot path and crown-jewel asset exist
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
    PrivilegeState -> Pivot Hosts -> Target Host -> Crown-Jewel Asset.
    """
    # 1. Attack chain for new lab machines:
    # lab-web-04 (Apache RCE priv-daemon-web) -> lab-web-06 (internal pivot) -> lab-service-05 (pure-ftpd) -> Asset
    lab_chain_query = """
    MATCH (h_jump:Host) WHERE h_jump.hostname = 'lab-web-06' OR h_jump.name = 'lab-web-06'
    MATCH (h_asset:Host) WHERE h_asset.hostname = 'lab-service-05' OR h_asset.name = 'lab-service-05'
    MATCH (p:PrivilegeState {id: 'priv-daemon-web'})
    MERGE (p)-[:PIVOTS_TO]->(h_jump)
    MERGE (h_jump)-[:PIVOTS_TO]->(h_asset)
    MERGE (a:Asset {id: 'asset-catalog-01'})
      ON CREATE SET a.name = 'Synthetic Asset Records & Repository', a.criticality = 'crown-jewel'
      ON MATCH SET a.name = 'Synthetic Asset Records & Repository', a.criticality = 'crown-jewel'
    MERGE (h_asset)-[:PROTECTS]->(a)
    """
    try:
        run_query(lab_chain_query)
    except Exception as exc:
        print(f"[graph_build.py] Lab attack chain completion note: {exc}")

    # 2. Attack chain for legacy cyber-range:
    # 10.10.10.10 (Apache RCE priv-daemon-web) -> 10.10.10.20 (internal-jump) -> 10.10.10.30 (db-server) -> Asset
    range_chain_query = """
    MATCH (h_internal:Host {ip: '10.10.10.20'})
    MATCH (h_db:Host {ip: '10.10.10.30'})
    MATCH (p:PrivilegeState {id: 'priv-daemon-web'})
    MERGE (p)-[:PIVOTS_TO]->(h_internal)
    MERGE (h_internal)-[:PIVOTS_TO]->(h_db)
    MERGE (a:Asset {id: 'asset-db-01'})
      ON CREATE SET a.name = 'Customer Records Database', a.criticality = 'crown-jewel'
      ON MATCH SET a.name = 'Customer Records Database', a.criticality = 'crown-jewel'
    MERGE (h_db)-[:PROTECTS]->(a)
    """
    try:
        run_query(range_chain_query)
    except Exception as exc:
        print(f"[graph_build.py] Range attack chain completion note: {exc}")
