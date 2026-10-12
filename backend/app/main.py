from typing import Any, Dict, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .db import run_query, init_schema, get_driver
from .scan import run_discovery_scan
from .graph_build import ingest_discovered_services

app = FastAPI(
    title="ThreatGraph API",
    description="Attack Graph Analysis & Multi-Stage Risk Scoring Platform",
    version="0.2.0"
)

# Enable CORS for local Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    try:
        init_schema()
    except Exception as e:
        print(f"[Warning] Could not initialize Neo4j schema on startup: {e}")


@app.get("/health")
def health_check():
    """Health endpoint that validates Neo4j connectivity via RETURN 1."""
    try:
        result = run_query("RETURN 1 AS status")
        if result and result[0].get("status") == 1:
            return {"status": "ok", "neo4j": "connected", "database": "healthy"}
        return {"status": "degraded", "neo4j": "unexpected_result"}
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Neo4j database connection failed: {str(e)}"
        )


class ScanRequest(BaseModel):
    target_subnet: str = "threatgraph-lab"


@app.post("/scan/start")
def start_scan(req: ScanRequest = ScanRequest()):
    """
    Trigger discovery scan on lab network (or specified subnet) and ingest findings into Neo4j.
    """
    try:
        services = run_discovery_scan(req.target_subnet)
        
        ingestion_stats = ingest_discovered_services(services)

        return {
            "status": "success",
            "target_subnet": req.target_subnet,
            "services_discovered_count": len(services),
            "services": services,
            "ingestion_stats": ingestion_stats,
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Discovery/Ingestion error: {str(e)}")


def compute_risk_score(cvss: float, epss: float, path_length: int, criticality_weight: float = 1.0) -> Dict[str, Any]:
    """
    Compute risk score according to ThreatGraph milestone formula:
    score = (cvss/10)*40 + epss*30 + (1/path_length)*10 + criticality_weight*20
    """
    cvss_component = (cvss / 10.0) * 40.0
    epss_component = epss * 30.0
    path_component = (1.0 / max(path_length, 1)) * 10.0
    crit_component = criticality_weight * 20.0
    total_score = round(cvss_component + epss_component + path_component + crit_component, 2)

    return {
        "total_score": total_score,
        "max_score": 100.0,
        "breakdown": {
            "cvss_component": round(cvss_component, 2),
            "cvss_value": cvss,
            "epss_component": round(epss_component, 2),
            "epss_value": epss,
            "path_component": round(path_component, 2),
            "path_length": path_length,
            "criticality_component": round(crit_component, 2),
            "criticality_weight": criticality_weight,
        }
    }


@app.get("/paths")
def get_attack_paths():
    """
    Query attack paths from internet-exposed hosts to crown-jewel assets
    and compute risk score for each path.
    """
    try:
        # Match all paths from internet-exposed Host to crown-jewel Asset
        query = """
        MATCH p = (start:Host {exposure: 'internet'})-[*1..10]->(target:Asset {criticality: 'crown-jewel'})
        RETURN p
        """
        driver = get_driver()
        paths_data = []

        with driver.session() as session:
            result = session.run(query)
            for record in result:
                path = record["p"]
                nodes = []
                for node in path.nodes:
                    node_dict = dict(node)
                    node_dict["_labels"] = list(node.labels)
                    nodes.append(node_dict)

                relationships = []
                for rel in path.relationships:
                    rel_dict = {
                        "type": rel.type,
                        "start_node_labels": list(rel.start_node.labels),
                        "end_node_labels": list(rel.end_node.labels),
                    }
                    relationships.append(rel_dict)

                # Extract vulnerability info along path if present
                cvss_val = 9.8  # Default fallback
                epss_val = 0.94
                for n in nodes:
                    if "Vulnerability" in n.get("_labels", []):
                        cvss_val = float(n.get("cvss", 9.8))
                        epss_val = float(n.get("epss", 0.94))

                path_length = len(relationships)
                risk_metrics = compute_risk_score(
                    cvss=cvss_val,
                    epss=epss_val,
                    path_length=path_length,
                    criticality_weight=1.0  # crown-jewel
                )

                paths_data.append({
                    "path_length": path_length,
                    "nodes_count": len(nodes),
                    "nodes": nodes,
                    "relationships": relationships,
                    "risk_score": risk_metrics["total_score"],
                    "risk_breakdown": risk_metrics["breakdown"],
                })

        return {
            "status": "success",
            "paths_found": len(paths_data),
            "paths": paths_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query attack paths: {str(e)}")
