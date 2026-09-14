import os
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv
from neo4j import GraphDatabase, Driver

# Automatically load .env if present
load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "threatgraphpassword")

_driver: Optional[Driver] = None


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    return _driver


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None


def run_query(query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Execute a Cypher query and return results as a list of dictionaries."""
    driver = get_driver()
    with driver.session() as session:
        result = session.run(query, params or {})
        return [record.data() for record in result]


def init_schema() -> None:
    """Ensure unique constraints exist on core node identifiers."""
    constraints = [
        "CREATE CONSTRAINT host_ip_unique IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE",
        "CREATE CONSTRAINT service_id_unique IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
        "CREATE CONSTRAINT vuln_cve_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE",
        "CREATE CONSTRAINT priv_id_unique IF NOT EXISTS FOR (p:PrivilegeState) REQUIRE p.id IS UNIQUE",
        "CREATE CONSTRAINT asset_id_unique IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
    ]
    for constraint in constraints:
        try:
            run_query(constraint)
        except Exception as e:
            # Community edition or older versions may handle constraint syntax variations
            print(f"[Schema Init] Note on constraint execution: {e}")
