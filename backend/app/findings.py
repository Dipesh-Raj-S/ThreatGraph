# Vulnerability finding fixture for ThreatGraph 

from typing import Any, Dict, List

HAND_CURATED_FINDINGS: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2021-41773",
        "title": "Apache HTTP Server 2.4.49 - Remote Code Execution via mod_cgi & Path Traversal",
        "description": (
            "A flaw in path normalization in Apache HTTP Server 2.4.49 allowed path traversal "
            "and, when mod_cgi is enabled with cgi-bin aliased, arbitrary command execution "
            "under the privileges of the web server daemon."
        ),
        "cvss": 9.8,
        # EPSS Score note: Calibrated static fixture value (94% probability).
        # Dynamic lookup via https://api.first.org/data/v1/epss?cve=... will replace this in Milestone 2.
        "epss": 0.94,
        "target_service_product": "Apache httpd",
        "target_service_version": "2.4.49",
        "privilege_granted": {
            "id": "priv-daemon-web",
            "level": "user",
            "description": "Remote Code Execution context as daemon",
        },
    },
    {
        "cve_id": "MISCONFIG-FTP-ANON",
        "title": "Pure-FTPd Anonymous Access & Synthetic Asset Disclosure",
        "description": (
            "Pure-FTPd daemon permits unauthenticated anonymous read access, "
            "exposing internal asset inventories and system topology data."
        ),
        "cvss": 7.5,
        "epss": 0.72,
        "target_service_product": "Pure-FTPd",
        "target_service_version": "",
        "privilege_granted": {
            "id": "priv-ftp-anon",
            "level": "guest",
            "description": "Unauthenticated read access to internal repository & asset catalog",
        },
    },
]


def get_finding_for_service(product: str, version: str) -> List[Dict[str, Any]]:
    """Match discovered service product & version against known findings."""
    matched = []
    prod_lower = (product or "").lower()
    ver_lower = (version or "").lower()

    for finding in HAND_CURATED_FINDINGS:
        target_prod = finding["target_service_product"].lower()
        target_ver = finding["target_service_version"].lower()

        if (target_prod in prod_lower or prod_lower in target_prod) and (
            target_ver in ver_lower or not target_ver
        ):
            matched.append(finding)

    return matched
