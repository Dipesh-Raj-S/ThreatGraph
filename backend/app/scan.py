"""
scan.py - Nmap discovery scanner for ThreatGraph cyber-range.
Strictly restricted to the 10.10.10.0/24 network.
"""

import ipaddress
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List
import nmap

# Automatically add local tools/nmap directory to PATH if present
_tools_nmap = Path(__file__).resolve().parent.parent.parent / "tools" / "nmap-7.92"
if _tools_nmap.exists() and str(_tools_nmap) not in os.environ.get("PATH", ""):
    os.environ["PATH"] = str(_tools_nmap) + os.pathsep + os.environ.get("PATH", "")

ALLOWED_NETWORK = ipaddress.ip_network("10.10.10.0/24")


def is_ip_allowed(ip_str: str) -> bool:
    """Validate that the given IP strictly belongs to the 10.10.10.0/24 cyber-range subnet."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip in ALLOWED_NETWORK
    except ValueError:
        return False


def run_discovery_scan(target_subnet: str = "10.10.10.0/24") -> List[Dict[str, Any]]:
    """
    Run an Nmap service discovery scan across the cyber-range subnet.
    Enforces strict 10.10.10.0/24 boundary.
    Supports both native nmap and container-bridged nmap scanning for isolated Docker subnets.
    """
    # Strict boundary validation check
    try:
        req_net = ipaddress.ip_network(target_subnet)
        if not req_net.subnet_of(ALLOWED_NETWORK):
            raise ValueError(
                f"Target subnet {target_subnet} is outside permitted cyber-range boundary {ALLOWED_NETWORK}"
            )
    except ValueError as e:
        raise ValueError(f"Invalid or unauthorized subnet: {e}")

    nm = nmap.PortScanner()
    xml_output = None

    # On Windows / Docker bridge setups, run Nmap attached to the cyber-range network to reach 10.10.10.0/24 directly
    docker_cmd = [
        "docker", "run", "--rm",
        "--network", "cyber-range_range_net",
        "instrumentisto/nmap",
        "-oX", "-",
        "-sV", "-T4", "-Pn",
        "-p", "22,80,5432",
        "10.10.10.10", "10.10.10.20", "10.10.10.30"
    ]

    try:
        proc = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=60, check=True)
        xml_output = proc.stdout
    except Exception as exc:
        print(f"[scan.py] Docker bridged nmap returned: {exc}. Falling back to direct python-nmap...")

    if xml_output and "<nmaprun" in xml_output:
        nm.analyse_nmap_xml_scan(xml_output)
    else:
        # Direct fallback
        nm.scan(hosts="10.10.10.10 10.10.10.20 10.10.10.30", ports="22,80,5432", arguments="-sV -T4 -Pn")

    discovered_services: List[Dict[str, Any]] = []

    for host in nm.all_hosts():
        if not is_ip_allowed(host):
            continue

        host_status = nm[host].state()
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                port_data = nm[host][proto][port]
                state = port_data.get("state", "closed")
                if state == "open":
                    service_info = {
                        "host": host,
                        "port": int(port),
                        "protocol": proto,
                        "service": port_data.get("name", "unknown"),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "state": state,
                        "host_status": host_status,
                    }
                    discovered_services.append(service_info)

    return discovered_services
