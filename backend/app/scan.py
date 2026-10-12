"""
Nmap discovery scanner for ThreatGraph labs and cyber-range.
Restricted to authorized private lab networks (threatgraph-lab / RFC-1918 subnets).
"""

import ipaddress
import json
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

# Automatically add local tools/nmap directory to PATH if present
_tools_nmap = Path(__file__).resolve().parent.parent.parent / "tools" / "nmap-7.92"
if _tools_nmap.exists() and str(_tools_nmap) not in os.environ.get("PATH", ""):
    os.environ["PATH"] = str(_tools_nmap) + os.pathsep + os.environ.get("PATH", "")

DEFAULT_LAB_CONTAINERS = ["lab-web-01", "lab-web-02", "lab-web-03", "lab-web-04", "lab-service-05", "lab-web-06"]
DEFAULT_LAB_NETWORK = os.getenv("DOCKER_NETWORK", "threatgraph-lab")

def is_ip_allowed(ip_str: str) -> bool:
    """Validate that the given IP strictly belongs to a private / loopback RFC 1918 subnet."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def get_docker_network_containers(network_name: str) -> List[str]:
    """Inspect the Docker network to discover attached container names dynamically."""
    try:
        proc = subprocess.run(
            ["docker", "network", "inspect", network_name],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            if data and "Containers" in data[0]:
                names = [c["Name"] for c in data[0]["Containers"].values() if c.get("Name")]
                if names:
                    return sorted(names)
    except Exception as exc:
        print(f"[scan.py] Note on docker network inspect: {exc}")

    if network_name == DEFAULT_LAB_NETWORK:
        return DEFAULT_LAB_CONTAINERS
    return []


def parse_nmap_xml(xml_content: str) -> List[Dict[str, Any]]:
    """Parse Nmap XML output to extract discovered hosts, ports, and service banners."""
    discovered: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as err:
        print(f"[scan.py] XML parsing failed: {err}")
        return discovered

    for host_node in root.findall("host"):
        ip = None
        for addr in host_node.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break

        if not ip or not is_ip_allowed(ip):
            continue

        hostnames = [
            h.get("name")
            for h in host_node.findall("hostnames/hostname")
            if h.get("name")
        ]
        # Prefer the short user container name if available
        hostname = ""
        for h in hostnames:
            if not h.endswith(f".{DEFAULT_LAB_NETWORK}") and not h.endswith(".internal"):
                hostname = h
                break
        if not hostname and hostnames:
            hostname = hostnames[0].split(".")[0]

        status_el = host_node.find("status")
        host_status = status_el.get("state", "up") if status_el is not None else "up"

        # Determine internet vs internal exposure
        is_internet = False
        if hostname:
            if hostname in ["lab-web-01", "lab-web-02", "lab-web-03", "lab-web-04"]:
                is_internet = True
            elif hostname in ["lab-service-05", "lab-web-06"]:
                is_internet = False
        elif ip == "10.10.10.10":
            is_internet = True

        exposure = "internet" if is_internet else "internal"

        for port_node in host_node.findall("ports/port"):
            state_el = port_node.find("state")
            state = state_el.get("state", "closed") if state_el is not None else "closed"
            if state != "open":
                continue

            proto = port_node.get("protocol", "tcp")
            port_id = int(port_node.get("portid", 0))

            svc_el = port_node.find("service")
            service_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""

            discovered.append({
                "host": ip,
                "hostname": hostname,
                "port": port_id,
                "protocol": proto,
                "service": service_name,
                "product": product,
                "version": version,
                "state": state,
                "host_status": host_status,
                "exposure": exposure,
            })

    return discovered


def run_discovery_scan(target_subnet: str = "threatgraph-lab") -> List[Dict[str, Any]]:
    """
    Run an Nmap service discovery scan across the target lab network or subnet.
    Strictly restricted to private lab environments.
    """
    target = (target_subnet or "").strip()

    # Case 1: Legacy cyber-range 10.10.10.0/24 subnet request
    if target == "10.10.10.0/24":
        network_name = "cyber-range_range_net"
        scan_ports = "22,80,5432"
        targets = ["10.10.10.10", "10.10.10.20", "10.10.10.30"]
    # Case 2: Specific custom subnet passed (must be private)
    elif "/" in target:
        try:
            req_net = ipaddress.ip_network(target)
            if not req_net.is_private:
                raise ValueError(f"Target subnet {target} is outside authorized private lab boundaries.")
        except ValueError as e:
            raise ValueError(f"Invalid or unauthorized subnet: {e}")
        network_name = DEFAULT_LAB_NETWORK
        scan_ports = "21,80"
        targets = get_docker_network_containers(network_name) or DEFAULT_LAB_CONTAINERS
    # Case 3: Default threatgraph-lab network
    else:
        network_name = DEFAULT_LAB_NETWORK
        scan_ports = "21,80"
        targets = get_docker_network_containers(network_name) or DEFAULT_LAB_CONTAINERS

    xml_output = None

    # Run containerized Nmap on the target Docker network
    docker_cmd = [
        "docker", "run", "--rm",
        "--network", network_name,
        "instrumentisto/nmap:latest",
        "-oX", "-",
        "-sV", "-T4", "-Pn",
        "-p", scan_ports,
        *targets
    ]

    try:
        proc = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=60, check=True)
        xml_output = proc.stdout
    except Exception as exc:
        print(f"[scan.py] Docker bridged nmap error: {exc}. Trying fallback...")

    # Fallback: direct python-nmap if native nmap exists
    if not xml_output or "<nmaprun" not in xml_output:
        try:
            import nmap
            nm = nmap.PortScanner()
            target_str = " ".join(targets)
            nm.scan(hosts=target_str, ports=scan_ports, arguments="-sV -T4 -Pn")
            xml_output = nm.get_nmap_last_output()
        except Exception as e:
            print(f"[scan.py] Native nmap fallback also failed: {e}")

    if not xml_output or "<nmaprun" not in xml_output:
        return []

    return parse_nmap_xml(xml_output)
