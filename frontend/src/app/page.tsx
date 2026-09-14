"use client";

import React, { useState, useEffect } from "react";

const API_BASE = "http://localhost:8000";

interface ServiceItem {
  host: string;
  port: number;
  protocol: string;
  service: string;
  product: string;
  version: string;
  state: string;
}

interface PathNode {
  _labels: string[];
  ip?: string;
  name?: string;
  exposure?: string;
  id?: string;
  cve_id?: string;
  title?: string;
  cvss?: number;
  epss?: number;
  level?: string;
  description?: string;
  criticality?: string;
}

interface AttackPath {
  path_length: number;
  nodes_count: number;
  nodes: PathNode[];
  risk_score: number;
  risk_breakdown: {
    cvss_component: number;
    cvss_value: number;
    epss_component: number;
    epss_value: number;
    path_component: number;
    path_length: number;
    criticality_component: number;
    criticality_weight: number;
  };
}

export default function ThreatGraphDashboard() {
  const [health, setHealth] = useState<{ status: string; neo4j: string } | null>(null);
  const [loadingScan, setLoadingScan] = useState(false);
  const [loadingPath, setLoadingPath] = useState(false);
  const [services, setServices] = useState<ServiceItem[]>([]);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [logMsg, setLogMsg] = useState<string>("");

  useEffect(() => {
    fetchHealth();
  }, []);

  const fetchHealth = async () => {
    try {
      const res = await fetch(`${API_BASE}/health`);
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      } else {
        setHealth({ status: "error", neo4j: "disconnected" });
      }
    } catch {
      setHealth({ status: "offline", neo4j: "unreachable" });
    }
  };

  const handleRunScan = async () => {
    setLoadingScan(true);
    setLogMsg("Scanning cyber-range subnet 10.10.10.0/24 via Nmap...");
    try {
      const res = await fetch(`${API_BASE}/scan/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_subnet: "10.10.10.0/24" }),
      });
      const data = await res.json();
      if (res.ok) {
        setServices(data.services || []);
        setLogMsg(`Scan complete! Discovered ${data.services_discovered_count} services. Ingested into Neo4j.`);
        // Auto-fetch paths after scan
        await handleFetchPaths();
      } else {
        setLogMsg(`Scan failed: ${data.detail || "Unknown error"}`);
      }
    } catch (e: any) {
      setLogMsg(`Scan error: ${e.message}`);
    } finally {
      setLoadingScan(false);
    }
  };

  const handleFetchPaths = async () => {
    setLoadingPath(true);
    try {
      const res = await fetch(`${API_BASE}/paths`);
      const data = await res.json();
      if (res.ok) {
        setPaths(data.paths || []);
      } else {
        setLogMsg(`Path query error: ${data.detail}`);
      }
    } catch (e: any) {
      setLogMsg(`Path fetch error: ${e.message}`);
    } finally {
      setLoadingPath(false);
    }
  };

  const getNodeTitle = (node: PathNode) => {
    const label = node._labels?.[0] || "Node";
    if (label === "Host") return `Host: ${node.ip} (${node.name || node.exposure || "Node"})`;
    if (label === "Service") return `Service: ${node.name || "service"} (${node.product || ""} ${node.version || ""}) [Port ${node.port || ""}]`;
    if (label === "Vulnerability") return `Vulnerability: ${node.cve_id} (CVSS ${node.cvss})`;
    if (label === "PrivilegeState") return `Privilege State: ${node.description || node.level || "Access"}`;
    if (label === "Asset") return `Crown Jewel Asset: ${node.name || node.id} (${node.criticality})`;
    return label;
  };

  return (
    <div className="container">
      {/* Header */}
      <header>
        <div>
          <h1 style={{ fontSize: "1.75rem", fontWeight: 700, letterSpacing: "-0.5px" }}>
            ThreatGraph <span style={{ fontSize: "1rem", color: "var(--accent-blue)", fontWeight: 500 }}>20% Milestone</span>
          </h1>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.875rem", marginTop: 4 }}>
            Subnet: <code style={{ color: "var(--accent-cyan)" }}>10.10.10.0/24</code> &bull; Neo4j Attack Graph Analysis
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {health?.neo4j === "connected" ? (
            <span className="badge badge-green">&bull; Neo4j Connected</span>
          ) : (
            <span className="badge badge-red">&bull; Neo4j Offline</span>
          )}
          <button
            id="run-scan-btn"
            className="btn"
            onClick={handleRunScan}
            disabled={loadingScan || loadingPath}
          >
            {loadingScan ? "Scanning 10.10.10.0/24..." : "Run Discovery & Build Graph"}
          </button>
        </div>
      </header>

      {logMsg && (
        <div style={{ padding: "10px 14px", background: "rgba(59, 130, 246, 0.1)", border: "1px solid rgba(59, 130, 246, 0.2)", borderRadius: 6, fontSize: "0.875rem" }}>
          <strong>Status:</strong> {logMsg}
        </div>
      )}

      {/* Discovered Inventory Card */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Discovered Hosts & Services</div>
          <span className="badge">{services.length} Open Services</span>
        </div>
        {services.length === 0 ? (
          <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
            No discovery data yet. Click &quot;Run Discovery &amp; Build Graph&quot; to scan the cyber-range.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Target Host</th>
                <th>Port / Proto</th>
                <th>Service</th>
                <th>Product</th>
                <th>Version</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {services.map((s, idx) => (
                <tr key={idx}>
                  <td>
                    <strong>{s.host}</strong>
                    {s.host === "10.10.10.10" && <span className="badge" style={{ marginLeft: 8 }}>Internet</span>}
                    {s.host !== "10.10.10.10" && <span className="badge badge-purple" style={{ marginLeft: 8 }}>Internal</span>}
                  </td>
                  <td>{s.port}/{s.protocol}</td>
                  <td>{s.service}</td>
                  <td>{s.product || "—"}</td>
                  <td>{s.version || "—"}</td>
                  <td>
                    <span className="badge badge-green">{s.state}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Attack Path & Risk Scoring Grid */}
      <div className="grid-2">
        {/* Left Column: Attack Path Sequence */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Discovered Attack Chain</div>
            <span className="badge badge-red">{paths.length} Active Path(s)</span>
          </div>

          {paths.length === 0 ? (
            <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
              No attack paths generated. Run discovery to ingest graph nodes and compute paths.
            </p>
          ) : (
            <div>
              {paths.map((p, pIdx) => (
                <div key={pIdx}>
                  <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: 16 }}>
                    Path from <strong>Internet Entry Point</strong> to <strong>Crown-Jewel Asset</strong> (Length: {p.path_length} hops)
                  </p>
                  <div style={{ display: "flex", flexDirection: "column" }}>
                    {p.nodes.map((node, nIdx) => (
                      <div key={nIdx} className="path-step">
                        <div className="step-num">{nIdx + 1}</div>
                        <div className="step-content">
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                            <strong style={{ fontSize: "0.95rem" }}>{getNodeTitle(node)}</strong>
                            <span className="badge" style={{ textTransform: "uppercase" }}>{node._labels?.[0]}</span>
                          </div>
                          {node.cve_id && (
                            <p style={{ fontSize: "0.8rem", color: "var(--accent-red)", marginTop: 4 }}>
                              Exploits real vulnerability: {node.title}
                            </p>
                          )}
                          {node.description && (
                            <p style={{ fontSize: "0.8rem", color: "var(--text-secondary)", marginTop: 4 }}>
                              {node.description}
                            </p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Column: Risk Score & Breakdown */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Path Risk Score & Formula</div>
            <span className="badge badge-orange">Milestone Formula</span>
          </div>

          {paths.length === 0 ? (
            <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
              Risk score calculation will appear after path computation.
            </p>
          ) : (
            <div>
              {paths.map((p, pIdx) => (
                <div key={pIdx} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                  {/* Big Score Box */}
                  <div style={{ background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: 8, padding: 20, textAlign: "center" }}>
                    <span style={{ fontSize: "0.85rem", color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "1px" }}>
                      Calculated Path Risk Score
                    </span>
                    <div style={{ fontSize: "3rem", fontWeight: 800, color: "var(--accent-red)", margin: "8px 0" }}>
                      {p.risk_score} <span style={{ fontSize: "1.2rem", color: "var(--text-muted)", fontWeight: 400 }}>/ 100</span>
                    </div>
                    <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                      High Criticality Multi-Stage Attack Vector
                    </p>
                  </div>

                  {/* Metrics Grid */}
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                    <div className="metric-box">
                      <span className="metric-label">CVSS Factor (40%)</span>
                      <span className="metric-val">{p.risk_breakdown.cvss_component}</span>
                      <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                        Base: {p.risk_breakdown.cvss_value} / 10
                      </span>
                    </div>

                    <div className="metric-box">
                      <span className="metric-label">EPSS Factor (30%)</span>
                      <span className="metric-val">{p.risk_breakdown.epss_component}</span>
                      <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                        Prob: {p.risk_breakdown.epss_value} (94%)
                      </span>
                    </div>

                    <div className="metric-box">
                      <span className="metric-label">Path Proximity (10%)</span>
                      <span className="metric-val">{p.risk_breakdown.path_component}</span>
                      <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                        1 / {p.risk_breakdown.path_length} hops
                      </span>
                    </div>

                    <div className="metric-box">
                      <span className="metric-label">Criticality (20%)</span>
                      <span className="metric-val">{p.risk_breakdown.criticality_component}</span>
                      <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                        Crown-Jewel (Weight 1.0)
                      </span>
                    </div>
                  </div>

                  {/* Formula Note */}
                  <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", background: "rgba(0,0,0,0.2)", padding: 12, borderRadius: 6, border: "1px solid var(--border)" }}>
                    <strong>Formula:</strong> <code>Score = (CVSS/10)*40 + EPSS*30 + (1/Path_Length)*10 + Criticality*20</code>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
