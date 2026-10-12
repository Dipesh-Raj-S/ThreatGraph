import React from "react";

interface PathRiskBreakdown {
    cvss_component: number | string;
    cvss_value: number | string;
    epss_component: number | string;
    epss_value: number | string;
    path_component: number | string;
    path_length: number | string;
    criticality_component: number | string;
}

interface PathItem {
    risk_score: number | string;
    risk_breakdown: PathRiskBreakdown;
}

interface PathRiskCardProps {
    paths?: PathItem[];
}

export default function PathRiskCard({ paths = [] }: PathRiskCardProps) {
    return (
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

                            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", background: "rgba(0,0,0,0.2)", padding: 12, borderRadius: 6, border: "1px solid var(--border)" }}>
                                <strong>Formula:</strong> <code>Score = (CVSS/10)*40 + EPSS*30 + (1/Path_Length)*10 + Criticality*20</code>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}