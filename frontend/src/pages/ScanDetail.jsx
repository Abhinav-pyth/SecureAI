import { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { scansAPI, reportsAPI } from '../api/client';
import { Shield, Download, ArrowLeft, ChevronDown, ChevronUp, AlertTriangle, CheckCircle } from 'lucide-react';
import toast from 'react-hot-toast';

function SeverityBadge({ severity }) {
    const s = (severity || 'informational').toLowerCase();
    return <span className={`badge badge-${s}`}>{severity}</span>;
}

function RiskRing({ score, level }) {
    const radius = 45;
    const circ = 2 * Math.PI * radius;
    const offset = circ - (score / 100) * circ;
    const color = score >= 75 ? '#ef4444' : score >= 50 ? '#f59e0b' : score >= 25 ? '#fbbf24' : '#10b981';

    return (
        <div className="risk-score-ring">
            <svg width="120" height="120" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r={radius} fill="none" stroke="var(--bg-glass)" strokeWidth="8" />
                <circle cx="60" cy="60" r={radius} fill="none" stroke={color} strokeWidth="8"
                    strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
                    style={{ transition: 'stroke-dashoffset 1s ease' }} />
            </svg>
            <div className="risk-score-text">
                <span className="risk-score-number" style={{ color }}>{score}</span>
                <span className="risk-score-label">{level}</span>
            </div>
        </div>
    );
}

function VulnCard({ finding }) {
    const [open, setOpen] = useState(false);
    const dotClass = `vuln-status-dot dot-${(finding.severity || 'informational').toLowerCase()}`;
    return (
        <div className="vuln-card">
            <div className="vuln-card-header" onClick={() => setOpen(v => !v)}>
                <div className={dotClass} />
                <span className="vuln-card-title">{finding.category || finding.name}</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginRight: 8 }}>{finding.owaspId}</span>
                <SeverityBadge severity={finding.severity} />
                {open ? <ChevronUp size={14} style={{ flexShrink: 0 }} /> : <ChevronDown size={14} style={{ flexShrink: 0 }} />}
            </div>
            {open && (
                <div className="vuln-card-body">
                    {finding.description && (
                        <div className="vuln-detail-row">
                            <div className="vuln-detail-label">Description</div>
                            <div className="vuln-detail-value">{finding.description}</div>
                        </div>
                    )}
                    {finding.evidence && (
                        <div className="vuln-detail-row">
                            <div className="vuln-detail-label">Evidence</div>
                            <div className="vuln-detail-value">{finding.evidence}</div>
                        </div>
                    )}
                    {finding.issues?.length > 0 && (
                        <div className="vuln-detail-row">
                            <div className="vuln-detail-label">Issues Found</div>
                            <div className="vuln-issues">
                                {finding.issues.map((issue, i) => (
                                    <div key={i} className="vuln-issue-item"><AlertTriangle size={12} style={{ flexShrink: 0, color: '#f59e0b' }} />{issue}</div>
                                ))}
                            </div>
                        </div>
                    )}
                    {finding.recommendation && (
                        <div className="vuln-detail-row">
                            <div className="vuln-detail-label">Recommendation</div>
                            <div className="vuln-detail-value" style={{ color: '#34d399' }}>{finding.recommendation}</div>
                        </div>
                    )}
                    {finding.cvssScore != null && (
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                            <span className="vuln-detail-label">CVSS Score:</span>
                            <span style={{ fontSize: '0.875rem', fontWeight: 700, color: finding.cvssScore >= 7 ? '#f87171' : finding.cvssScore >= 4 ? '#fbbf24' : '#34d399' }}>{finding.cvssScore.toFixed(1)}</span>
                        </div>
                    )}
                    {finding.autoPatch && (
                        <div className="vuln-detail-row mt-16" style={{ background: 'rgba(0,212,255,0.05)', padding: 12, borderRadius: 8, border: '1px solid rgba(0,212,255,0.2)' }}>
                            <div className="vuln-detail-label" style={{ color: 'var(--accent-cyan)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                                <span style={{ fontSize: '1.2rem' }}>✨</span> AI Auto-Patch Code
                            </div>
                            <pre style={{
                                background: '#0d1117',
                                padding: '12px',
                                borderRadius: '6px',
                                overflowX: 'auto',
                                fontSize: '0.8rem',
                                fontFamily: 'JetBrains Mono, monospace',
                                color: '#e5e7eb',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-all'
                            }}>
                                <code>{finding.autoPatch}</code>
                            </pre>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default function ScanDetail() {
    const { id } = useParams();
    const [scan, setScan] = useState(null);
    const [loading, setLoading] = useState(true);
    const [downloading, setDownloading] = useState(false);
    const [polling, setPolling] = useState(false);

    const fetchStatus = useCallback(async () => {
        try {
            const { data } = await scansAPI.status(id);
            setScan(prev => ({ ...prev, ...data }));
            return data.status;
        } catch { return 'error'; }
    }, [id]);

    const fetchResults = useCallback(async () => {
        try {
            const { data } = await scansAPI.results(id);
            setScan(data);
        } catch (err) { toast.error('Failed to load scan results'); }
    }, [id]);

    useEffect(() => {
        (async () => {
            setLoading(true);
            const { data } = await scansAPI.status(id);
            setScan(data);
            setLoading(false);
            if (data.status === 'complete' || data.status === 'failed') {
                if (data.status === 'complete') fetchResults();
            } else {
                setPolling(true);
            }
        })();
    }, [id]);

    useEffect(() => {
        if (!polling) return;
        const interval = setInterval(async () => {
            const status = await fetchStatus();
            if (status === 'complete') {
                clearInterval(interval);
                setPolling(false);
                await fetchResults();
            } else if (status === 'failed') {
                clearInterval(interval);
                setPolling(false);
                toast.error('Scan failed');
            }
        }, 2000);
        return () => clearInterval(interval);
    }, [polling, fetchStatus, fetchResults]);

    const downloadPdf = async () => {
        setDownloading(true);
        try {
            const { data } = await reportsAPI.downloadPdf(id);
            const url = window.URL.createObjectURL(new Blob([data], { type: 'application/pdf' }));
            const a = document.createElement('a');
            a.href = url;
            a.download = `security-report-${id.slice(0, 8)}.pdf`;
            a.click();
            window.URL.revokeObjectURL(url);
            toast.success('Report downloaded!');
        } catch { toast.error('Failed to download report'); }
        finally { setDownloading(false); }
    };

    if (loading) return <div className="page-wrapper"><div className="page-content"><div className="empty-state"><div className="spinner spinner-lg" /></div></div></div>;
    if (!scan) return null;

    const aiSummary = scan.ai_summary && typeof scan.ai_summary === 'object' ? scan.ai_summary : null;
    const findings = aiSummary?.findings || scan.results || [];
    const severitySummary = scan.severity_summary || {};
    const isRunning = scan.status === 'pending' || scan.status === 'running';

    return (
        <div className="page-wrapper">
            <div className="page-content">
                <div className="flex items-center gap-16 mb-32">
                    <Link to="/dashboard" className="btn btn-sm btn-secondary"><ArrowLeft size={14} /></Link>
                    <div style={{ flex: 1, minWidth: 0 }}>
                        <h1 style={{ fontSize: '1.3rem', marginBottom: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{scan.target_url}</h1>
                        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Scan ID: {scan.id}</p>
                    </div>
                    <span className={`badge badge-${scan.status}`}>{scan.status}</span>
                    {scan.status === 'complete' && (
                        <button id="download-report-btn" className="btn btn-secondary" onClick={downloadPdf} disabled={downloading}>
                            {downloading ? <span className="spinner" /> : <><Download size={14} /> Report</>}
                        </button>
                    )}
                </div>

                {/* Progress */}
                {(isRunning || scan.status === 'complete') && (
                    <div className="scan-progress-section mb-24">
                        <div className="flex items-center justify-between mb-16">
                            <h3 style={{ fontSize: '0.95rem' }}>{isRunning ? '🔍 Scanning in progress...' : '✅ Scan complete'}</h3>
                            <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--accent-cyan)' }}>{scan.progress || 0}%</span>
                        </div>
                        <div className="progress-bar-wrap">
                            <div className="progress-bar-fill" style={{ width: `${scan.progress || 0}%` }} />
                        </div>
                        {isRunning && <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 12 }} className="animate-pulse">Running OWASP checks — this may take up to 2 minutes...</p>}
                    </div>
                )}

                {scan.status === 'failed' && (
                    <div className="card mb-24" style={{ borderColor: 'rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.05)' }}>
                        <div className="flex items-center gap-12">
                            <AlertTriangle size={18} color="#f87171" />
                            <div>
                                <p style={{ color: '#f87171', fontWeight: 600, marginBottom: 4 }}>Scan Failed</p>
                                <p style={{ fontSize: '0.85rem' }}>{scan.ai_summary || 'An error occurred during the scan.'}</p>
                            </div>
                        </div>
                    </div>
                )}

                {scan.status === 'complete' && aiSummary && (
                    <>
                        {/* Risk overview */}
                        <div className="card mb-24">
                            <h2 style={{ fontSize: '1.1rem', marginBottom: 24 }}>Risk Overview</h2>
                            <div className="risk-overview">
                                <RiskRing score={aiSummary.overallRiskScore || 0} level={aiSummary.riskLevel || 'Unknown'} />
                                <div>
                                    <p style={{ marginBottom: 16, fontSize: '0.875rem' }}>{aiSummary.executiveSummary}</p>
                                    <div className="severity-bars">
                                        {[
                                            { label: 'Critical', color: '#ef4444' },
                                            { label: 'High', color: '#f59e0b' },
                                            { label: 'Medium', color: '#fbbf24' },
                                            { label: 'Low', color: '#10b981' },
                                            { label: 'Informational', color: '#818cf8' },
                                        ].map(({ label, color }) => {
                                            const count = severitySummary[label] || 0;
                                            const max = Math.max(...Object.values(severitySummary), 1);
                                            return (
                                                <div key={label} className="severity-bar-row">
                                                    <span className="severity-bar-label">{label}</span>
                                                    <div className="severity-bar-track">
                                                        <div className="severity-bar-fill" style={{ width: `${(count / max) * 100}%`, background: color }} />
                                                    </div>
                                                    <span className="severity-bar-count" style={{ color }}>{count}</span>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Key findings */}
                        {aiSummary.keyFindings?.length > 0 && (
                            <div className="card mb-24">
                                <h2 style={{ fontSize: '1rem', marginBottom: 16 }}>Key Findings</h2>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                                    {aiSummary.keyFindings.map((f, i) => (
                                        <div key={i} className="owasp-item" style={{ gap: 10 }}>
                                            <CheckCircle size={14} color="#00d4ff" style={{ flexShrink: 0 }} />
                                            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{f}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </>
                )}

                {/* Vulnerability cards */}
                {findings.length > 0 && (
                    <div className="card">
                        <h2 style={{ fontSize: '1rem', marginBottom: 20 }}>Vulnerability Details ({findings.length})</h2>
                        <div className="vuln-grid">
                            {findings.map((f, i) => <VulnCard key={i} finding={f} />)}
                        </div>
                    </div>
                )}

                {/* Remediation */}
                {aiSummary?.prioritizedRemediation?.length > 0 && (
                    <div className="card mt-24">
                        <h2 style={{ fontSize: '1rem', marginBottom: 16 }}>Prioritized Remediation</h2>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                            {aiSummary.prioritizedRemediation.map((step, i) => (
                                <div key={i} style={{ display: 'flex', gap: 12, padding: '10px 14px', background: 'var(--bg-glass)', borderRadius: 'var(--radius-sm)', borderLeft: '3px solid var(--accent-green)' }}>
                                    <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, minWidth: 20 }}>{i + 1}.</span>
                                    <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>{step}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
