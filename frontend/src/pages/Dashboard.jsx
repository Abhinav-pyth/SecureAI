import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { scansAPI } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { PlusCircle, Shield, AlertTriangle, CheckCircle, Clock, ChevronRight } from 'lucide-react';

function timeSince(dateStr) {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    const secs = Math.floor((Date.now() - d) / 1000);
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
}

function StatusBadge({ status }) {
    return <span className={`badge badge-${status}`}>{status}</span>;
}

export default function Dashboard() {
    const { user } = useAuth();
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        scansAPI.list().then(r => setScans(r.data.scans)).catch(console.error).finally(() => setLoading(false));
    }, []);

    const total = scans.length;
    const complete = scans.filter(s => s.status === 'complete').length;
    const running = scans.filter(s => s.status === 'running' || s.status === 'pending').length;
    const criticalCount = scans.reduce((sum, s) => sum + (s.severity_summary?.Critical || 0), 0);

    return (
        <div className="page-wrapper">
            <div className="page-content">
                {/* Header */}
                <div className="dashboard-header">
                    <div>
                        <h1 style={{ fontSize: '1.8rem', marginBottom: 4 }}>
                            Good evening, <span className="gradient-text">{user?.username}</span> 👋
                        </h1>
                        <p>Here's your security testing overview.</p>
                    </div>
                    <Link to="/scan/new" className="btn btn-primary">
                        <PlusCircle size={16} /> New Scan
                    </Link>
                </div>

                {/* Stats */}
                <div className="stats-grid">
                    {[
                        { icon: <Shield size={18} />, bg: 'rgba(0,212,255,0.1)', fg: 'var(--accent-cyan)', label: 'Total Scans', value: total },
                        { icon: <CheckCircle size={18} />, bg: 'rgba(16,185,129,0.1)', fg: 'var(--accent-green)', label: 'Completed', value: complete },
                        { icon: <Clock size={18} />, bg: 'rgba(124,58,237,0.1)', fg: '#a78bfa', label: 'In Progress', value: running },
                        { icon: <AlertTriangle size={18} />, bg: 'rgba(239,68,68,0.1)', fg: 'var(--accent-red)', label: 'Critical Findings', value: criticalCount },
                    ].map(stat => (
                        <div key={stat.label} className="stat-card">
                            <div className="stat-icon" style={{ background: stat.bg, color: stat.fg }}>{stat.icon}</div>
                            <div className="stat-value">{stat.value}</div>
                            <div className="stat-label">{stat.label}</div>
                        </div>
                    ))}
                </div>

                {/* Scan list */}
                <div className="card">
                    <div className="flex items-center justify-between mb-24">
                        <h2 style={{ fontSize: '1.1rem' }}>Recent Scans</h2>
                        <Link to="/scan/new" className="btn btn-sm btn-secondary"><PlusCircle size={14} /> New</Link>
                    </div>

                    {loading ? (
                        <div className="empty-state"><div className="spinner spinner-lg" /></div>
                    ) : scans.length === 0 ? (
                        <div className="empty-state">
                            <div className="empty-state-icon">🔍</div>
                            <h3>No scans yet</h3>
                            <p>Start your first security scan to see results here.</p>
                            <Link to="/scan/new" className="btn btn-primary mt-16">Start Scanning</Link>
                        </div>
                    ) : (
                        <div className="scan-list">
                            {scans.map(scan => (
                                <Link key={scan.id} to={`/scan/${scan.id}`} className="scan-item">
                                    <div style={{ flexShrink: 0, width: 36, height: 36, background: 'var(--bg-glass)', borderRadius: 'var(--radius-sm)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                        <Shield size={16} color="var(--accent-cyan)" />
                                    </div>
                                    <div className="scan-item-info">
                                        <div className="scan-item-url">{scan.target_url}</div>
                                        <div className="scan-item-meta">{timeSince(scan.created_at)}</div>
                                    </div>
                                    {scan.severity_summary && (
                                        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                                            {scan.severity_summary.Critical > 0 && <span className="badge badge-critical">{scan.severity_summary.Critical} C</span>}
                                            {scan.severity_summary.High > 0 && <span className="badge badge-high">{scan.severity_summary.High} H</span>}
                                            {scan.severity_summary.Medium > 0 && <span className="badge badge-medium">{scan.severity_summary.Medium} M</span>}
                                        </div>
                                    )}
                                    <StatusBadge status={scan.status} />
                                    <ChevronRight size={16} color="var(--text-muted)" />
                                </Link>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
