import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { scansAPI, reportsAPI } from '../api/client';
import { FileText, Download, Shield, ExternalLink } from 'lucide-react';
import toast from 'react-hot-toast';

function timeSince(dateStr) {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    const secs = Math.floor((Date.now() - d) / 1000);
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
}

export default function Reports() {
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [downloading, setDownloading] = useState(null);

    useEffect(() => {
        scansAPI.list()
            .then(r => setScans(r.data.scans.filter(s => s.status === 'complete')))
            .catch(console.error)
            .finally(() => setLoading(false));
    }, []);

    const downloadPdf = async (scan) => {
        setDownloading(scan.id);
        try {
            const { data } = await reportsAPI.downloadPdf(scan.id);
            const url = window.URL.createObjectURL(new Blob([data], { type: 'application/pdf' }));
            const a = document.createElement('a');
            a.href = url;
            a.download = `security-report-${scan.id.slice(0, 8)}.pdf`;
            a.click();
            window.URL.revokeObjectURL(url);
            toast.success(`Report for ${scan.target_url} downloaded!`);
        } catch { toast.error('Failed to download report'); }
        finally { setDownloading(null); }
    };

    return (
        <div className="page-wrapper">
            <div className="page-content">
                <div className="dashboard-header">
                    <div>
                        <h1 style={{ fontSize: '1.8rem', marginBottom: 4 }}>Security Reports</h1>
                        <p>Download PDF reports for completed scans.</p>
                    </div>
                </div>

                <div className="card">
                    {loading ? (
                        <div className="empty-state"><div className="spinner spinner-lg" /></div>
                    ) : scans.length === 0 ? (
                        <div className="empty-state">
                            <div className="empty-state-icon"><FileText size={48} /></div>
                            <h3>No reports yet</h3>
                            <p>Complete a scan to generate a security report.</p>
                            <Link to="/scan/new" className="btn btn-primary mt-16">Start a Scan</Link>
                        </div>
                    ) : (
                        <div className="scan-list">
                            {scans.map(scan => {
                                const summary = scan.severity_summary || {};
                                return (
                                    <div key={scan.id} className="scan-item" style={{ cursor: 'default' }}>
                                        <div style={{ flexShrink: 0, width: 40, height: 40, background: 'rgba(16,185,129,0.1)', borderRadius: 'var(--radius-sm)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                            <FileText size={18} color="var(--accent-green)" />
                                        </div>
                                        <div className="scan-item-info">
                                            <div className="scan-item-url">{scan.target_url}</div>
                                            <div className="scan-item-meta">Completed {timeSince(scan.completed_at)}</div>
                                        </div>
                                        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                                            {summary.Critical > 0 && <span className="badge badge-critical">{summary.Critical} C</span>}
                                            {summary.High > 0 && <span className="badge badge-high">{summary.High} H</span>}
                                            {summary.Medium > 0 && <span className="badge badge-medium">{summary.Medium} M</span>}
                                        </div>
                                        <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
                                            <Link to={`/scan/${scan.id}`} className="btn btn-sm btn-secondary" title="View scan">
                                                <ExternalLink size={13} />
                                            </Link>
                                            <button className="btn btn-sm btn-primary" onClick={() => downloadPdf(scan)} disabled={downloading === scan.id}>
                                                {downloading === scan.id ? <span className="spinner" /> : <><Download size={13} /> PDF</>}
                                            </button>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
