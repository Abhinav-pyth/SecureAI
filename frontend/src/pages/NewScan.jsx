import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { scansAPI } from '../api/client';
import { Shield, Zap, AlertTriangle, Lock, ExternalLink } from 'lucide-react';
import toast from 'react-hot-toast';

const OWASP_LIST = [
    { id: 'A01:2021', name: 'Broken Access Control' },
    { id: 'A02:2021', name: 'Cryptographic Failures' },
    { id: 'A03:2021', name: 'Injection' },
    { id: 'A04:2021', name: 'Insecure Design' },
    { id: 'A05:2021', name: 'Security Misconfiguration' },
    { id: 'A06:2021', name: 'Vulnerable Components' },
    { id: 'A07:2021', name: 'Auth Failures' },
    { id: 'A08:2021', name: 'Software Integrity Failures' },
    { id: 'A09:2021', name: 'Logging & Monitoring Failures' },
    { id: 'A10:2021', name: 'Server-Side Request Forgery' },
];

export default function NewScan() {
    const [url, setUrl] = useState('');
    const [loading, setLoading] = useState(false);
    const [urlError, setUrlError] = useState('');
    const navigate = useNavigate();

    const validateUrl = (u) => {
        try { new URL(u); return true; } catch { return false; }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!validateUrl(url)) {
            setUrlError('Please enter a valid URL including http:// or https://');
            return;
        }
        setUrlError('');
        setLoading(true);
        try {
            const { data } = await scansAPI.start(url);
            toast.success('Scan started successfully!');
            navigate(`/scan/${data.scanId}`);
        } catch (err) {
            const msg = err.response?.data?.errors?.[0]?.msg || err.response?.data?.error || 'Failed to start scan.';
            toast.error(msg);
            setUrlError(msg);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="page-wrapper">
            <div className="page-content new-scan-wrap">
                <div style={{ marginBottom: 32 }}>
                    <h1 style={{ fontSize: '1.8rem', marginBottom: 8 }}>New Security Scan</h1>
                    <p>Enter the target URL to scan for OWASP Top 10 vulnerabilities.</p>
                </div>

                <div className="card card-glow mb-24">
                    <h2 style={{ fontSize: '1.1rem', marginBottom: 20 }}>
                        <Zap size={16} style={{ display: 'inline', marginRight: 8, color: 'var(--accent-cyan)' }} />
                        Target Configuration
                    </h2>
                    <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                        <div className="form-group">
                            <label className="form-label">Target URL</label>
                            <div style={{ display: 'flex', gap: 10 }}>
                                <input id="scan-url-input" className={`form-input ${urlError ? 'error' : ''}`} type="text"
                                    placeholder="https://example.com"
                                    value={url} onChange={e => { setUrl(e.target.value); setUrlError(''); }}
                                    style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.875rem' }} />
                                <button id="start-scan-btn" type="submit" className="btn btn-primary" disabled={loading || !url}
                                    style={{ flexShrink: 0, minWidth: 120 }}>
                                    {loading ? <span className="spinner" /> : <><Shield size={15} /> Start Scan</>}
                                </button>
                            </div>
                            {urlError ? <p className="form-error">{urlError}</p> :
                                <p className="form-hint">Include the full URL with protocol (http:// or https://)</p>}
                        </div>
                    </form>
                </div>

                {/* OWASP coverage */}
                <div className="card mb-24">
                    <h2 style={{ fontSize: '1rem', marginBottom: 4 }}>Checks Included</h2>
                    <p style={{ fontSize: '0.85rem', marginBottom: 16 }}>All OWASP Top 10 (2021) categories will be tested:</p>
                    <div className="owasp-grid">
                        {OWASP_LIST.map(o => (
                            <div key={o.id} className="owasp-item">
                                <span className="owasp-item-id">{o.id.split(':')[0]}</span>
                                <span>{o.name}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Warning */}
                <div className="card" style={{ background: 'rgba(245,158,11,0.05)', borderColor: 'rgba(245,158,11,0.2)' }}>
                    <div className="flex items-center gap-12">
                        <AlertTriangle size={18} color="#f59e0b" style={{ flexShrink: 0 }} />
                        <div>
                            <p style={{ fontSize: '0.85rem', color: '#fcd34d', fontWeight: 600, marginBottom: 2 }}>Legal Reminder</p>
                            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                                Only scan applications you own or have explicit written permission to test. This tool makes real HTTP requests to the target.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
