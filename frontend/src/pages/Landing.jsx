import { Link, useNavigate } from 'react-router-dom';
import { ShieldCheck, Zap, FileText, Brain, ArrowRight, Lock, AlertTriangle, Search } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useEffect } from 'react';

const FEATURES = [
    { icon: '🛡️', iconClass: 'feature-icon-cyan', title: 'OWASP Top 10 Coverage', desc: 'Comprehensive scanning across all 10 OWASP vulnerability categories with active HTTP probes and AI analysis.' },
    { icon: '🤖', iconClass: 'feature-icon-purple', title: 'Ollama AI Analysis', desc: 'Local LLM (Llama 3 / Mistral) synthesizes scan findings into actionable security insights with risk scoring.' },
    { icon: '📄', iconClass: 'feature-icon-green', title: 'PDF Reports', desc: 'Generate professional, colour-coded security reports with executive summaries and prioritized remediation steps.' },
    { icon: '⚡', iconClass: 'feature-icon-orange', title: 'Real-Time Progress', desc: 'Watch vulnerability checks complete in real time with live progress tracking for each OWASP category.' },
];

const OWASP = [
    'A01 – Broken Access Control', 'A02 – Cryptographic Failures',
    'A03 – Injection', 'A04 – Insecure Design',
    'A05 – Security Misconfiguration', 'A06 – Vulnerable Components',
    'A07 – Auth Failures', 'A08 – Integrity Failures',
    'A09 – Logging Failures', 'A10 – SSRF',
];

export default function Landing() {
    const { isAuthenticated } = useAuth();
    const navigate = useNavigate();

    useEffect(() => {
        if (isAuthenticated) navigate('/dashboard');
    }, [isAuthenticated]);

    return (
        <>
            <section className="landing-hero">
                <div className="hero-badge">
                    <ShieldCheck size={12} /> AI-Powered · OWASP Top 10 · Real-Time
                </div>
                <h1 className="hero-title">
                    Web Application<br />
                    <span className="gradient-text">Security Testing</span>
                </h1>
                <p className="hero-subtitle">
                    Scan any web application for OWASP Top 10 vulnerabilities using AI-assisted penetration testing.
                    Get detailed reports with remediation guidance in minutes.
                </p>
                <div className="hero-cta">
                    <Link to="/register" className="btn btn-primary btn-lg">
                        Start Scanning Free <ArrowRight size={18} />
                    </Link>
                    <Link to="/login" className="btn btn-secondary btn-lg">
                        Sign In
                    </Link>
                </div>

                {/* OWASP pills */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center', maxWidth: 700 }}>
                    {OWASP.map((item) => (
                        <span key={item} className="owasp-item" style={{ fontSize: '0.72rem' }}>{item}</span>
                    ))}
                </div>
            </section>

            {/* Features */}
            <div className="features-grid">
                {FEATURES.map((f) => (
                    <div key={f.title} className="feature-card">
                        <div className={`feature-icon ${f.iconClass}`}>{f.icon}</div>
                        <h3>{f.title}</h3>
                        <p>{f.desc}</p>
                    </div>
                ))}
            </div>

            {/* Warning banner */}
            <div style={{ maxWidth: 700, margin: '0 auto 60px', padding: '0 24px' }}>
                <div className="card" style={{ background: 'rgba(245,158,11,0.07)', borderColor: 'rgba(245,158,11,0.2)' }}>
                    <div className="flex items-center gap-12">
                        <AlertTriangle size={20} color="#f59e0b" style={{ flexShrink: 0 }} />
                        <p style={{ fontSize: '0.85rem', color: '#fcd34d' }}>
                            <strong>Legal Notice:</strong> Only scan web applications you own or have explicit written permission to test.
                            Unauthorized testing may be illegal.
                        </p>
                    </div>
                </div>
            </div>
        </>
    );
}
