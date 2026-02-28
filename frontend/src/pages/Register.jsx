import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck, Eye, EyeOff, CheckCircle } from 'lucide-react';
import toast from 'react-hot-toast';

export default function Register() {
    const [form, setForm] = useState({ username: '', email: '', password: '' });
    const [showPwd, setShowPwd] = useState(false);
    const [errors, setErrors] = useState({});
    const { register, loading } = useAuth();
    const navigate = useNavigate();

    const validate = () => {
        const e = {};
        if (!form.username || form.username.length < 3) e.username = 'Username must be at least 3 characters';
        if (!form.email || !/\S+@\S+\.\S+/.test(form.email)) e.email = 'Valid email required';
        if (!form.password || form.password.length < 8) e.password = 'Password must be at least 8 characters';
        else if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(form.password)) e.password = 'Needs uppercase, lowercase, and a digit';
        return e;
    };

    const pwdStrength = () => {
        const p = form.password;
        if (p.length === 0) return 0;
        let s = 0;
        if (p.length >= 8) s++;
        if (/[A-Z]/.test(p)) s++;
        if (/[a-z]/.test(p)) s++;
        if (/\d/.test(p)) s++;
        if (/[^A-Za-z0-9]/.test(p)) s++;
        return s;
    };

    const strength = pwdStrength();
    const strengthLabel = ['', 'Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'][strength];
    const strengthColor = ['', '#ef4444', '#f59e0b', '#fbbf24', '#10b981', '#00d4ff'][strength];

    const handleSubmit = async (e) => {
        e.preventDefault();
        const errs = validate();
        if (Object.keys(errs).length) { setErrors(errs); return; }
        setErrors({});
        try {
            await register(form.username, form.email, form.password);
            toast.success('Account created! Welcome to SecureAI.');
            navigate('/dashboard');
        } catch (err) {
            const msg = err.response?.data?.error || 'Registration failed.';
            setErrors({ general: msg });
            toast.error(msg);
        }
    };

    return (
        <div className="auth-page">
            <div className="card card-glow auth-card">
                <div className="auth-logo">
                    <div className="auth-logo-icon"><ShieldCheck size={24} color="white" /></div>
                    <span style={{ fontSize: '1.4rem', fontWeight: 800 }}>SecureAI</span>
                </div>
                <h2 className="auth-title">Create account</h2>
                <p className="auth-subtitle">Start your first security scan in minutes</p>

                <form className="auth-form" onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label className="form-label">Username</label>
                        <input id="reg-username" className={`form-input ${errors.username ? 'error' : ''}`} type="text" placeholder="johndoe"
                            value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} />
                        {errors.username && <p className="form-error">{errors.username}</p>}
                    </div>

                    <div className="form-group">
                        <label className="form-label">Email address</label>
                        <input id="reg-email" className={`form-input ${errors.email ? 'error' : ''}`} type="email" placeholder="you@example.com"
                            value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} />
                        {errors.email && <p className="form-error">{errors.email}</p>}
                    </div>

                    <div className="form-group">
                        <label className="form-label">Password</label>
                        <div style={{ position: 'relative' }}>
                            <input id="reg-password" className={`form-input ${errors.password ? 'error' : ''}`}
                                type={showPwd ? 'text' : 'password'} placeholder="Min 8 chars with upper, lower, digit"
                                value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} />
                            <button type="button" onClick={() => setShowPwd(v => !v)}
                                style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                                {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
                            </button>
                        </div>
                        {form.password && (
                            <div style={{ marginTop: 6 }}>
                                <div style={{ display: 'flex', gap: 4, marginBottom: 4 }}>
                                    {[1, 2, 3, 4, 5].map(i => (
                                        <div key={i} style={{ flex: 1, height: 3, borderRadius: 2, background: i <= strength ? strengthColor : 'var(--border)', transition: 'background 0.3s' }} />
                                    ))}
                                </div>
                                <p style={{ fontSize: '0.75rem', color: strengthColor }}>{strengthLabel}</p>
                            </div>
                        )}
                        {errors.password && <p className="form-error">{errors.password}</p>}
                    </div>

                    {errors.general && <p className="form-error">{errors.general}</p>}

                    <button id="reg-submit" type="submit" className="btn btn-primary w-full btn-lg" disabled={loading}>
                        {loading ? <span className="spinner" /> : 'Create Account'}
                    </button>
                </form>

                <p className="auth-footer">
                    Already have an account? <Link to="/login">Sign in</Link>
                </p>
            </div>
        </div>
    );
}
