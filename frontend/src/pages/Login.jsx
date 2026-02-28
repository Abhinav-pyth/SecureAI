import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck, Eye, EyeOff } from 'lucide-react';
import toast from 'react-hot-toast';

export default function Login() {
    const [form, setForm] = useState({ identifier: '', password: '' });
    const [showPwd, setShowPwd] = useState(false);
    const [error, setError] = useState('');
    const { login, loading } = useAuth();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        try {
            await login(form.identifier, form.password);
            toast.success('Welcome back!');
            navigate('/dashboard');
        } catch (err) {
            const msg = err.response?.data?.error || 'Login failed. Please try again.';
            setError(msg);
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
                <h2 className="auth-title">Welcome back</h2>
                <p className="auth-subtitle">Sign in to your security testing account</p>

                <form className="auth-form" onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label className="form-label">Username or Email</label>
                        <input id="login-identifier" className={`form-input ${error ? 'error' : ''}`} type="text" placeholder="johndoe or you@example.com"
                            value={form.identifier} onChange={e => setForm(f => ({ ...f, identifier: e.target.value }))} required />
                    </div>

                    <div className="form-group">
                        <label className="form-label">Password</label>
                        <div style={{ position: 'relative' }}>
                            <input id="login-password" className={`form-input ${error ? 'error' : ''}`}
                                type={showPwd ? 'text' : 'password'} placeholder="••••••••"
                                value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} required />
                            <button type="button" onClick={() => setShowPwd(v => !v)}
                                style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                                {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
                            </button>
                        </div>
                    </div>

                    {error && <p className="form-error">{error}</p>}

                    <button id="login-submit" type="submit" className="btn btn-primary w-full btn-lg" disabled={loading}>
                        {loading ? <span className="spinner" /> : 'Sign In'}
                    </button>
                </form>

                <p className="auth-footer">
                    Don't have an account? <Link to="/register">Create one</Link>
                </p>
            </div>
        </div>
    );
}
