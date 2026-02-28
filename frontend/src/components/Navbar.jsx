import { Link, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck, LayoutDashboard, PlusCircle, FileText, LogOut } from 'lucide-react';

export default function Navbar() {
    const { user, logout, isAuthenticated } = useAuth();
    const navigate = useNavigate();

    const handleLogout = () => {
        logout();
        navigate('/');
    };

    return (
        <nav className="navbar">
            <div className="navbar-inner">
                <Link to={isAuthenticated ? '/dashboard' : '/'} className="navbar-logo">
                    <div className="navbar-logo-icon">
                        <ShieldCheck size={18} />
                    </div>
                    <span>SecureAI</span>
                </Link>

                {isAuthenticated && (
                    <div className="navbar-links">
                        <NavLink to="/dashboard" className={({ isActive }) => `navbar-link ${isActive ? 'active' : ''}`}>
                            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                <LayoutDashboard size={14} /> Dashboard
                            </span>
                        </NavLink>
                        <NavLink to="/scan/new" className={({ isActive }) => `navbar-link ${isActive ? 'active' : ''}`}>
                            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                <PlusCircle size={14} /> New Scan
                            </span>
                        </NavLink>
                        <NavLink to="/reports" className={({ isActive }) => `navbar-link ${isActive ? 'active' : ''}`}>
                            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                <FileText size={14} /> Reports
                            </span>
                        </NavLink>
                    </div>
                )}

                <div className="navbar-user">
                    {isAuthenticated ? (
                        <>
                            <div className="user-badge">
                                <div className="user-avatar">{user?.username?.[0]?.toUpperCase() || 'U'}</div>
                                <span>{user?.username}</span>
                            </div>
                            <button className="btn btn-sm btn-secondary" onClick={handleLogout} title="Logout">
                                <LogOut size={14} />
                            </button>
                        </>
                    ) : (
                        <>
                            <Link to="/login" className="btn btn-sm btn-secondary">Sign In</Link>
                            <Link to="/register" className="btn btn-sm btn-primary">Sign Up</Link>
                        </>
                    )}
                </div>
            </div>
        </nav>
    );
}
