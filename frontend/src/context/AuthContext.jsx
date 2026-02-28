import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authAPI } from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
    const [user, setUser] = useState(() => {
        try {
            const stored = localStorage.getItem('auth_user');
            return stored ? JSON.parse(stored) : null;
        } catch { return null; }
    });
    const [loading, setLoading] = useState(false);

    const saveAuth = (token, userData) => {
        localStorage.setItem('auth_token', token);
        localStorage.setItem('auth_user', JSON.stringify(userData));
        setUser(userData);
    };

    const register = useCallback(async (username, email, password) => {
        setLoading(true);
        try {
            const { data } = await authAPI.register({ username, email, password });
            saveAuth(data.token, data.user);
            return data;
        } finally { setLoading(false); }
    }, []);

    const login = useCallback(async (identifier, password) => {
        setLoading(true);
        try {
            const { data } = await authAPI.login({ identifier, password });
            saveAuth(data.token, data.user);
            return data;
        } finally { setLoading(false); }
    }, []);

    const logout = useCallback(() => {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_user');
        setUser(null);
    }, []);

    return (
        <AuthContext.Provider value={{ user, loading, register, login, logout, isAuthenticated: !!user }}>
            {children}
        </AuthContext.Provider>
    );
}

export const useAuth = () => {
    const ctx = useContext(AuthContext);
    if (!ctx) throw new Error('useAuth must be inside AuthProvider');
    return ctx;
};
