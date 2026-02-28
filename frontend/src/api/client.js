import axios from 'axios';

const api = axios.create({
    baseURL: 'http://localhost:3001/api',
    timeout: 30000,
    headers: { 'Content-Type': 'application/json' },
});

// Attach JWT from localStorage on every request
api.interceptors.request.use((config) => {
    const token = localStorage.getItem('auth_token');
    if (token) config.headers.Authorization = `Bearer ${token}`;
    return config;
});

// Handle 401s globally
api.interceptors.response.use(
    (res) => res,
    (err) => {
        if (err.response?.status === 401) {
            localStorage.removeItem('auth_token');
            localStorage.removeItem('auth_user');
            window.location.href = '/login';
        }
        return Promise.reject(err);
    }
);

// ── Auth ─────────────────────────────────────────────────────────────────────
export const authAPI = {
    register: (data) => api.post('/auth/register', data),
    login: (data) => api.post('/auth/login', data),
    me: () => api.get('/auth/me'),
};

// ── Scans ─────────────────────────────────────────────────────────────────────
export const scansAPI = {
    list: () => api.get('/scans'),
    start: (targetUrl) => api.post('/scans', { targetUrl }),
    status: (id) => api.get(`/scans/${id}/status`),
    results: (id) => api.get(`/scans/${id}/results`),
};

// ── Reports ───────────────────────────────────────────────────────────────────
export const reportsAPI = {
    downloadPdf: (scanId) =>
        api.get(`/reports/${scanId}/pdf`, { responseType: 'blob' }),
};

export default api;
