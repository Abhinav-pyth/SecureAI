require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { initDb } = require('./db/database');

const app = express();

// ── Security middleware ──────────────────────────────────────────────────────
app.use(helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false,
}));

app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: 'Too many auth attempts, please wait 15 minutes.' },
});

app.use(limiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Health check (no auth needed)
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── Bootstrap: init DB then register routes ─────────────────────────────────
async function bootstrap() {
    await initDb();

    // Routes loaded AFTER db is ready
    const authRoutes = require('./routes/auth');
    const scanRoutes = require('./routes/scans');
    const reportRoutes = require('./routes/reports');

    app.use('/api/auth', authLimiter, authRoutes);
    app.use('/api/scans', scanRoutes);
    app.use('/api/reports', reportRoutes);

    // 404
    app.use((req, res) => res.status(404).json({ error: 'Route not found' }));

    // Global error handler
    app.use((err, req, res, _next) => {
        console.error('Unhandled error:', err);
        res.status(500).json({ error: 'Internal server error' });
    });

    const PORT = process.env.PORT || 3001;
    app.listen(PORT, () => {
        console.log(`\n🛡️  AI Security Testing API running on http://localhost:${PORT}`);
        console.log(`   Ollama: ${process.env.OLLAMA_BASE_URL || 'http://localhost:11434'} (${process.env.OLLAMA_MODEL || 'llama3'})\n`);
    });
}

bootstrap().catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
});

module.exports = app;
