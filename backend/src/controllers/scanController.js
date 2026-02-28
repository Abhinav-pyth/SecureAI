const ScanModel = require('../models/Scan');
const { runOWASPScan } = require('../services/scannerService');
const { analyzeScanResults } = require('../services/ollamaService');
const { body, validationResult } = require('express-validator');

const startScanValidation = [
    body('targetUrl')
        .trim()
        .notEmpty().withMessage('Target URL is required')
        .isURL({ protocols: ['http', 'https'], require_protocol: true })
        .withMessage('Must be a valid http/https URL'),
];

const startScan = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { targetUrl } = req.body;
    const userId = req.user.id;

    const scan = ScanModel.create({ userId, targetUrl });
    res.status(201).json({ scanId: scan.id, status: 'pending' });

    // Run async in background
    runScanAsync(scan.id, targetUrl);
};

async function runScanAsync(scanId, targetUrl) {
    try {
        ScanModel.updateStatus(scanId, 'running', 0);

        const { results: checkResults, techStack } = await runOWASPScan(targetUrl, (progress) => {
            ScanModel.updateProgress(scanId, progress);
        });

        ScanModel.updateProgress(scanId, 92);

        // AI analysis, now passing the inferred tech stack to allow for code-level auto-patching
        const aiAnalysis = await analyzeScanResults(checkResults, techStack);

        const severitySummary = {
            Critical: 0,
            High: 0,
            Medium: 0,
            Low: 0,
            Informational: 0,
        };

        (aiAnalysis.findings || checkResults).forEach((f) => {
            const sev = f.severity || 'Informational';
            severitySummary[sev] = (severitySummary[sev] || 0) + 1;
        });

        ScanModel.saveResults(
            scanId,
            checkResults,
            JSON.stringify(aiAnalysis),
            severitySummary
        );
    } catch (err) {
        console.error('Scan failed:', err);
        ScanModel.fail(scanId, err.message);
    }
}

const getScanStatus = (req, res) => {
    const scan = ScanModel.findById(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    return res.json({
        id: scan.id,
        status: scan.status,
        progress: scan.progress,
        target_url: scan.target_url,
        created_at: scan.created_at,
        completed_at: scan.completed_at,
    });
};

const getScanResult = (req, res) => {
    const scan = ScanModel.findById(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    const aiSummary = scan.ai_summary ? JSON.parse(scan.ai_summary) : null;
    return res.json({ ...scan, ai_summary: aiSummary });
};

const listScans = (req, res) => {
    const limit = parseInt(req.query.limit) || 20;
    const offset = parseInt(req.query.offset) || 0;
    const scans = ScanModel.findByUser(req.user.id, limit, offset);
    return res.json({ scans });
};

module.exports = { startScan, getScanStatus, getScanResult, listScans, startScanValidation };
