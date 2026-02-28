const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const ScanModel = require('../models/Scan');
const { generateReport } = require('../services/reportService');

router.use(authMiddleware);

router.get('/:scanId/pdf', (req, res) => {
    const scan = ScanModel.findById(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    if (scan.status !== 'complete') return res.status(400).json({ error: 'Scan not complete' });

    const aiSummary = scan.ai_summary ? JSON.parse(scan.ai_summary) : null;
    const scanWithParsed = { ...scan, ai_summary_parsed: aiSummary };

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="security-report-${scan.id.slice(0, 8)}.pdf"`);

    generateReport(scanWithParsed, res);
});

module.exports = router;
