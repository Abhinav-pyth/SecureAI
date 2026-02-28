const PDFDocument = require('pdfkit');

const SEVERITY_COLORS = {
    Critical: '#dc2626',
    High: '#ea580c',
    Medium: '#d97706',
    Low: '#16a34a',
    Informational: '#2563eb',
};

function generateReport(scan, stream) {
    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    doc.pipe(stream);

    const analysis = scan.ai_summary_parsed || {};
    const results = scan.results || [];

    // ── Header ──────────────────────────────────────────────────────────────────
    doc.rect(0, 0, doc.page.width, 80).fill('#0f172a');
    doc.fillColor('#00d4ff').fontSize(22).font('Helvetica-Bold')
        .text('AI Security Testing Report', 50, 20);
    doc.fillColor('#94a3b8').fontSize(10).font('Helvetica')
        .text(`Generated: ${new Date().toUTCString()}`, 50, 50);
    doc.fillColor('#ffffff').text(`Target: ${scan.target_url}`, 300, 50, { align: 'right' });

    doc.moveDown(3);

    // ── Executive Summary ────────────────────────────────────────────────────────
    doc.fillColor('#0f172a').rect(50, doc.y, doc.page.width - 100, 1).fill();
    doc.moveDown(0.5);
    doc.fillColor('#1e293b').fontSize(14).font('Helvetica-Bold').text('Executive Summary');
    doc.moveDown(0.3);

    const riskLevel = analysis.riskLevel || 'Unknown';
    const riskColor = { Critical: '#dc2626', High: '#ea580c', Medium: '#d97706', Low: '#16a34a' }[riskLevel] || '#64748b';

    doc.fontSize(10).font('Helvetica')
        .fillColor('#374151')
        .text(`Risk Level: `, { continued: true })
        .fillColor(riskColor).font('Helvetica-Bold')
        .text(riskLevel, { continued: true })
        .fillColor('#374151').font('Helvetica')
        .text(`  |  Risk Score: ${analysis.overallRiskScore || 'N/A'}/100`);
    doc.moveDown(0.5);

    if (analysis.executiveSummary) {
        doc.fillColor('#374151').fontSize(10).font('Helvetica').text(analysis.executiveSummary);
    }
    doc.moveDown(1);

    // ── Key Findings ─────────────────────────────────────────────────────────────
    if (analysis.keyFindings && analysis.keyFindings.length > 0) {
        doc.fillColor('#1e293b').fontSize(14).font('Helvetica-Bold').text('Key Findings');
        doc.moveDown(0.3);
        analysis.keyFindings.forEach((finding, i) => {
            doc.fillColor('#374151').fontSize(10).font('Helvetica').text(`${i + 1}. ${finding}`);
        });
        doc.moveDown(1);
    }

    // ── Vulnerability Findings ───────────────────────────────────────────────────
    doc.fillColor('#1e293b').fontSize(14).font('Helvetica-Bold').text('Vulnerability Details');
    doc.moveDown(0.5);

    const findings = analysis.findings || results;
    findings.forEach((finding, idx) => {
        const severity = finding.severity || 'Informational';
        const color = SEVERITY_COLORS[severity] || '#64748b';

        // Section header
        doc.rect(50, doc.y, doc.page.width - 100, 20).fill(color);
        doc.fillColor('#ffffff').fontSize(10).font('Helvetica-Bold')
            .text(`${idx + 1}. ${finding.category || finding.name}   [${finding.owaspId}]   Severity: ${severity}`,
                55, doc.y - 15);
        doc.moveDown(0.3);

        // Details
        doc.fillColor('#374151').fontSize(9).font('Helvetica-Bold').text('Description:', { continued: false });
        doc.font('Helvetica').text(finding.description || 'N/A');
        doc.moveDown(0.2);

        doc.font('Helvetica-Bold').text('Evidence:', { continued: false });
        doc.font('Helvetica').text(finding.evidence || 'N/A');
        doc.moveDown(0.2);

        doc.font('Helvetica-Bold').text('Recommendation:', { continued: false });
        doc.font('Helvetica').text(finding.recommendation || 'N/A');
        doc.moveDown(1);
    });

    // ── Remediation Priority ─────────────────────────────────────────────────────
    if (analysis.prioritizedRemediation?.length > 0) {
        doc.addPage();
        doc.fillColor('#1e293b').fontSize(14).font('Helvetica-Bold').text('Prioritized Remediation Steps');
        doc.moveDown(0.5);
        analysis.prioritizedRemediation.forEach((step, i) => {
            doc.fillColor('#374151').fontSize(10).font('Helvetica').text(`${i + 1}. ${step}`);
            doc.moveDown(0.3);
        });
    }

    // ── Footer ───────────────────────────────────────────────────────────────────
    const pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
        doc.switchToPage(pages.start + i);
        doc.fillColor('#94a3b8').fontSize(8).font('Helvetica')
            .text(`AI Security Testing Platform | Confidential | Page ${i + 1} of ${pages.count}`,
                50, doc.page.height - 30, { align: 'center' });
    }

    doc.end();
}

module.exports = { generateReport };
