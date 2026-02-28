const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');

class ScanModel {
    static create({ userId, targetUrl }) {
        const id = uuidv4();
        const now = new Date().toISOString();
        db.run(
            'INSERT INTO scans (id, user_id, target_url, status, progress, created_at) VALUES (?, ?, ?, ?, ?, ?)',
            [id, userId, targetUrl, 'pending', 0, now]
        );
        return this.findById(id);
    }

    static findById(id) {
        const scan = db.get('SELECT * FROM scans WHERE id = ?', [id]);
        if (!scan) return null;
        return this._parse(scan);
    }

    static findByUser(userId, limit = 20, offset = 0) {
        const scans = db.all(
            'SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
            [userId, limit, offset]
        );
        return scans.map(this._parse);
    }

    static updateStatus(id, status, progress = null) {
        if (progress !== null) {
            db.run('UPDATE scans SET status = ?, progress = ? WHERE id = ?', [status, progress, id]);
        } else {
            db.run('UPDATE scans SET status = ? WHERE id = ?', [status, id]);
        }
    }

    static updateProgress(id, progress) {
        db.run('UPDATE scans SET progress = ? WHERE id = ?', [progress, id]);
    }

    static saveResults(id, results, aiSummary, severitySummary) {
        db.run(
            `UPDATE scans 
       SET status = 'complete', progress = 100, results = ?, ai_summary = ?, 
           severity_summary = ?, completed_at = ?
       WHERE id = ?`,
            [JSON.stringify(results), aiSummary, JSON.stringify(severitySummary), new Date().toISOString(), id]
        );
    }

    static fail(id, errorMsg) {
        db.run(
            `UPDATE scans SET status = 'failed', ai_summary = ?, completed_at = ? WHERE id = ?`,
            [errorMsg, new Date().toISOString(), id]
        );
    }

    static _parse(scan) {
        return {
            ...scan,
            results: scan.results ? JSON.parse(scan.results) : null,
            severity_summary: scan.severity_summary ? JSON.parse(scan.severity_summary) : null,
        };
    }
}

module.exports = ScanModel;
