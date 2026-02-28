const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const {
    startScan,
    getScanStatus,
    getScanResult,
    listScans,
    startScanValidation,
} = require('../controllers/scanController');

router.use(authMiddleware);

router.get('/', listScans);
router.post('/', startScanValidation, startScan);
router.get('/:id/status', getScanStatus);
router.get('/:id/results', getScanResult);

module.exports = router;
