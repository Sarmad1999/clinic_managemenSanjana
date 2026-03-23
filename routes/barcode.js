'use strict';

/**
 * routes/barcode.js
 *
 * Barcode Scanner Interface module (Student 2)
 *
 * Features:
 *   • Scan patient wristband barcodes (USB/Bluetooth HID keyboard-wedge + manual)
 *   • Look up patient record and upcoming appointments by barcode
 *   • Issue / re-issue barcode wristbands (admin + receptionist)
 *   • View / print wristband with Code 128 barcode SVG
 *
 * Security:
 *   • isAuthenticated + requireRole on every route
 *   • express-validator on all inputs (allowlist regex)
 *   • CSRF tokens (global doubleCsrf in server.js)
 *   • Parameterised SQL queries
 *   • HIPAA-compliant audit logging (scan found / not_found / issue)
 */

const express = require('express');
const router  = express.Router();
const { body, validationResult } = require('express-validator');
const db      = require('../config/db');
const { isAuthenticated, requireRole } = require('../middleware/authMiddleware');
const { logAction } = require('../middleware/auditLogger');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseId(str) {
  const n = parseInt(str, 10);
  return Number.isFinite(n) && n > 0 ? n : NaN;
}

// ═══════════════════════════════════════════════════════════════════════════════
// BARCODE SCANNER ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ─── GET /scan-barcode ────────────────────────────────────────────────────────
router.get(
  '/scan-barcode',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  (req, res) => {
    res.render('scan-barcode', {
      user:        req.session.user,
      patientData: null,
      error:       null
    });
  }
);

// ─── POST /scan-barcode ───────────────────────────────────────────────────────
router.post(
  '/scan-barcode',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  [
    body('barcode_data')
      .trim()
      .notEmpty().withMessage('Barcode data is required')
      .isLength({ max: 200 }).withMessage('Barcode data is too long')
      .matches(/^[\w\-.:]+$/).withMessage('Barcode contains invalid characters')
  ],
  async (req, res) => {
    const valErrors = validationResult(req);
    if (!valErrors.isEmpty()) {
      return res.render('scan-barcode', {
        user: req.session.user, patientData: null,
        error: valErrors.array()[0].msg
      });
    }

    const { barcode_data } = req.body;

    try {
      let patient = null;

      // 1. Try the barcode_wristbands table
      const [[wristband]] = await db.query(
        `SELECT bw.barcode_data, p.*
           FROM barcode_wristbands bw
           JOIN patients p ON bw.patient_id = p.patient_id
          WHERE bw.barcode_data = ?
          LIMIT 1`,
        [barcode_data]
      );

      if (wristband) {
        const { barcode_data: _bc, ...patientFields } = wristband;
        patient = patientFields;
      } else {
        // 2. BC-{id}-{timestamp} fallback
        const match = barcode_data.match(/^BC-(\d+)-\d+$/);
        if (match) {
          const [[p]] = await db.query(
            'SELECT * FROM patients WHERE patient_id = ? LIMIT 1',
            [parseInt(match[1], 10)]
          );
          if (p) patient = p;
        }
      }

      if (!patient) {
        await logAction(db, {
          userId:      req.session.user.user_id,
          username:    req.session.user.username,
          role:        req.session.user.role,
          action:      'SCAN_BARCODE',
          targetTable: 'barcode_wristbands',
          targetId:    null,
          ip:          req.ip,
          result:      'not_found',
          details:     `Barcode lookup failed: ${barcode_data}`
        });
        return res.render('scan-barcode', {
          user: req.session.user, patientData: null,
          error: `No patient found for barcode: ${barcode_data}`
        });
      }

      const [appointments] = await db.query(
        `SELECT a.*, u.username AS provider_name
           FROM appointments a
           LEFT JOIN users u ON a.provider_id = u.user_id
          WHERE a.patient_id = ?
          ORDER BY a.appointment_date DESC, a.appointment_time DESC
          LIMIT 5`,
        [patient.patient_id]
      );

      await logAction(db, {
        userId:      req.session.user.user_id,
        username:    req.session.user.username,
        role:        req.session.user.role,
        action:      'SCAN_BARCODE',
        targetTable: 'patients',
        targetId:    patient.patient_id,
        ip:          req.ip,
        result:      'success',
        details:     `Barcode scan matched patient #${patient.patient_id} (${patient.full_name})`
      });

      res.render('scan-barcode', {
        user:        req.session.user,
        patientData: { patient, appointments },
        error:       null
      });
    } catch (err) {
      console.error('Barcode scan error:', err);
      res.render('scan-barcode', {
        user: req.session.user, patientData: null,
        error: 'A server error occurred during barcode lookup. Please try again.'
      });
    }
  }
);

// ─── GET /barcode-wristband/:patient_id ───────────────────────────────────────
router.get(
  '/barcode-wristband/:patient_id',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  async (req, res) => {
    const pid = parseId(req.params.patient_id);
    if (isNaN(pid)) {
      return res.status(404).render('error', { message: 'Patient not found.', user: req.session.user });
    }

    try {
      const [[patient]] = await db.query(
        'SELECT * FROM patients WHERE patient_id = ? LIMIT 1', [pid]
      );
      if (!patient) {
        return res.status(404).render('error', { message: 'Patient not found.', user: req.session.user });
      }

      const [[wristband]] = await db.query(
        'SELECT * FROM barcode_wristbands WHERE patient_id = ? ORDER BY issued_at DESC LIMIT 1',
        [pid]
      );

      const flash = req.session.flash || {};
      delete req.session.flash;

      res.render('wristband-barcode', {
        user:      req.session.user,
        patient,
        wristband: wristband || null,
        success:   flash.success || null,
        error:     null
      });
    } catch (err) {
      console.error('Barcode wristband view error:', err);
      res.render('error', { message: 'Failed to load wristband page.', user: req.session.user });
    }
  }
);

// ─── POST /barcode-wristband ──────────────────────────────────────────────────
router.post(
  '/barcode-wristband',
  isAuthenticated,
  requireRole('admin', 'receptionist'),
  [
    body('patient_id').isInt({ min: 1 }).withMessage('Invalid patient ID')
  ],
  async (req, res) => {
    const valErrors = validationResult(req);
    if (!valErrors.isEmpty()) {
      return res.status(400).render('error', {
        message: valErrors.array()[0].msg, user: req.session.user
      });
    }

    const pid = parseInt(req.body.patient_id, 10);

    try {
      const [[patient]] = await db.query(
        'SELECT * FROM patients WHERE patient_id = ? LIMIT 1', [pid]
      );
      if (!patient) {
        return res.status(404).render('error', {
          message: 'Patient not found.', user: req.session.user
        });
      }

      // Unique, URL-safe barcode
      const barcode_data = `BC-${pid}-${Date.now()}`;

      await db.query(
        'INSERT INTO barcode_wristbands (patient_id, barcode_data, issued_by) VALUES (?, ?, ?)',
        [pid, barcode_data, req.session.user.user_id]
      );

      await logAction(db, {
        userId:      req.session.user.user_id,
        username:    req.session.user.username,
        role:        req.session.user.role,
        action:      'ISSUE_BARCODE_WRISTBAND',
        targetTable: 'barcode_wristbands',
        targetId:    pid,
        ip:          req.ip,
        result:      'success',
        details:     `Issued barcode wristband ${barcode_data} for patient #${pid}`
      });

      req.session.flash = { success: `Barcode wristband issued: ${barcode_data}` };
      res.redirect(`/barcode-wristband/${pid}`);
    } catch (err) {
      console.error('Issue barcode wristband error:', err);
      res.render('error', {
        message: 'Failed to issue barcode wristband.', user: req.session.user
      });
    }
  }
);

module.exports = router;
