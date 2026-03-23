'use strict';

/**
 * routes/appointments.js
 *
 * Appointment & Scheduling module (Student 2)
 *
 * Features:
 *   • View / filter appointments (by date, type, status) — color-coded
 *   • Create / edit / cancel / complete appointments
 *   • Appointment types: doctor, laboratory, radiology
 *   • Status lifecycle: scheduled → confirmed → completed / cancelled / no_show
 *
 * Security:
 *   • isAuthenticated + requireRole on every route
 *   • express-validator validation on all mutations
 *   • CSRF tokens (global doubleCsrf in server.js)
 *   • Parameterised SQL queries
 *   • HIPAA-compliant audit logging on every mutation
 */

const express = require('express');
const router  = express.Router();
const { body, validationResult } = require('express-validator');
const db      = require('../config/db');
const { isAuthenticated, requireRole } = require('../middleware/authMiddleware');
const { logAction } = require('../middleware/auditLogger');

// ─── Constants ────────────────────────────────────────────────────────────────

const APPOINTMENT_TYPES    = ['doctor', 'laboratory', 'radiology'];
const APPOINTMENT_STATUSES = ['scheduled', 'confirmed', 'cancelled', 'completed', 'no_show'];

const TYPE_COLOR_MAP = {
  doctor:     '#0d6efd',
  laboratory: '#198754',
  radiology:  '#6f42c1'
};

const STATUS_BADGE = {
  scheduled: 'primary',
  confirmed: 'success',
  cancelled: 'secondary',
  completed: 'info',
  no_show:   'warning'
};

const DURATION_OPTIONS = [15, 30, 45, 60, 90, 120];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseId(str) {
  const n = parseInt(str, 10);
  return Number.isFinite(n) && n > 0 ? n : NaN;
}

// ─── Shared validators ────────────────────────────────────────────────────────

const appointmentValidators = [
  body('patient_id')
    .isInt({ min: 1 }).withMessage('A valid patient must be selected'),
  body('appointment_type')
    .isIn(APPOINTMENT_TYPES).withMessage('Invalid appointment type'),
  body('appointment_date')
    .isISO8601().withMessage('A valid date is required'),
  body('appointment_time')
    .matches(/^\d{2}:\d{2}$/).withMessage('Time must be in HH:MM format'),
  body('duration_minutes')
    .isInt({ min: 5, max: 480 }).withMessage('Duration must be 5–480 minutes'),
  body('provider_id')
    .optional({ checkFalsy: true })
    .isInt({ min: 1 }).withMessage('Invalid provider'),
  body('status')
    .isIn(APPOINTMENT_STATUSES).withMessage('Invalid status'),
  body('notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 1000 }).withMessage('Notes must not exceed 1 000 characters')
];

// ─── Load form dropdowns helper ───────────────────────────────────────────────

async function loadDropdowns() {
  const [patients]  = await db.query(
    'SELECT patient_id, full_name FROM patients ORDER BY full_name'
  );
  const [providers] = await db.query(
    "SELECT user_id, username FROM users WHERE role IN ('doctor','admin') ORDER BY username"
  );
  return { patients, providers };
}

// ═══════════════════════════════════════════════════════════════════════════════
// APPOINTMENT ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ─── GET /appointments ────────────────────────────────────────────────────────
router.get(
  '/appointments',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  async (req, res) => {
    try {
      const { date, status, type } = req.query;

      let where  = 'WHERE 1=1';
      const params = [];

      if (date) {
        where += ' AND a.appointment_date = ?';
        params.push(date);
      }
      if (status && APPOINTMENT_STATUSES.includes(status)) {
        where += ' AND a.status = ?';
        params.push(status);
      }
      if (type && APPOINTMENT_TYPES.includes(type)) {
        where += ' AND a.appointment_type = ?';
        params.push(type);
      }

      const [appointments] = await db.query(
        `SELECT a.*,
                p.full_name AS patient_name,
                u.username  AS provider_name
           FROM appointments a
           JOIN patients p ON a.patient_id = p.patient_id
           LEFT JOIN users u ON a.provider_id = u.user_id
           ${where}
           ORDER BY a.appointment_date DESC, a.appointment_time DESC`,
        params
      );

      const flash = req.session.flash || {};
      delete req.session.flash;

      res.render('appointments', {
        appointments,
        user:    req.session.user,
        filters: { date: date || '', status: status || '', type: type || '' },
        APPOINTMENT_TYPES,
        APPOINTMENT_STATUSES,
        STATUS_BADGE,
        TYPE_COLOR_MAP,
        success: flash.success || null,
        errors:  []
      });
    } catch (err) {
      console.error('Appointments list error:', err);
      res.render('appointments', {
        appointments: [],
        user:    req.session.user,
        filters: {},
        APPOINTMENT_TYPES,
        APPOINTMENT_STATUSES,
        STATUS_BADGE,
        TYPE_COLOR_MAP,
        success: null,
        errors:  [{ msg: 'Failed to load appointments.' }]
      });
    }
  }
);

// ─── GET /appointments/new ────────────────────────────────────────────────────
router.get(
  '/appointments/new',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  async (req, res) => {
    try {
      const { patients, providers } = await loadDropdowns();
      res.render('appointment-new', {
        user:               req.session.user,
        patients,
        providers,
        APPOINTMENT_TYPES,
        APPOINTMENT_STATUSES,
        DURATION_OPTIONS,
        errors: [],
        form:   { patient_id: req.query.patient_id || '' }
      });
    } catch (err) {
      console.error('Appointment new form error:', err);
      res.render('error', { message: 'Failed to load form.', user: req.session.user });
    }
  }
);

// ─── POST /appointments ───────────────────────────────────────────────────────
router.post(
  '/appointments',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  appointmentValidators,
  async (req, res) => {
    const valErrors = validationResult(req);

    if (!valErrors.isEmpty()) {
      const { patients, providers } = await loadDropdowns();
      return res.render('appointment-new', {
        user: req.session.user, patients, providers,
        APPOINTMENT_TYPES, APPOINTMENT_STATUSES, DURATION_OPTIONS,
        errors: valErrors.array(), form: req.body
      });
    }

    const {
      patient_id, appointment_type, appointment_date, appointment_time,
      duration_minutes, provider_id, notes, status
    } = req.body;

    const color_code = TYPE_COLOR_MAP[appointment_type] || '#0d6efd';

    try {
      const [result] = await db.query(
        `INSERT INTO appointments
           (patient_id, provider_id, appointment_type, appointment_date, appointment_time,
            duration_minutes, status, notes, color_code, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          patient_id, provider_id || null, appointment_type,
          appointment_date, appointment_time, duration_minutes,
          status, notes || null, color_code, req.session.user.user_id
        ]
      );

      await logAction(db, {
        userId:      req.session.user.user_id,
        username:    req.session.user.username,
        role:        req.session.user.role,
        action:      'CREATE_APPOINTMENT',
        targetTable: 'appointments',
        targetId:    result.insertId,
        ip:          req.ip,
        result:      'success',
        details:     `Appointment for patient #${patient_id} on ${appointment_date} ${appointment_time} (${appointment_type})`
      });

      req.session.flash = { success: 'Appointment scheduled successfully.' };
      res.redirect('/appointments');
    } catch (err) {
      console.error('Create appointment error:', err);
      const { patients, providers } = await loadDropdowns();
      res.render('appointment-new', {
        user: req.session.user, patients, providers,
        APPOINTMENT_TYPES, APPOINTMENT_STATUSES, DURATION_OPTIONS,
        errors: [{ msg: 'Database error — appointment not saved. Please try again.' }],
        form: req.body
      });
    }
  }
);

// ─── GET /appointments/:id/edit ───────────────────────────────────────────────
router.get(
  '/appointments/:id/edit',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  async (req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) {
      return res.status(404).render('error', { message: 'Appointment not found.', user: req.session.user });
    }

    try {
      const [[appt]] = await db.query(
        'SELECT * FROM appointments WHERE appointment_id = ?', [id]
      );
      if (!appt) {
        return res.status(404).render('error', { message: 'Appointment not found.', user: req.session.user });
      }

      const { patients, providers } = await loadDropdowns();

      const dateStr = appt.appointment_date
        ? new Date(appt.appointment_date).toISOString().split('T')[0] : '';
      const timeStr = appt.appointment_time
        ? String(appt.appointment_time).slice(0, 5) : '';

      res.render('appointment-edit', {
        user: req.session.user,
        appt: { ...appt, appointment_date: dateStr, appointment_time: timeStr },
        patients, providers,
        APPOINTMENT_TYPES, APPOINTMENT_STATUSES, DURATION_OPTIONS, STATUS_BADGE,
        errors: []
      });
    } catch (err) {
      console.error('Appointment edit load error:', err);
      res.render('error', { message: 'Failed to load appointment.', user: req.session.user });
    }
  }
);

// ─── POST /appointments/:id/edit ──────────────────────────────────────────────
router.post(
  '/appointments/:id/edit',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  appointmentValidators,
  async (req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) {
      return res.status(404).render('error', { message: 'Appointment not found.', user: req.session.user });
    }

    const valErrors = validationResult(req);
    if (!valErrors.isEmpty()) {
      const [[appt]]    = await db.query('SELECT * FROM appointments WHERE appointment_id = ?', [id]);
      const { patients, providers } = await loadDropdowns();
      return res.render('appointment-edit', {
        user: req.session.user,
        appt: { ...(appt || {}), ...req.body, appointment_id: id },
        patients, providers,
        APPOINTMENT_TYPES, APPOINTMENT_STATUSES, DURATION_OPTIONS, STATUS_BADGE,
        errors: valErrors.array()
      });
    }

    const {
      patient_id, appointment_type, appointment_date, appointment_time,
      duration_minutes, provider_id, notes, status
    } = req.body;

    const color_code = TYPE_COLOR_MAP[appointment_type] || '#0d6efd';

    try {
      await db.query(
        `UPDATE appointments
            SET patient_id       = ?,
                provider_id      = ?,
                appointment_type = ?,
                appointment_date = ?,
                appointment_time = ?,
                duration_minutes = ?,
                status           = ?,
                notes            = ?,
                color_code       = ?
          WHERE appointment_id   = ?`,
        [
          patient_id, provider_id || null, appointment_type,
          appointment_date, appointment_time, duration_minutes,
          status, notes || null, color_code, id
        ]
      );

      await logAction(db, {
        userId:      req.session.user.user_id,
        username:    req.session.user.username,
        role:        req.session.user.role,
        action:      'UPDATE_APPOINTMENT',
        targetTable: 'appointments',
        targetId:    id,
        ip:          req.ip,
        result:      'success',
        details:     `Updated appointment #${id} → status: ${status}`
      });

      req.session.flash = { success: 'Appointment updated successfully.' };
      res.redirect('/appointments');
    } catch (err) {
      console.error('Update appointment error:', err);
      res.render('error', { message: 'Failed to update appointment.', user: req.session.user });
    }
  }
);

// ─── POST /appointments/:id/cancel ────────────────────────────────────────────
router.post(
  '/appointments/:id/cancel',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  async (req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.redirect('/appointments');

    try {
      await db.query(
        "UPDATE appointments SET status = 'cancelled' WHERE appointment_id = ?", [id]
      );
      await logAction(db, {
        userId:      req.session.user.user_id,
        username:    req.session.user.username,
        role:        req.session.user.role,
        action:      'CANCEL_APPOINTMENT',
        targetTable: 'appointments',
        targetId:    id,
        ip:          req.ip,
        result:      'success',
        details:     `Cancelled appointment #${id}`
      });
      req.session.flash = { success: 'Appointment cancelled.' };
    } catch (err) {
      console.error('Cancel appointment error:', err);
      req.session.flash = { success: 'Error: Could not cancel appointment. Please try again.' };
    }
    res.redirect('/appointments');
  }
);

// ─── POST /appointments/:id/complete ──────────────────────────────────────────
router.post(
  '/appointments/:id/complete',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  async (req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.redirect('/appointments');

    try {
      await db.query(
        "UPDATE appointments SET status = 'completed' WHERE appointment_id = ?", [id]
      );
      await logAction(db, {
        userId:      req.session.user.user_id,
        username:    req.session.user.username,
        role:        req.session.user.role,
        action:      'COMPLETE_APPOINTMENT',
        targetTable: 'appointments',
        targetId:    id,
        ip:          req.ip,
        result:      'success',
        details:     `Marked appointment #${id} as completed`
      });
      req.session.flash = { success: 'Appointment marked as completed.' };
    } catch (err) {
      console.error('Complete appointment error:', err);
    }
    res.redirect('/appointments');
  }
);

module.exports = router;
