'use strict';

/**
 * routes/patients.js
 *
 * Patient management module
 *
 * Features:
 *   • Add new patient records
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

// ─── Validators ───────────────────────────────────────────────────────────────

const patientValidators = [
  body('full_name')
    .trim()
    .notEmpty().withMessage('Full name is required')
    .isLength({ max: 150 }).withMessage('Full name must not exceed 150 characters'),
  body('age')
    .optional({ checkFalsy: true })
    .isInt({ min: 0, max: 150 }).withMessage('Age must be a number between 0 and 150'),
  body('gender')
    .optional({ checkFalsy: true })
    .isIn(['Male', 'Female', 'Other']).withMessage('Invalid gender value'),
  body('phone')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 50 }).withMessage('Phone must not exceed 50 characters'),
  body('email')
    .optional({ checkFalsy: true })
    .trim()
    .isEmail().withMessage('A valid email address is required')
    .isLength({ max: 150 }).withMessage('Email must not exceed 150 characters'),
  body('date_of_birth')
    .optional({ checkFalsy: true })
    .isISO8601().withMessage('Date of birth must be a valid date')
    .toDate(),
  body('address')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 255 }).withMessage('Address must not exceed 255 characters'),
  body('preferred_language')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 50 }).withMessage('Language must not exceed 50 characters'),
  body('insurance_info')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 255 }).withMessage('Insurance info must not exceed 255 characters')
];

// ═══════════════════════════════════════════════════════════════════════════════
// PATIENT ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ─── GET /patients/new ────────────────────────────────────────────────────────
router.get(
  '/patients/new',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  (req, res) => {
    res.render('patient-new', {
      user:   req.session.user,
      errors: [],
      form:   {}
    });
  }
);

// ─── POST /patients ───────────────────────────────────────────────────────────
router.post(
  '/patients',
  isAuthenticated,
  requireRole('admin', 'doctor', 'receptionist'),
  patientValidators,
  async (req, res) => {
    const valErrors = validationResult(req);

    if (!valErrors.isEmpty()) {
      return res.render('patient-new', {
        user:   req.session.user,
        errors: valErrors.array(),
        form:   req.body
      });
    }

    const {
      full_name, age, gender, phone, email,
      date_of_birth, address, preferred_language, insurance_info
    } = req.body;

    try {
      const [result] = await db.query(
        `INSERT INTO patients
           (full_name, age, gender, phone, email,
            date_of_birth, address, preferred_language, insurance_info)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          full_name,
          age        || null,
          gender     || null,
          phone      || null,
          email      || null,
          date_of_birth || null,
          address    || null,
          preferred_language || 'English',
          insurance_info || null
        ]
      );

      await logAction(db, {
        userId:      req.session.user.user_id,
        username:    req.session.user.username,
        role:        req.session.user.role,
        action:      'CREATE_PATIENT',
        targetTable: 'patients',
        targetId:    result.insertId,
        ip:          req.ip,
        result:      'success',
        details:     `Added new patient: ${full_name} (ID #${result.insertId})`
      });

      req.session.flash = { success: `Patient "${full_name}" added successfully.` };
      res.redirect('/dashboard');
    } catch (err) {
      console.error('Create patient error:', err);
      res.render('patient-new', {
        user:   req.session.user,
        errors: [{ msg: 'Database error — patient not saved. Please try again.' }],
        form:   req.body
      });
    }
  }
);

module.exports = router;
