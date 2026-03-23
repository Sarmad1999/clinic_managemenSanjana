'use strict';

/**
 * routes/auth.js
 *
 * Authentication routes: login, register, logout, MFA setup/verify.
 *
 * Security controls:
 *   • bcryptjs (10 rounds) password hashing
 *   • TOTP MFA via otplib
 *   • express-validator input validation
 *   • CSRF tokens (applied globally in server.js)
 *   • Audit logging on login/logout/register/MFA events
 *   • Rate limiting applied globally in server.js
 */

const express   = require('express');
const router    = express.Router();
const bcrypt    = require('bcryptjs');
const { authenticator } = require('otplib');
const QRCode    = require('qrcode');
const { body, validationResult } = require('express-validator');
const db        = require('../config/db');
const { logAction } = require('../middleware/auditLogger');

// ─── GET /login ──────────────────────────────────────────────────────────────
router.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  const flash = req.session.flash || {};
  delete req.session.flash;
  res.render('login', { error: flash.error || null, success: flash.success || null });
});

// ─── POST /login ─────────────────────────────────────────────────────────────
router.post('/login', [
  body('username').trim().notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('login', { error: errors.array()[0].msg, success: null });
  }

  const { username, password } = req.body;
  const ip = req.ip;

  try {
    const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);

    if (rows.length === 0) {
      await logAction(db, {
        username, action: 'LOGIN_FAILED', targetTable: 'users',
        ip, result: 'failure', details: 'User not found'
      });
      return res.render('login', { error: 'Invalid username or password.', success: null });
    }

    const user  = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      await logAction(db, {
        userId: user.user_id, username, role: user.role,
        action: 'LOGIN_FAILED', targetTable: 'users', targetId: user.user_id,
        ip, result: 'failure', details: 'Wrong password'
      });
      return res.render('login', { error: 'Invalid username or password.', success: null });
    }

    if (user.mfa_enabled) {
      req.session.pendingUser = {
        user_id: user.user_id, username: user.username,
        email: user.email, role: user.role, mfa_enabled: user.mfa_enabled
      };
      return res.redirect('/mfa-verify');
    }

    req.session.user = {
      user_id: user.user_id, username: user.username,
      email: user.email, role: user.role, mfa_enabled: user.mfa_enabled
    };

    await logAction(db, {
      userId: user.user_id, username: user.username, role: user.role,
      action: 'LOGIN_SUCCESS', targetTable: 'users', targetId: user.user_id,
      ip, result: 'success', details: 'Login without MFA'
    });

    const returnTo = req.session.returnTo || '/dashboard';
    delete req.session.returnTo;
    res.redirect(returnTo);

  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { error: 'Server error. Please try again.', success: null });
  }
});

// ─── GET /register ───────────────────────────────────────────────────────────
router.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('register', { error: null, success: null });
});

// ─── POST /register ──────────────────────────────────────────────────────────
router.post('/register', [
  body('username').trim().notEmpty().isLength({ min: 3, max: 50 })
    .withMessage('Username must be 3–50 characters'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('confirm_password').custom((val, { req }) => {
    if (val !== req.body.password) throw new Error('Passwords do not match');
    return true;
  }),
  body('role').isIn(['admin', 'doctor', 'receptionist']).withMessage('Invalid role')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('register', { error: errors.array()[0].msg, success: null });
  }

  const { username, email, password, role } = req.body;
  const ip = req.ip;

  try {
    const [existing] = await db.query(
      'SELECT user_id FROM users WHERE username = ? OR email = ?',
      [username, email]
    );
    if (existing.length > 0) {
      return res.render('register', { error: 'Username or email is already taken.', success: null });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
      [username, email, passwordHash, role]
    );

    await logAction(db, {
      userId: result.insertId, username, role,
      action: 'USER_REGISTERED', targetTable: 'users', targetId: result.insertId,
      ip, result: 'success', details: `New ${role} account registered`
    });

    res.render('register', { error: null, success: 'Account created! You can now log in.' });

  } catch (err) {
    console.error('Register error:', err);
    res.render('register', { error: 'Server error. Please try again.', success: null });
  }
});

// ─── GET /logout ─────────────────────────────────────────────────────────────
router.get('/logout', async (req, res) => {
  if (req.session.user) {
    const { user_id, username, role } = req.session.user;
    await logAction(db, {
      userId: user_id, username, role,
      action: 'LOGOUT', targetTable: 'users', targetId: user_id,
      ip: req.ip, result: 'success', details: null
    });
  }
  req.session.destroy(() => res.redirect('/login'));
});

// ─── GET /mfa-verify ─────────────────────────────────────────────────────────
router.get('/mfa-verify', (req, res) => {
  if (!req.session.pendingUser) return res.redirect('/login');
  res.render('mfa-verify', { error: null });
});

// ─── POST /mfa-verify ────────────────────────────────────────────────────────
router.post('/mfa-verify', async (req, res) => {
  if (!req.session.pendingUser) return res.redirect('/login');

  const { token } = req.body;
  const pending   = req.session.pendingUser;
  const ip        = req.ip;

  try {
    const [rows] = await db.query('SELECT * FROM users WHERE user_id = ?', [pending.user_id]);
    if (rows.length === 0) return res.redirect('/login');

    const user    = rows[0];
    const isValid = authenticator.verify({ token: String(token).trim(), secret: user.mfa_secret });

    if (!isValid) {
      await logAction(db, {
        userId: user.user_id, username: user.username, role: user.role,
        action: 'MFA_FAILED', targetTable: 'users', targetId: user.user_id,
        ip, result: 'failure', details: 'Invalid TOTP code'
      });
      return res.render('mfa-verify', { error: 'Invalid authentication code. Please try again.' });
    }

    delete req.session.pendingUser;
    req.session.user = {
      user_id: user.user_id, username: user.username,
      email: user.email, role: user.role, mfa_enabled: user.mfa_enabled
    };

    await logAction(db, {
      userId: user.user_id, username: user.username, role: user.role,
      action: 'LOGIN_SUCCESS', targetTable: 'users', targetId: user.user_id,
      ip, result: 'success', details: 'Login with MFA verified'
    });

    const returnTo = req.session.returnTo || '/dashboard';
    delete req.session.returnTo;
    res.redirect(returnTo);

  } catch (err) {
    console.error('MFA verify error:', err);
    res.render('mfa-verify', { error: 'Server error. Please try again.' });
  }
});

// ─── GET /mfa-setup ──────────────────────────────────────────────────────────
router.get('/mfa-setup', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  try {
    const secret     = authenticator.generateSecret();
    const otpAuthUrl = authenticator.keyuri(req.session.user.username, 'UHC Clinic', secret);
    const qrImage    = await QRCode.toDataURL(otpAuthUrl);

    req.session.mfaSetupSecret = secret;
    res.render('mfa-setup', { qrImage, secret, error: null, success: null, user: req.session.user });
  } catch (err) {
    console.error('MFA setup error:', err);
    res.redirect('/dashboard');
  }
});

// ─── POST /mfa-setup ─────────────────────────────────────────────────────────
router.post('/mfa-setup', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const { token } = req.body;
  const secret    = req.session.mfaSetupSecret;
  if (!secret) return res.redirect('/mfa-setup');

  const isValid = authenticator.verify({ token: String(token).trim(), secret });

  if (!isValid) {
    try {
      const otpAuthUrl = authenticator.keyuri(req.session.user.username, 'UHC Clinic', secret);
      const qrImage    = await QRCode.toDataURL(otpAuthUrl);
      return res.render('mfa-setup', {
        qrImage, secret,
        error: 'Invalid code. Please scan the QR code and try again.',
        success: null, user: req.session.user
      });
    } catch {
      return res.redirect('/mfa-setup');
    }
  }

  try {
    await db.query(
      'UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE user_id = ?',
      [secret, req.session.user.user_id]
    );

    req.session.user.mfa_enabled = 1;
    delete req.session.mfaSetupSecret;

    await logAction(db, {
      userId:      req.session.user.user_id,
      username:    req.session.user.username,
      role:        req.session.user.role,
      action:      'MFA_ENABLED',
      targetTable: 'users',
      targetId:    req.session.user.user_id,
      ip:          req.ip,
      result:      'success',
      details:     'MFA setup completed successfully'
    });

    req.session.flash = { success: 'Two-factor authentication enabled successfully!' };
    res.redirect('/dashboard');

  } catch (err) {
    console.error('MFA save error:', err);
    res.redirect('/mfa-setup');
  }
});

module.exports = router;
