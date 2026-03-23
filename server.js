'use strict';

/**
 * server.js — Student 2 Standalone Application
 *
 * UHC Clinic: Appointment & Scheduling + Barcode Scanner Interface
 *
 * Security stack:
 *   • Helmet.js          — HTTP security headers
 *   • express-session    — server-side session management
 *   • bcryptjs           — password hashing (10 rounds)
 *   • otplib TOTP        — multi-factor authentication
 *   • csrf-csrf          — double-submit CSRF protection
 *   • express-rate-limit — brute-force / DoS mitigation
 *   • express-validator  — input validation & sanitisation
 *   • RBAC middleware    — role-based access control
 *   • Audit logging      — HIPAA-compliant action trail
 */

const express      = require('express');
const path         = require('path');
const fs           = require('fs');
const http         = require('http');
const https        = require('https');
const session      = require('express-session');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

require('dotenv').config();

const app = express();

// ─────────────────────────────────────────────────────────────────────────────
// Security headers
// ─────────────────────────────────────────────────────────────────────────────
app.use(helmet());

// ─────────────────────────────────────────────────────────────────────────────
// Body parsing + views
// ─────────────────────────────────────────────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─────────────────────────────────────────────────────────────────────────────
// Cookie parser (must precede csrf-csrf)
// ─────────────────────────────────────────────────────────────────────────────
app.use(cookieParser());

// ─────────────────────────────────────────────────────────────────────────────
// Session
// ─────────────────────────────────────────────────────────────────────────────
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-this-default-secret-in-env',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 1000  // 1 hour
    }
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// CSRF protection
// ─────────────────────────────────────────────────────────────────────────────
const csrf = doubleCsrf({
  getSecret: () => process.env.SESSION_SECRET || 'change-this-default-secret-in-env',
  getSessionIdentifier: (req) => req.sessionID,
  getCsrfTokenFromRequest: (req) => req.body?._csrf,
  cookieName: '_csrf',
  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/'
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
});

app.use(csrf.doubleCsrfProtection);

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.csrfToken   = csrf.generateCsrfToken(req, res);
  next();
});

// ─────────────────────────────────────────────────────────────────────────────
// Rate limiting
// ─────────────────────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many attempts from this IP. Please try again after 15 minutes.'
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/login',      authLimiter);
app.use('/register',   authLimiter);
app.use('/mfa-verify', authLimiter);
app.use('/',           generalLimiter);

// ─────────────────────────────────────────────────────────────────────────────
// Routes
// ─────────────────────────────────────────────────────────────────────────────
const authRoutes         = require('./routes/auth');
const appointmentRoutes  = require('./routes/appointments');
const barcodeRoutes      = require('./routes/barcode');

app.use('/', authRoutes);
app.use('/', appointmentRoutes);
app.use('/', barcodeRoutes);

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard
// ─────────────────────────────────────────────────────────────────────────────
const { isAuthenticated, requireRole } = require('./middleware/authMiddleware');
const db = require('./config/db');

app.get('/dashboard', isAuthenticated, (req, res) => {
  const flash = req.session.flash || {};
  delete req.session.flash;

  res.render('dashboard', {
    user:    req.session.user,
    success: flash.success || null
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Audit logs (admin only)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/audit-logs', isAuthenticated, requireRole('admin'), async (req, res) => {
  try {
    const [logs] = await db.query(
      'SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500'
    );
    res.render('audit-logs', { user: req.session.user, logs });
  } catch (err) {
    console.error('Audit logs error:', err);
    res.render('audit-logs', { user: req.session.user, logs: [] });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 404 handler
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).render('error', {
    message: 'Page not found.',
    user:    req.session.user || null
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// HTTPS / HTTP server
// ─────────────────────────────────────────────────────────────────────────────
const PORT     = process.env.PORT || 3001;
const certPath = process.env.HTTPS_CERT;
const keyPath  = process.env.HTTPS_KEY;

if (certPath && keyPath && fs.existsSync(certPath) && fs.existsSync(keyPath)) {
  const tlsOptions = {
    cert: fs.readFileSync(certPath),
    key:  fs.readFileSync(keyPath)
  };
  https.createServer(tlsOptions, app).listen(PORT, () => {
    console.log(`[Student 2] Server running on https://localhost:${PORT}  [HTTPS]`);
  });
} else {
  http.createServer(app).listen(PORT, () => {
    console.log(`[Student 2] Server running on http://localhost:${PORT}  [HTTP — set HTTPS_CERT/HTTPS_KEY for TLS]`);
  });
}
