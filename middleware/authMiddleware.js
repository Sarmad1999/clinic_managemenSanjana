/**
 * middleware/authMiddleware.js
 *
 * isAuthenticated — session gate
 * requireRole     — RBAC enforcement with audit logging on denial
 */
'use strict';

const { logAction } = require('./auditLogger');

function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  req.session.returnTo = req.originalUrl;
  res.redirect('/login');
}

function requireRole(...roles) {
  return async (req, res, next) => {
    if (!req.session || !req.session.user) {
      return res.redirect('/login');
    }
    if (!roles.includes(req.session.user.role)) {
      const db = require('../config/db');
      await logAction(db, {
        userId:      req.session.user.user_id,
        username:    req.session.user.username,
        role:        req.session.user.role,
        action:      'UNAUTHORIZED_ACCESS',
        targetTable: null,
        targetId:    null,
        ip:          req.ip,
        result:      'denied',
        details:     `Attempted to access ${req.originalUrl} — requires role(s): ${roles.join(', ')}`
      });
      return res.status(403).render('error', {
        message: 'Access Denied: You do not have permission to view this page.',
        user:    req.session.user
      });
    }
    next();
  };
}

module.exports = { isAuthenticated, requireRole };
