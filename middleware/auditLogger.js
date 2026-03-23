/**
 * middleware/auditLogger.js
 *
 * Inserts a row into audit_logs for every significant user action.
 * Supports HIPAA audit trail requirements.
 */
'use strict';

async function logAction(db, {
  userId      = null,
  username    = null,
  role        = null,
  action,
  targetTable = null,
  targetId    = null,
  ip          = null,
  result      = 'success',
  details     = null
}) {
  try {
    await db.query(
      `INSERT INTO audit_logs
         (user_id, username, role, action, target_table, target_id, ip_address, result, details)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [userId, username, role, action, targetTable, targetId, ip, result, details]
    );
  } catch (err) {
    // Never let audit-log failures crash the application
    console.error('[Student 2] Audit log error:', err.message);
  }
}

module.exports = { logAction };
