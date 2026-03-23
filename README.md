# UHC Clinic — Student 2 Subsystem

**Appointment & Scheduling + Barcode Scanner Interface**

United Health Care Clinic Management System — Student 2 standalone application.

---

## Modules covered

| Module | Routes |
|---|---|
| **Appointment & Scheduling** | `GET/POST /appointments`, `GET/POST /appointments/new`, `GET/POST /appointments/:id/edit`, `POST /appointments/:id/cancel`, `POST /appointments/:id/complete` |
| **Barcode Scanner Interface** | `GET/POST /scan-barcode`, `GET /barcode-wristband/:id`, `POST /barcode-wristband` |
| **Authentication** | `GET/POST /login`, `GET/POST /register`, `GET /logout`, `GET/POST /mfa-setup`, `GET/POST /mfa-verify` |
| **Admin** | `GET /audit-logs` (admin only) |

---

## Security Stack

| Control | Implementation |
|---|---|
| Password hashing | bcryptjs, 10 rounds |
| Session management | express-session (httpOnly, secure in prod) |
| Multi-Factor Auth | otplib TOTP (Google Authenticator compatible) |
| CSRF protection | csrf-csrf double-submit cookie |
| Rate limiting | express-rate-limit (20 auth, 200 general per 15 min) |
| Input validation | express-validator allowlist validators on every mutation |
| SQL injection prevention | Parameterised queries via mysql2 |
| Role-Based Access Control | Custom requireRole() middleware |
| HIPAA audit trail | audit_logs table — every action logged with user/IP/result |
| Security headers | Helmet.js |
| HTTPS support | Node.js https module with TLS cert/key |

---

## Requirements

- Node.js 18+
- MariaDB 10.6+ (or MySQL 8+)

---

## Setup

### 1. Install dependencies

```bash
cd student2_app
npm install
```

### 2. Configure environment variables

```bash
cp .env.example .env
nano .env
```

| Variable | Purpose |
|---|---|
| `DB_HOST` | MariaDB host (usually `localhost`) |
| `DB_USER` | Database username |
| `DB_PASSWORD` | Database password |
| `DB_NAME` | Database name (e.g. `clinic_student2`) |
| `SESSION_SECRET` | Long random string (min 32 chars) |
| `PORT` | Server port (default `3001`) |
| `HTTPS_CERT` | Path to TLS certificate (optional) |
| `HTTPS_KEY` | Path to TLS private key (optional) |

**Generate a secure SESSION_SECRET:**
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### 3. Set up the database

```bash
mariadb -u root -p -e "CREATE DATABASE IF NOT EXISTS clinic_student2;"
mariadb -u root -p clinic_student2 < schema.sql
```

### 4. Create first admin account

```bash
node -e "
const bcrypt = require('bcryptjs');
const hash = bcrypt.hashSync('Admin@1234', 10);
console.log('INSERT INTO users (username,email,password_hash,role) VALUES (\"admin\",\"admin@uhcclinic.com\",\"' + hash + '\",\"admin\");');
"
```

Paste the output SQL into MariaDB.

### 5. Run the application

```bash
# Development (auto-restart)
npm run dev

# Production
npm start
```

App available at: **http://localhost:3001**

---

## (Optional) HTTPS

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes \
  -subj "/CN=localhost/O=UHC Clinic/C=AU"
```

Set in `.env`:
```
HTTPS_CERT=./certs/cert.pem
HTTPS_KEY=./certs/key.pem
```

---

## Appointment features

- **Types**: Doctor | Laboratory | Radiology — each colour-coded in the list
- **Status lifecycle**: `scheduled` → `confirmed` → `completed` / `cancelled` / `no_show`
- **Filters**: by date, appointment type, status
- **Quick actions**: mark complete, cancel, edit from the list view

## Barcode Scanner features

- **Hardware scanner support**: USB/Bluetooth HID scanners auto-submit on `Enter`
- **Manual entry fallback**: type the barcode value manually
- **Patient lookup**: resolves `BC-{id}-{timestamp}` format
- **Wristband issuance**: issue/re-issue Code 128 wristbands (admin + receptionist)
- **Print**: browser print of the wristband with SVG barcode

---

## Merging with Student 1 (Patient Registration)

The `patients` and `users` tables in `schema.sql` are designed to be compatible with the Student 1 schema. On a shared database:

1. Run Student 1's full schema first (it owns `patients` / `users`)
2. Run only the `appointments` and `barcode_wristbands` CREATE statements from this `schema.sql`
3. Point Student 2 app at the same `DB_NAME` as Student 1 — all foreign keys resolve correctly

---

## Feature → Requirement mapping

| Feature | Requirement |
|---|---|
| Appointment scheduling (doctor/lab/radiology) | Appointment & Scheduling module |
| Calendar colour-coding by type | Color-coded schedules |
| Online scheduling via web UI | Online appointment availability |
| Status tracking (scheduled/confirmed/completed/cancelled) | Patients and staff can check appointment status |
| Barcode wristband issue + scan | Barcode Scanner Interface |
| Code 128 wristband barcode | Patient Wristband uses barcode for identification |
| TOTP MFA | Access Control Mechanism (HIPAA Authorization) |
| RBAC (admin/doctor/receptionist) | Access Control Mechanism |
| Audit logging | Audit Logging and Analysis (HIPAA) |
| express-validator input validation | Data Validation and Sanitization (HIPAA) |
| Parameterised SQL queries | Protection against SQL injection |
| CSRF double-submit | Protection against CSRF attacks |
| Helmet.js + rate limiting | Security headers + brute-force protection |
