-- ============================================================
-- Student 2 Standalone Database Schema
-- United Health Care — Appointment & Scheduling + Barcode Scanner
-- ============================================================
-- Run: mariadb -u root -p -e "CREATE DATABASE IF NOT EXISTS clinic_student2;"
--       mariadb -u root -p clinic_student2 < schema.sql
-- ============================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ── users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `users` (
  `user_id`       int(11)      NOT NULL AUTO_INCREMENT,
  `username`      varchar(50)  NOT NULL,
  `email`         varchar(150) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role`          enum('admin','doctor','receptionist') NOT NULL DEFAULT 'receptionist',
  `mfa_enabled`   tinyint(1)   NOT NULL DEFAULT 0,
  `mfa_secret`    varchar(64)  DEFAULT NULL,
  `created_at`    timestamp    NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email`    (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── audit_logs ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `log_id`       int(11)      NOT NULL AUTO_INCREMENT,
  `user_id`      int(11)      DEFAULT NULL,
  `username`     varchar(50)  DEFAULT NULL,
  `role`         varchar(30)  DEFAULT NULL,
  `action`       varchar(100) NOT NULL,
  `target_table` varchar(50)  DEFAULT NULL,
  `target_id`    int(11)      DEFAULT NULL,
  `ip_address`   varchar(45)  DEFAULT NULL,
  `result`       enum('success','failure','denied','not_found') NOT NULL DEFAULT 'success',
  `details`      text         DEFAULT NULL,
  `created_at`   timestamp    NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`log_id`),
  KEY `user_id`    (`user_id`),
  KEY `action`     (`action`),
  KEY `created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── patients ─────────────────────────────────────────────────────────────────
-- Minimal patient table for Student 2 (shared with Student 1 on merge).
-- Only the columns required by Appointment & Barcode modules are included here.
CREATE TABLE IF NOT EXISTS `patients` (
  `patient_id`         int(11)       NOT NULL AUTO_INCREMENT,
  `full_name`          varchar(150)  NOT NULL,
  `age`                int(11)       DEFAULT NULL,
  `gender`             enum('Male','Female','Other') DEFAULT NULL,
  `phone`              varchar(50)   DEFAULT NULL,
  `address`            varchar(255)  DEFAULT NULL,
  `email`              varchar(150)  DEFAULT NULL,
  `date_of_birth`      date          DEFAULT NULL,
  `preferred_language` varchar(50)   DEFAULT 'English',
  `insurance_info`     varchar(255)  DEFAULT NULL,
  `created_at`         timestamp     NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`patient_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── appointments ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `appointments` (
  `appointment_id`   int(11)      NOT NULL AUTO_INCREMENT,
  `patient_id`       int(11)      NOT NULL,
  `provider_id`      int(11)      DEFAULT NULL       COMMENT 'doctor/staff user_id',
  `appointment_type` enum('doctor','laboratory','radiology') NOT NULL DEFAULT 'doctor',
  `appointment_date` date         NOT NULL,
  `appointment_time` time         NOT NULL,
  `duration_minutes` int(11)      NOT NULL DEFAULT 30,
  `status`           enum('scheduled','confirmed','cancelled','completed','no_show')
                     NOT NULL DEFAULT 'scheduled',
  `notes`            text         DEFAULT NULL,
  `color_code`       varchar(7)   NOT NULL DEFAULT '#0d6efd',
  `created_by`       int(11)      DEFAULT NULL,
  `created_at`       timestamp    NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`appointment_id`),
  KEY `patient_id`       (`patient_id`),
  KEY `provider_id`      (`provider_id`),
  KEY `appointment_date` (`appointment_date`),
  CONSTRAINT `appointments_fk_patient`   FOREIGN KEY (`patient_id`)
    REFERENCES `patients` (`patient_id`) ON DELETE CASCADE  ON UPDATE CASCADE,
  CONSTRAINT `appointments_fk_provider`  FOREIGN KEY (`provider_id`)
    REFERENCES `users`    (`user_id`)    ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `appointments_fk_createdby` FOREIGN KEY (`created_by`)
    REFERENCES `users`    (`user_id`)    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── barcode_wristbands ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `barcode_wristbands` (
  `wristband_id`  int(11)      NOT NULL AUTO_INCREMENT,
  `patient_id`    int(11)      NOT NULL,
  `barcode_data`  varchar(100) NOT NULL,
  `issued_by`     int(11)      DEFAULT NULL,
  `issued_at`     timestamp    NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`wristband_id`),
  UNIQUE KEY `barcode_data` (`barcode_data`),
  KEY `patient_id` (`patient_id`),
  CONSTRAINT `barcode_wristbands_fk_patient`   FOREIGN KEY (`patient_id`)
    REFERENCES `patients` (`patient_id`) ON DELETE CASCADE  ON UPDATE CASCADE,
  CONSTRAINT `barcode_wristbands_fk_issued_by` FOREIGN KEY (`issued_by`)
    REFERENCES `users`    (`user_id`)    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;
