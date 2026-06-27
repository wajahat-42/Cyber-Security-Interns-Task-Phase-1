# 🔐 Cybersecurity Internship — User Management System Security Assessment

**Organization:** DevelopersHub
**Duration:** 3 Weeks · June 2026
**Intern:** Cybersecurity Intern

---

## Overview

Security assessment and hardening of a Node.js User Management System — covering the full lifecycle from vulnerability discovery through implementation and penetration testing.

**Stack:** Node.js · Express · SQLite · JWT · bcrypt · Helmet.js · Winston · Nmap

---

## Vulnerabilities Identified

| Vulnerability | Severity | Location |
|---|---|---|
| SQL Injection | 🔴 Critical | Login, Signup, Search, Profile |
| Plaintext Passwords | 🔴 Critical | Database |
| Stored XSS | 🟠 High | Profile Page |
| Weak Session Secret | 🟡 Medium | Session Config |
| Missing Security Headers | 🟡 Medium | HTTP Response |
| Information Disclosure | 🔵 Low | Error Messages |

---

## What Was Fixed

| Area | Before | After |
|---|---|---|
| SQL Injection | Raw string concat | Parameterized queries |
| Password Storage | Plaintext | bcrypt (10 salt rounds) |
| Authentication | Session-based | JWT + HTTP-only cookies |
| Security Headers | None | Helmet.js (CSP, HSTS, X-Frame-Options) |
| Input Validation | None | `validator` library (whitelist approach) |
| Logging | None | Winston audit trail |

---

## Week-by-Week Breakdown

**Week 1 — Assessment**
Stood up the vulnerable app and ran full vulnerability assessment. Confirmed SQL injection across 4 endpoints, stored XSS in profile templates, and plaintext credential storage.

**Week 2 — Hardening**
Replaced all raw queries with parameterized statements. Migrated passwords to bcrypt, swapped sessions for JWT, and locked down HTTP headers with Helmet.js.

**Week 3 — Pen Testing & Reporting**
Ran Nmap for network-level reconnaissance. Integrated Winston for audit logging. Documented all controls against OWASP Top 10 and compiled this report.

---

## Tools & Libraries

`OWASP ZAP` `Nmap` `bcrypt` `jsonwebtoken` `helmet` `validator` `winston` `express` `sqlite3`

---

## Status

- [x] SQL Injection — Mitigated
- [x] XSS — Mitigated
- [x] Password Security — Hashed
- [x] Authentication — JWT-based
- [x] Security Headers — Configured
- [x] Audit Logging — Implemented
- [x] MFA Support — Planned
- [x] Log Integrity Protection — Planned
