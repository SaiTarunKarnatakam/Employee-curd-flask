# Enterprise Workforce Portal & Governance Engine

![CI Quality Gate](https://github.com/SaiTarunKarnatakam/Employee-curd-flask/actions/workflows/ci.yml/badge.svg)
![Architecture](https://img.shields.io/badge/Architecture-Clean%20Python%20%7C%20Zero--ORM-blue)
![Governance](https://img.shields.io/badge/Compliance-PDPA%20%2F%20SOC%202%20Audit%20Trails-green)

A modular, enterprise-grade Employee Lifecycle and Workforce Governance Portal developed for modernizing manual corporate record systems. Engineered with a native SQLite3 parameterized data layer, Multi-Factor Step-Up Authentication (2FA), Role-Based Access Control (RBAC), immutable administrative mutation audit logs for regulatory compliance (PDPA / SOC 2), and an AI-ready telemetry endpoint for downstream LLM and BI ingestion.

---

## Enterprise Modernization Matrix

| Capability | Legacy Baseline (Phase 1) | Modern Enterprise State (Phase 2) | Business & Compliance Impact |
| :--- | :--- | :--- | :--- |
| **Authentication** | Unauthenticated | Session-managed with 30-min auto-invalidation | Eliminates credential and session hijacking risks |
| **Privileged Access** | Flat access | 2-Step OTP Authentication for HR & IT Admins | Implements Zero-Trust verification for root roles |
| **Access Governance** | Unrestricted | Role-Based Access Control (RBAC) | Enforces strict segregation of operational duties |
| **Data Retention** | Hard Deletes (Data Loss) | Non-destructive soft-delete with re-hire tracking | Preserves organizational tenure & generates fresh IDs |
| **Auditability** | Zero observability | Dual logging: Session logins + Mutation ledger | Ensures complete compliance traceability (PDPA/SOC 2) |
| **AI Integration** | None (Static HTML) | `/api/v1/workforce-summary` JSON REST endpoint | Prepares structured telemetry & prompts for LLMs |
| **Quality Gate** | Manual local checks | 6-part automated `unittest` suite via GitHub Actions CI | Automated regression testing on every push |

---

## Core API & System Endpoints

* `GET /department/<dept_name>`: Scoped active personnel dashboard based on authenticated user department.
* `GET /audit/governance`: Administrative ledger recording actor attribution, action type, target IDs, and timestamps.
* `GET /audit/logins`: Session authentication tracking.
* `GET /api/v1/workforce-summary`: AI telemetry endpoint generating structured headcount distribution and context prompts for LLM ingestion.
* `GET /profile` & `POST /profile`: Self-service security credentials management and password rotation.

---

## Local Development & Testing

1. **Activate Virtual Environment:**
   ```powershell
   .\venv\Scripts\Activate.ps1