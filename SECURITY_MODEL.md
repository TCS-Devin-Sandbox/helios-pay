# Helios Pay — Threat Model

> Source: drafted by Devin from the code of `TCS-Devin-Sandbox/helios-pay` (commit `5ad1a6c`), including the in-repo infrastructure (`infra/terraform`, `infra/helm`, `infra/.github-deploy`, `.github/workflows`, `docker-compose.yml`). There is no `SECURITY_MODEL.md`. `SECURITY.md` is only a notice that the project is an intentionally vulnerable demo. Items marked **[user]** come from the requester; everything else is Devin's reading of the code and moves no finding.

## 1. System overview and trust boundaries

Multi-tenant B2B payments and invoice platform. Tenants (`acme`, `globex`, `initech`, seeded by `services/core-api/app/seed.py`) share one Postgres database, and tenant isolation is only logical: a `tenant_id` column on every row, checked per route (`app/services/authz.py::require_tenant`). Roles are `admin`, `operator` and `viewer`. Auth uses an HS256 JWT (`HELIOS_JWT_SECRET`; claims `sub`, `tenant_id`, `role`, `aud=helios`, 8h `exp`). core-api `POST /auth/login` issues it. Each service verifies it on its own (`app/core/security.py`, `partner-gateway/src/middleware/auth.ts`).

Trust boundaries:
- **Internet → Web / Core API / Partner Gateway**: browser and partner traffic.
- **Tenant ↔ tenant**: inside core-api and the shared DB. The JWT `tenant_id` is the only thing separating tenants.
- **Service → service**: core-api, Postgres, Redis and ledger-worker on the internal network.
- **Outbound**: partner-gateway sends webhooks to partner-supplied URLs (`lib/dispatch.ts`). The internal network and the cloud metadata service sit on the other side (compose ships `metadata` and `attacker` helpers).
- **CI/CD and cloud**: GitHub Actions and the AWS IAM/S3/RDS/network resources defined in Terraform.

### Components

| Component | Code | Notes |
|---|---|---|
| `Web` | `web/` | Next.js 14 operator console; invoice memo and notes rendering (`components/InvoiceMemo.tsx`, `Notes.tsx`); token kept in `localStorage` (`lib/api.ts`) |
| `Core API` | `services/core-api/app/` (routers, services, db, models, schemas, alembic) | FastAPI: invoices, documents, imports, reports, diagnostics, admin, users, legacy |
| `Auth` | `core-api/app/core/{security,deps}.py`, `app/routers/auth.py`, `app/services/reset.py`, `partner-gateway/src/middleware/auth.ts` | JWT issuing and checking, password reset, role checks |
| `Support Copilot` | `core-api/app/routers/copilot.py`, `app/services/copilot_tools.py`, `web/components/CopilotPanel.tsx` | Assistant that reads invoice memos and acts on embedded tool calls (`HELIOS_LLM_MODE=stub` by default) |
| `Partner Gateway` | `services/partner-gateway/src/` | Express: webhook registration and outbound dispatch (`lib/urlguard.ts` blocklist) |
| `Ledger Worker` | `services/ledger-worker/` | Go + Redis: `POST /refunds`, balances, settlement |
| `Infrastructure` | `infra/terraform/`, `infra/helm/`, `infra/.github-deploy/`, `.github/workflows/`, `docker-compose.yml`, `.env.example` | AWS IAM/S3/RDS/SG, Helm chart, CI and deploy, local stack |

## 2. Entry points and who can reach them

- **Core API `:8000`**:
  - `/auth/*` (login, password reset), `/admin/metrics` and `/healthz` are mounted **without** the global auth dependency (`app/main.py`).
  - The copilot, diagnostics, documents, imports, invoices, reports and users routers need a valid JWT.
  - `require_role("operator")` guards only invoice create, statements and bulk import.
  - The `legacy` router is mounted only when `HELIOS_ENABLE_LEGACY=1`.
- **Partner Gateway `:8080`**: `/partners/webhooks` (JWT middleware checks HS256 and the audience).
- **Ledger Worker `:8090`**: `POST /refunds` has no authentication; it is meant to be internal only.
- **Web `:3000`**: operator console. The Helm service is `ClusterIP`; the repo defines no ingress.
- **CI**: `.github/workflows/ci.yml` (push and pull_request) and `deploy.yml` (`workflow_dispatch`).

## 3. Assets and sensitivity

- **Tenant business data** (invoices, payments, documents, users): high. Cross-tenant exposure is the main platform risk.
- **Money movement** (refunds, ledger balances, settlement): high, for integrity.
- **Credentials and secrets** (JWT signing secret, webhook HMAC key, DB credentials, password hashes, password-reset tokens, CI/AWS credentials): high.
- **Cloud resources** (S3 documents bucket, RDS instance, the IAM policy used by the runtime): high.

## 4. Attacker profiles

1. Anonymous internet user who can reach web, core-api and partner-gateway.
2. Authenticated user of one tenant, any role, trying to read or change another tenant's data or raise their own role.
3. Malicious partner who controls webhook URLs and uploaded SARIF/CSV/YAML/zip content.
4. Prompt-injection author: puts content in invoices or notes that the Support Copilot reads later.
5. Insider or CI contributor with access to workflows or cloud configuration.

- **[user]** Who can get an account: **invited tenant users only** (customers' staff). There is no public sign-up. Findings that need a login need an invited user of some tenant, of any role. That is attacker 2, which stays in scope.
- **[user]** Every attacker profile above stays in scope.

## 5. Existing controls (as observed)

- JWT HS256 with an audience check in core-api and partner-gateway. Exception: core-api has an `alg=none` compatibility branch in `core/security.py`.
- `require_role` in `core/deps.py` and `require_tenant` in `services/authz.py`, applied to some routes only.
- `urlguard.ts` blocks internal webhook destinations with a substring blocklist.
- CORS is restricted to `HELIOS_CORS_ORIGINS`.
- The legacy router is off by default.
- Passwords are hashed with bcrypt.

## 6. Out of scope / accepted risk

- **[user]** Nothing is ruled out and no risk is accepted. Every attacker and asset stays in scope; the user gave no ranking of assets.
- The whole repository is scanned, as submitted.

## 7. User priorities

- **[user]** No asset is named as more critical than the others, so no finding is raised.
- **[user]** Deployment: Terraform/Helm describe the real deployment. **web, core-api and partner-gateway are reachable from the internet; ledger-worker is internal only.** Findings whose only path is direct internet access to ledger-worker `:8090` are lowered one level. They stay reachable from inside the network, or through the partner-gateway SSRF, by an invited tenant user.
- Reranking consequence: apart from the ledger-worker reachability above, findings keep the scanner's severity.

## 8. Open questions

- Which assets matter most? Unanswered; all are treated as high.
- The repo has no ingress definition for the internet exposure the user confirmed.
