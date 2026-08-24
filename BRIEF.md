# sssihms_password_vault — organizational password manager on Frappe/ERPNext

## What this is

A custom Frappe app for SSSIHMS Whitefield: an **organizational** password manager for
department-shared credentials (bank portals, vendor logins, statutory portals, Wi-Fi,
equipment admin panels, hospital SaaS accounts). Managed access, role-based, auditable.

**This is deliberately NOT the personal zero-knowledge password manager**
(`~/Documents/Password Manager`, github.com/vemula78/password-manager). That product's
guarantee is that the server can never read a vault. This product's value is the opposite
trade: IT/admin CAN manage, recover, and audit credentials, because they are the
organization's credentials, not any one person's. Keep the two codebases completely
separate. No shared code, no shared repo, no shared deployment.

## What is reused from the personal app (reference/ folder, read-only)

Ported concepts only — reimplemented in Python, not imported:
- `templates.ts` — Indian credential templates (netbanking, UPI, card, gov-ID portal,
  Wi-Fi, insurance, login, note, custom). Field definitions, sensitive/masked flags.
- `generator.ts` — password/passphrase/PIN generation rules (charset guarantees,
  ambiguity exclusion, EFF-style wordlist). Server-side via Python `secrets`.
- `health.ts` — weak/reused password detection + scoring.
- `importCsv.ts` — generic CSV import header-alias mapping (Chrome/Apple/most managers).

NOT reused, by design: all libsodium crypto, key hierarchy, vault file format, sync
protocol, tombstones. Frappe's own `Password` fieldtype (encrypted at rest with the site
encryption key) plus role-based permissions replace all of it.

## Deployment target

- Bench: `sssihms-web-vm2023`, `/home/azureuser/frappe_docker` (`pwd.yml`), Frappe 16.31,
  ERPNext 16.32. Site `frontend` (evaluation, synthetic data only).
- App code lives in the containers' writable layer — GitHub repo is the source of truth;
  restore procedure = `bench get-app` into backend + queue-short + queue-long + scheduler
  + websocket, then `install-app`, `migrate`, `build`. See the facility-management
  PERSISTENCE.md pattern.
- Existing custom apps on this bench to match in style: `sssihms_hr`, `hospital_ops`,
  `facility_management`, `patient_ticketing`, `trust_compliance`.

## Security requirements (non-negotiable)

1. Passwords stored ONLY in `Password` fieldtype (encrypted at rest). Never in plain
   Data/Text fields, never in versions/comments, never in logs, never in list views,
   never returned by a normal `get_doc`/`get_list` read.
2. Reveal is a whitelisted RPC that (a) re-checks permission server-side, (b) writes an
   append-only access-log row BEFORE returning the secret, (c) is rate-limited.
3. Separation of duties: who can create/edit a credential, who can reveal it, and who can
   administer spaces are distinct capabilities. An auditor role can read access logs but
   not secrets.
4. Access scoping by "Vault Space" (e.g. Accounts, IT, Cardiology office): membership is
   explicit, per-space, with reader/editor/manager levels. Frappe permission query
   conditions + `has_permission` hooks enforce it at the ORM level, not just the UI.
5. Append-only audit: access log rows can never be edited or deleted by anyone below
   System Manager, and even then it should require a deliberate override.
6. No secret values in Frappe's standard Version history (no_track on secret fields) and
   no secrets in error logs/tracebacks.
7. Frappe framework rules: all queries through the ORM/QB (no raw SQL string interp),
   all RPC entry points `@frappe.whitelist()` with explicit permission checks (never
   `ignore_permissions=True` to bypass a check), CSRF stays on.

## Functional scope (V1)

- Vault Space (department) with member child table: user + access level.
- Credential doctype: type (template), title, space, url/username/notes + typed template
  fields; secret fields as Password fieldtype; expiry/rotation-due date; tags; favorite.
- Reveal/copy RPC with audit logging; masked display (last 4) for masked fields.
- Access log doctype (append-only) + a report per space and org-wide for auditors.
- Password generator (password/passphrase/PIN) as whitelisted RPC + desk UI control.
- Health report: weak/reused/expiring per space, score, for space managers.
- CSV import (Chrome/Apple/etc. shape) into a chosen space, with skipped-row report.
- Rotation reminders: daily scheduler job -> notification to space managers when a
  credential passes its rotation-due date.
- Roles: `Vault Admin` (app-level admin), `Vault Auditor` (logs only, no secrets),
  space-level access via membership (not global roles).

Out of scope V1: browser extension, mobile, breach monitoring, external sync,
per-credential approval workflows, secret versioning beyond Frappe's own.

## Conventions

- App name `sssihms_password_vault`, module `Password Vault`.
- Python: match sssihms_hr style — controllers with explicit permission checks,
  "Codex finding" style comments where a security decision is deliberate.
- Tests: Frappe unit tests (`frappe.tests.utils.FrappeTestCase`) runnable via
  `bench --site <site> run-tests --app sssihms_password_vault`.
- Commits: Praveen Vemula <vemula78@gmail.com>.
- Synthetic data only; still treat secrets as real in design.
