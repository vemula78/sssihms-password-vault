# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Project: SSSIHMS Password Vault (Frappe 16 custom app)

An **organizational** password manager for department-shared credentials at SSSIHMS
Whitefield. `BRIEF.md` is binding on requirements, `DESIGN.md` on design — read both before
changing anything security-relevant. `NOTES/` holds one lesson per file.

**This is not the personal password manager.** `~/Documents/Password Manager`
(github.com/vemula78/password-manager) is a zero-knowledge product whose guarantee is that
the server can *never* read a vault. This app makes the opposite trade deliberately: IT/admin
**can** manage, recover and audit these credentials, because they belong to the organization.
Keep the two completely separate — no shared code, repo, or deployment. `reference/` holds
read-only copies of four TypeScript files from that app whose *concepts* were reimplemented in
Python here (templates, generator, health, CSV import). Never import from it; never port its
libsodium crypto, key hierarchy, vault file format, or sync protocol.

## Hard rules

- Secrets live **only** in Frappe `Password` fields (encrypted at rest into `__Auth` with the
  site encryption key). Never a Data/Text column, never a log line, never an exception
  message, never a list view, never the return of a plain `get_doc`/`get_list`.
- A secret leaves the server through exactly one door: `vault.api.reveal_secret`. It
  re-checks permission server-side, writes the access-log row **and commits it** before
  decrypting, and is rate-limited. That order is load-bearing — a log row for a reveal that
  then failed is acceptable; a reveal with no log row is not.
- `frappe.client.get_password` is a **framework** route that would return a vault secret with
  no audit row. It is closed by `override_whitelisted_methods` in `hooks.py` →
  `vault.api.get_password_override`. Do not remove that hook. It only intercepts the HTTP
  handler (`frappe/handler.py:execute_cmd`), which is the only remotely reachable path —
  direct Python calls and `frappe.call` bypass the override by design, so a console test
  "succeeding" is not a regression. Verify this one with a real HTTP request.
- **Auditors never read credentials.** `Vault Auditor` is a *disqualification*, not merely an
  absence of grant — it holds even for an auditor who also has `Vault User` and a space
  membership, because `Vault User` is auto-assigned the moment anyone joins a space. Enforced
  in three mirrored places (`credential_query_conditions` returns `1=0`,
  `credential_has_permission` returns `False`, and `reveal_secret` denies); all three must
  agree. `Vault Admin` wins over auditor-ness.
- The access log is append-only: no role has create/write/delete DocPerms, the controller's
  `validate()` throws on re-save, and rows must outlive the credential they log
  (`ignore_links_on_delete` in `hooks.py`). Deleting a credential that was ever revealed
  would otherwise fail Frappe's link check.
- `track_changes` is **0** on `Vault Credential` and `Credential Secret Field`. `no_track` is
  not a real Frappe 16 docfield property — disabling version tracking on the doctype is the
  actual defence, so no Version row can ever carry a secret regardless of Frappe's masking
  internals.

## Commands

Local, no bench needed — the pure-logic modules (`generator`, `health`, `csv_import`,
`wordlist`) import no Frappe at module scope, and `csv_import` guards its Frappe import in a
`try/except ImportError` specifically so this works:

```bash
python3 -m unittest discover -s sssihms_password_vault/vault/tests   # 52 tests
python3 -m py_compile $(find sssihms_password_vault -name '*.py')
```

Note: the README's `pytest` invocation does not work — pytest is not installed here and the
suites are `unittest`-based.

On the bench (`sssihms-web-vm2023`, `/home/azureuser/frappe_docker`, `pwd.yml`) — the
doctype/permission/audit suites need a real site:

```bash
bench --site testspv.local run-tests --app sssihms_password_vault        # pure logic
bench --site testspv.local run-tests --module sssihms_password_vault.password_vault.doctype.vault_credential.test_vault_credential
bench --site testspv.local migrate && bench --site testspv.local clear-cache
bench execute sssihms_password_vault.vault.reminders.daily_rotation_sweep
```

Full green is **80 tests**: 52 pure + 21 credential + 7 access-log. `clear-cache` after
copying files in, or `hooks.py` changes (including the override) will not be picked up.

## Architecture

**Two layers, deliberately.** `vault/` holds framework-light logic — `generator.py`,
`health.py`, `csv_import.py`, `wordlist.py` are pure and unit-tested without a site;
`permissions.py`, `audit.py`, `api.py`, `reminders.py`, `templates.py` are Frappe-aware.
`password_vault/` holds the Frappe artifacts (doctypes, reports). Reports and controllers stay
thin wrappers over `vault/` so the logic that matters remains testable off-bench.

**Row-level access is membership, not role.** The DocPerm rows grant a *ceiling* to the
`Vault User` role; the `has_permission` and `permission_query_conditions` hooks narrow it to
the caller's `Vault Space Member` level (`Reader`/`Editor`/`Manager`) per row. Both halves are
required and neither suffices alone: `has_permission` gates opening/saving one document,
`permission_query_conditions` gates what SQL-backed list and report queries return. Both are
ORM-level, so no UI can route around them.

**Template fields are a child table, not columns.** `Credential Secret Field` carries
template-specific fields, with the value in a `Password` field (`secret_value`) when secret and
a plain `value` when not — the controller rejects a row that populates both. `TEMPLATES` in
`vault/templates.py` is a Python constant, not a doctype: field definitions are code, so they
version with the app rather than drifting per site.

**Health and access reports return verdicts, never secrets.** The health report decrypts
server-side inside `execute()` (which is why it is a Script Report, not a Page) and returns
only strengths, reuse-group ids and rotation status — no values, no hashes. It resolves each
credential through `get_doc` one at a time so `credential_has_permission` stays in force per
document; never `ignore_permissions` there.

**An org-wide health run logs one row per space actually scanned.** The log's `vault_space` is
a mandatory Link, so a synthetic `"(all spaces)"` marker fails link validation — and per-space
rows are the truthful record of what the admin saw anyway.

## Deployment

App code lives in the containers' **writable layer**; this repo is the source of truth. Files
must be deployed to all five containers — `backend`, `queue-short`, `queue-long`, `scheduler`,
`websocket` — or the scheduler and background workers will run stale code while `backend`
looks correct. `DEPLOY.md` has the runbook. Site `frontend` is the evaluation site (synthetic
data only); `testspv.local` is for tests.

Frappe-16 specifics confirmed against installed source (don't re-derive):
`flags.in_insert` *is* true inside `on_update` during an insert (re-set around
`run_post_save_methods`), so it works as a create/update double-log guard; likes and tags
bypass `doc.save`, so the append-only `validate()` guard does not break them;
`frappe.client.get_password` is `System Manager`-only upstream, which is why the override must
also reproduce that check for non-vault doctypes.

## Practical

- Commits: Praveen Vemula <vemula78@gmail.com>.
- The bench's other custom apps (`sssihms_hr`, `hospital_ops`, `facility_management`,
  `patient_ticketing`, `trust_compliance`) are the house style to match — `sssihms_hr`'s
  `_create_custom_roles` and its Staff Document Access audit trail are the closest analogues.
