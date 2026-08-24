# Independent security audit — SSSIHMS Password Vault (Frappe 16 app)

You are auditing a Frappe 16 / ERPNext custom app at `~/Documents/sssihms-password-vault`
(repo `vemula78/sssihms-password-vault`). Work from the code on disk. Nothing in this prompt
is a finding; treat every claim in the repo's own docs and comments as a claim to be tested,
not as evidence.

## What the app is, and what it is deliberately not

It is an **organizational** password manager for department-shared credentials at a hospital
(bank portals, vendor logins, statutory portals, Wi-Fi, equipment admin panels). It is
deliberately **not** zero-knowledge: IT/admin are *supposed* to be able to manage, recover
and audit these credentials, because the credentials belong to the organization. Secrets sit
in Frappe `Password` fields, encrypted at rest with the site encryption key.

So do **not** report "the server can decrypt secrets" or "a System Manager could read the
database" as vulnerabilities. Those are the accepted trade. Report instead where the app
fails the guarantees it actually claims, below.

## The guarantees to attack

1. **One audited door.** A secret leaves the server only through
   `vault.api.reveal_secret`, which re-checks permission server-side, writes the access-log
   row *and commits it* before decrypting, and is rate-limited. Find any other route by
   which a secret value, or a decryptable copy of one, can reach a client, a file, a log, an
   exception message, an email, a Version row, a report export, a print format, a
   notification, an error trace, a `__Auth` read, or a websocket payload.
2. **Append-only audit log.** `Credential Access Log` rows must be impossible to create
   with false content, modify, or delete via any remotely reachable path, and must outlive
   the credential they describe. Try renames, bulk operations, `frappe.client.*`,
   `frappe.model.rename_doc`, deletes, cascades, `db_set`, imports, and the Data Import /
   Bulk Update tooling.
3. **Row access is membership, not role.** `Vault User` is only a ceiling; the
   `has_permission` and `permission_query_conditions` hooks narrow to the caller's
   `Vault Space Member` level (Reader/Editor/Manager). Find any query path that returns
   credential rows the caller has no membership for — Frappe's own APIs
   (`frappe.client.get_list`, `get_count`, `get_value`, `frappe.desk.reportview.*`, link-field
   search, dashboards, `frappe.db.get_list` with `ignore_permissions`), report queries, child
   tables reached via parent, or anything that bypasses `permission_query_conditions`.
4. **Separation of duties.** A `Vault Auditor` must never read a credential or reveal a
   secret, even if that same user also holds `Vault User` and a real space membership.
   `Vault Admin` legitimately overrides this. The guard is mirrored in three places; check
   they cannot disagree, and look for a fourth path none of them cover.
5. **Escalation.** Can a space Manager, an Editor, or a plain authenticated ERPNext account
   with no vault role reach anything above their level — create a space, add themselves to
   one, change a member row, flip `disabled`, edit Vault Settings, assign a role, or get a
   credential moved into a space they control?
6. **Input handling.** Every whitelisted method: injection (SQL via query conditions or
   `frappe.db.sql`), unbounded input, type confusion between JSON and form-encoded POSTs,
   missing `methods=["POST"]` on state-changing calls, rate-limit bypass, and enumeration or
   timing oracles that disclose which credentials/spaces/fields exist.
7. **CSV import** ingests plaintext secrets from an uploaded file. Check what happens to the
   file, whether values can land in a File doctype, a log, or an error message, and whether
   import can write into a space the caller is not an Editor of.

## Ground rules for this audit

- **Verify Frappe behaviour against the installed framework source**, not from memory.
  Several past mistakes here came from assuming a docfield property or hook semantics
  existed. If you cannot verify a framework claim, say so and mark the confidence.
- Distinguish **remotely reachable** from **console-only**. A `bench console` or direct
  Python call can obviously do anything; that is not a finding. Say which HTTP path reaches
  the issue. (One relevant subtlety: `override_whitelisted_methods` is applied only in
  `frappe/handler.py:execute_cmd`, so a console call is not a test of it.)
- **Report every issue you find, with a severity and a confidence rating.** Do not filter by
  importance — filtering happens in a later pass. Coverage beats concision. Include design
  concerns, not just exploitable bugs, but label which is which.
- For each finding: file and line, the exact path an attacker takes, what they gain, and the
  smallest change that closes it. Where you can, name the test that would have caught it.
- Also report **anything the code claims in a comment or docstring that is not true**. A
  false reassurance in a security file is itself a defect.
- Note gaps in test coverage for security-relevant behaviour.

## Orientation

- `BRIEF.md` (requirements) and `DESIGN.md` (design) are the binding specs — audit the code
  against them, and report where the code and spec disagree in either direction.
- `NOTES/` holds one lesson per file, including a prior audit's outcomes. Read it so you do
  not re-report already-fixed issues as new — but do re-test that those fixes actually hold.
- `CLAUDE.md` describes the intended invariants. It is a claim, not evidence.
- `reference/from-personal-password-manager/` is read-only TypeScript from an unrelated
  zero-knowledge app, kept only because four concepts were reimplemented in Python. It must
  not be imported by anything. Verify that, then ignore it. Do not audit it, and do not
  suggest adopting its crypto — that is a different product with the opposite security model.
- Layering: `vault/` is logic (`generator`, `health`, `csv_import`, `wordlist` are pure;
  `permissions`, `audit`, `api`, `reminders`, `templates` are Frappe-aware);
  `password_vault/` holds doctypes and reports.

Running tests locally, no bench required:

```bash
python3 -m unittest discover -s sssihms_password_vault/vault/tests   # 52 pure tests
```

The doctype/permission/audit suites need a real site
(`bench --site <site> run-tests --module ...`); full green is 80 tests. If you cannot run
those, review them by reading and say which of your findings are unverified as a result.

Do not change any code. Produce findings only.
