# SSSIHMS Password Vault

A Frappe 16 custom app for Sri Sathya Sai Institute of Higher Medical Sciences (SSSIHMS),
Whitefield: an **organizational** password manager for department-shared credentials — bank
portals, vendor logins, statutory portals, Wi-Fi, equipment admin panels, hospital SaaS
accounts. Managed access, role-based, auditable.

This is deliberately **not** a zero-knowledge personal password manager. Its value is the
opposite trade: IT/admin *can* manage, recover and audit these credentials, because they
belong to the organization rather than to any one person. Secrets are stored in Frappe's
`Password` fieldtype (encrypted at rest with the site encryption key) and every reveal is
logged before the value is returned.

## What it adds

- **Vault Space** — a department-scoped container with an explicit member table
  (`Reader` / `Editor` / `Manager`). Membership, not a global role, decides who sees what.
- **Vault Credential** — one credential, typed by an Indian credential template
  (netbanking, UPI, card, demat, government-ID portal, Wi-Fi, insurance, login, note,
  custom). Template-specific fields live in the `Credential Secret Field` child table;
  secret values are `Password` fields, never plain columns.
- **Credential Access Log** — append-only. Every reveal, copy, create, update, delete,
  import, membership change and health run, with the denial attempts too. No role can write
  or delete a row; deletion requires a console-only override flag.
- **Reveal RPC** — re-checks permission server-side, writes and commits the log row *before*
  decrypting, and is rate-limited.
- **Credential Access Report** — scoped log report: Vault Admin and Vault Auditor see every
  space, a space Manager sees only their own spaces.
- **Password generator**, **health report** (weak / reused / expiring), **CSV import**
  (Chrome/Apple/most managers) and a **daily rotation-reminder sweep**.

## Roles

| Role | What it grants |
|---|---|
| `Vault Admin` | App administrator: creates spaces, sees every credential, manages settings. No audit-log delete. |
| `Vault Auditor` | Reads the access log and space membership. **Never** reads a credential, and can never reveal a secret. |
| `Vault User` | The base doctype grant; narrowed per row to the caller's space membership by `has_permission` / `permission_query_conditions` hooks. Auto-assigned on first membership. |

## Install

```bash
cd /home/azureuser/frappe_docker
bench get-app https://github.com/<owner>/sssihms-password-vault.git
bench --site <site> install-app sssihms_password_vault
bench --site <site> migrate
bench build --app sssihms_password_vault
```

The app code lives in the containers' writable layer on `sssihms-web-vm2023`; this GitHub
repo is the source of truth. To restore after a container rebuild, run `bench get-app` in
the backend **and** the queue-short, queue-long, scheduler and websocket containers, then
`install-app`, `migrate`, `build`.

## Tests

```bash
bench --site <site> run-tests --app sssihms_password_vault
# and the doctype/permission/audit suites, which need a site:
bench --site <site> run-tests --module sssihms_password_vault.password_vault.doctype.vault_credential.test_vault_credential
bench --site <site> run-tests --module sssihms_password_vault.password_vault.doctype.credential_access_log.test_credential_access_log
bench --site <site> run-tests --module sssihms_password_vault.password_vault.doctype.vault_space.test_vault_space

# pure logic (generator, health scoring, CSV parsing, wordlist) also runs without a bench:
python3 -m unittest discover -s sssihms_password_vault/vault/tests
```

Full green is 92 tests: 52 pure + 31 credential + 7 access-log + 2 vault-space.

## Documents

`BRIEF.md` is binding on requirements; `DESIGN.md` is binding on design. Read both before
changing anything security-relevant.
