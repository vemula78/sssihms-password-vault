sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:182:			if (!r.message) {
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:185:			const { value, auto_hide_seconds } = r.message;
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:188:				frappe.utils.copy_to_clipboard(value);
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:190:					message: __("Copied. This copy is in the access log."),
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:196:			dialog.set_value("revealed", value);
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:198:			setTimeout(() => dialog.set_value("revealed", ""), seconds * 1000);
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:200:				message: __("Hiding again in {0}s.", [seconds]),
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:208:	const targets = [{ value: "password", label: __("Password (this credential)") }];
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:212:			targets.push({ value: row.field_key, label: row.label || row.field_key })
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:222:				options: ["password", "passphrase", "pin"].join("\n"),
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:223:				default: "password",
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:232:				default: "password",
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:235:					"The generated value is written into the form but not saved until you save the document."
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:240:		primary_action(values) {
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:242:			if (values.length) {
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:243:				if (values.kind === "password") options.length = values.length;
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:244:				if (values.kind === "passphrase") options.words = values.length;
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:245:				if (values.kind === "pin") options.digits = values.length;
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:250:				args: { kind: values.kind, options: JSON.stringify(options) },
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:252:					if (!r.message) {
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:255:					write_generated(frm, values.target, r.message.value);
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:258:						message: __("Generated. Save the document to store it."),
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:268:function write_generated(frm, target, value) {
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:269:	if (target === "password") {
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:270:		frm.set_value("password", value);
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:275:		frappe.model.set_value(row.doctype, row.name, "secret_value", value);
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:283:		// The server rejects a secret row that also carries a plaintext value; move it
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:285:		if (row.is_secret && row.value) {
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:286:			frappe.model.set_value(cdt, cdn, "secret_value", row.value);
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:287:			frappe.model.set_value(cdt, cdn, "value", "");
sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.js:289:				message: __("Moved that value into the encrypted Secret Value field."),
sssihms_password_vault/password_vault/report/credential_access_report/credential_access_report.js:59:	formatter(value, row, column, data, default_formatter) {
sssihms_password_vault/password_vault/report/credential_access_report/credential_access_report.js:60:		value = default_formatter(value, row, column, data);
sssihms_password_vault/password_vault/report/credential_access_report/credential_access_report.js:62:			value = `<span style="color: var(--red-600); font-weight: 600;">${value}</span>`;
sssihms_password_vault/password_vault/report/credential_access_report/credential_access_report.js:64:		return value;
sssihms_password_vault/password_vault/report/credential_access_report/credential_access_report.py:28:from sssihms_password_vault.vault.audit import ACTIONS, OUTCOMES
sssihms_password_vault/password_vault/report/credential_access_report/credential_access_report.py:29:from sssihms_password_vault.vault.permissions import (
sssihms_password_vault/password_vault/report/credential_access_report/credential_access_report.py:99:            "detail",
sssihms_password_vault/password_vault/report/credential_access_report/credential_access_report.py:147:        {"fieldname": "detail", "label": _("Detail"), "fieldtype": "Data", "width": 240},
sssihms_password_vault/password_vault/doctype/vault_space/vault_space.py:8:from sssihms_password_vault.vault.audit import write_access_log
sssihms_password_vault/password_vault/doctype/vault_space/vault_space.py:9:from sssihms_password_vault.vault.permissions import LEVEL_RANK
sssihms_password_vault/password_vault/doctype/vault_space/vault_space.py:82:                title="sssihms_password_vault",
sssihms_password_vault/password_vault/doctype/vault_space/vault_space.py:83:                message=(
sssihms_password_vault/password_vault/doctype/vault_space/vault_space.py:119:    def _log_membership(self, detail: str) -> None:
sssihms_password_vault/password_vault/doctype/vault_space/vault_space.py:124:            detail=detail,
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.json:15:  "is_password",
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.json:16:  "value",
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.json:17:  "secret_value",
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.json:43:   "options": "text\npassword\npin\nemail\nphone\nurl\ndate\nnumber\nmultiline",
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.json:49:   "description": "The value lives in Secret Value (encrypted at rest) and is only ever returned through the audited reveal endpoint.",
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.json:65:   "fieldname": "is_password",
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.json:71:   "description": "Plaintext. Only for rows where Is Secret is unticked — the controller rejects a value here on a secret row.",
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.json:72:   "fieldname": "value",
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.json:79:   "fieldname": "secret_value",
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.py:11:    `secret_value` is a `Password` field: Frappe encrypts it with the site encryption key
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.py:12:    into `__Auth`, keyed by (doctype, this row's name, "secret_value"), and leaves only
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.py:14:    `frappe.utils.password.get_decrypted_password("Credential Secret Field", row.name,
sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.py:15:    "secret_value")` — and in this app that call appears only in the audited reveal path

codex
## Findings

1. **High — certain:** Frappe’s standard password-retrieval RPC remains available, bypassing the audited reveal endpoint, its rate limit, and its pre-return audit commit.

   The app exposes `Password` fields on `Vault Credential` and does not override/block Frappe’s built-in `frappe.client.get_password` route. Any user who has normal read access to a credential can request the primary `password` directly through that framework route; the app’s audit code is never invoked. This defeats the core invariant that secrets leave the server only through `reveal_secret`.

   Evidence: [hooks.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/hooks.py:11) registers no override for the framework password endpoint; [vault_credential.json](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.json:67) defines the decryptable field; [api.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/api.py:49) implements the intended, audited route. The same risk may extend to child-table `secret_value` fields depending on Frappe’s child-document permission resolution.

2. **High — certain:** A `Vault Auditor` added to a space obtains `Vault User` access and can read that space’s credentials; coupled with finding 1, they can retrieve the primary secret without any logged reveal.

   The implementation explicitly grants `Vault User` to every member, including an auditor mistakenly added to a space. The credential query condition and single-document permission hook test membership only; neither rejects `Vault Auditor`. The special auditor restriction exists solely in `reveal_secret`, so it does not protect framework-level password retrieval.

   Evidence: [vault_space.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/password_vault/doctype/vault_space/vault_space.py:90)–[97] auto-assigns `Vault User`; [permissions.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/permissions.py:154)–[170] scopes list access solely by membership; [permissions.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/permissions.py:194)–[223] similarly permits membership-based reads; [api.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/api.py:75)–[82] is the only place that rejects auditors. This contradicts the stated “auditors never read credentials” control.

3. **Low — certain:** Secret fields omit `no_track`, contrary to the binding design and the stated Version-history defense.

   Both Password fields have `no_copy`, `print_hide`, and `report_hide`, but neither has `no_track: 1`. Frappe normally represents Password values as masked placeholders, so this is not proof that plaintext is currently written to Version rows; it is nevertheless a missing required defense-in-depth control and leaves behavior dependent on framework internals and future changes.

   Evidence: [vault_credential.json](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.json:67)–[73]; [credential_secret_field.json](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.json:78)–[84].

4. **Low — certain:** Invalid reveal actions are denied without an audit row.

   `reveal_secret` rejects an invalid `action` before loading the credential or calling `write_access_log`. This is a denial path that is unrecorded, despite the design’s intent that denied reveal attempts are logged. It does not disclose a secret, but weakens attempted-abuse visibility.

   Evidence: [api.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/api.py:63)–[64], compared with the logged denial path at [api.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/api.py:87)–[103].

I found no raw SQL execution, formatted SQL passed to `frappe.db.sql`, `eval`/`exec`, unsafe user-controlled report filters, log-edit/delete HTTP route, secret-bearing CSV echo, health-report secret/hash return, or direct secret flow into reminder notifications, emails, or `frappe.log_error` payloads. The reveal endpoint itself correctly writes and commits its log before decryption.

Overall verdict: the app is thoughtfully structured and its custom reveal path is strong, but it is not safe to deploy as an auditable password manager until the standard Frappe Password retrieval surface is explicitly closed or replaced. That omission bypasses the central audit/rate-limit guarantee and, together with the auditor-membership logic, can give a Vault Auditor secrets that the design expressly forbids.
tokens used
144,308
## Findings

1. **High — certain:** Frappe’s standard password-retrieval RPC remains available, bypassing the audited reveal endpoint, its rate limit, and its pre-return audit commit.

   The app exposes `Password` fields on `Vault Credential` and does not override/block Frappe’s built-in `frappe.client.get_password` route. Any user who has normal read access to a credential can request the primary `password` directly through that framework route; the app’s audit code is never invoked. This defeats the core invariant that secrets leave the server only through `reveal_secret`.

   Evidence: [hooks.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/hooks.py:11) registers no override for the framework password endpoint; [vault_credential.json](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.json:67) defines the decryptable field; [api.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/api.py:49) implements the intended, audited route. The same risk may extend to child-table `secret_value` fields depending on Frappe’s child-document permission resolution.

2. **High — certain:** A `Vault Auditor` added to a space obtains `Vault User` access and can read that space’s credentials; coupled with finding 1, they can retrieve the primary secret without any logged reveal.

   The implementation explicitly grants `Vault User` to every member, including an auditor mistakenly added to a space. The credential query condition and single-document permission hook test membership only; neither rejects `Vault Auditor`. The special auditor restriction exists solely in `reveal_secret`, so it does not protect framework-level password retrieval.

   Evidence: [vault_space.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/password_vault/doctype/vault_space/vault_space.py:90)–[97] auto-assigns `Vault User`; [permissions.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/permissions.py:154)–[170] scopes list access solely by membership; [permissions.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/permissions.py:194)–[223] similarly permits membership-based reads; [api.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/api.py:75)–[82] is the only place that rejects auditors. This contradicts the stated “auditors never read credentials” control.

3. **Low — certain:** Secret fields omit `no_track`, contrary to the binding design and the stated Version-history defense.

   Both Password fields have `no_copy`, `print_hide`, and `report_hide`, but neither has `no_track: 1`. Frappe normally represents Password values as masked placeholders, so this is not proof that plaintext is currently written to Version rows; it is nevertheless a missing required defense-in-depth control and leaves behavior dependent on framework internals and future changes.

   Evidence: [vault_credential.json](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/password_vault/doctype/vault_credential/vault_credential.json:67)–[73]; [credential_secret_field.json](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/password_vault/doctype/credential_secret_field/credential_secret_field.json:78)–[84].

4. **Low — certain:** Invalid reveal actions are denied without an audit row.

   `reveal_secret` rejects an invalid `action` before loading the credential or calling `write_access_log`. This is a denial path that is unrecorded, despite the design’s intent that denied reveal attempts are logged. It does not disclose a secret, but weakens attempted-abuse visibility.

   Evidence: [api.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/api.py:63)–[64], compared with the logged denial path at [api.py](/Users/sssihms/Documents/sssihms-password-vault/sssihms_password_vault/vault/api.py:87)–[103].

I found no raw SQL execution, formatted SQL passed to `frappe.db.sql`, `eval`/`exec`, unsafe user-controlled report filters, log-edit/delete HTTP route, secret-bearing CSV echo, health-report secret/hash return, or direct secret flow into reminder notifications, emails, or `frappe.log_error` payloads. The reveal endpoint itself correctly writes and commits its log before decryption.

Overall verdict: the app is thoughtfully structured and its custom reveal path is strong, but it is not safe to deploy as an auditable password manager until the standard Frappe Password retrieval surface is explicitly closed or replaced. That omission bypasses the central audit/rate-limit guarantee and, together with the auditor-membership logic, can give a Vault Auditor secrets that the design expressly forbids.

[exited with code 0]
