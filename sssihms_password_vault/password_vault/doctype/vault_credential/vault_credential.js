// Vault Credential form script.
//
// Three jobs: build the Secret Fields child rows from the selected template, reveal/copy a
// secret through the audited server endpoint, and generate a new secret.
//
// No secret value is ever written to localStorage, sessionStorage, a route argument, a
// document title, or frappe.boot. A revealed value lives in one dialog field and is cleared
// when the dialog closes or the auto-hide timer fires.

const API = "sssihms_password_vault.vault.api";

let TEMPLATE_CACHE = null;

function get_templates() {
	if (TEMPLATE_CACHE) {
		return Promise.resolve(TEMPLATE_CACHE);
	}
	return frappe
		.call({ method: `${API}.get_templates` })
		.then((r) => {
			TEMPLATE_CACHE = r.message || {};
			return TEMPLATE_CACHE;
		});
}

frappe.ui.form.on("Vault Credential", {
	refresh(frm) {
		frm.trigger("add_vault_buttons");

		if (frm.doc.credential_type && !frm.is_new()) {
			// vault_space and credential_type are immutable server-side; grey them out so
			// the user finds that out before typing rather than on save.
			frm.set_df_property("vault_space", "read_only", 1);
			frm.set_df_property("credential_type", "read_only", 1);
		}
	},

	credential_type(frm) {
		if (!frm.doc.credential_type) {
			return;
		}
		frm.trigger("apply_template");
	},

	add_vault_buttons(frm) {
		if (frm.is_new()) {
			return;
		}

		frm.add_custom_button(__("Reveal / Copy"), () => reveal_dialog(frm), __("Secrets"));
		frm.add_custom_button(__("Generate"), () => generate_dialog(frm), __("Secrets"));
		frm.add_custom_button(
			__("Access Log"),
			() =>
				frappe.set_route("query-report", "Credential Access Report", {
					credential: frm.doc.name,
				}),
			__("Secrets")
		);
	},

	apply_template(frm) {
		get_templates().then((templates) => {
			const template = templates[frm.doc.credential_type];
			if (!template) {
				return;
			}

			// The login and wifi templates route some keys to the parent columns
			// (username/password/url); those must not also become child rows, or the same
			// secret would exist in two places and drift.
			const parent_keys = {
				login: ["username", "password", "url"],
				wifi: ["password"],
			}[frm.doc.credential_type] || [];

			const existing = new Set((frm.doc.secret_fields || []).map((r) => r.field_key));
			let added = 0;

			(template.fields || []).forEach((field) => {
				if (parent_keys.includes(field.key) || existing.has(field.key)) {
					return;
				}
				const row = frm.add_child("secret_fields", {
					field_key: field.key,
					label: field.label,
					field_kind: field.kind,
					is_secret: field.sensitive ? 1 : 0,
					is_masked: field.masked ? 1 : 0,
					is_password: field.is_password ? 1 : 0,
					warning: field.warning || null,
				});
				if (row) {
					added += 1;
				}
			});

			frm.refresh_field("secret_fields");

			if (template.warning) {
				frappe.msgprint({
					title: __("Before you store this"),
					message: template.warning,
					indicator: "orange",
				});
			}
			if (added) {
				frappe.show_alert({
					message: __("Added {0} template field(s).", [added]),
					indicator: "green",
				});
			}
		});
	},
});

/** Every field on this credential that the reveal endpoint will serve. */
function revealable_fields(frm) {
	const fields = [];
	if (frm.doc.password) {
		fields.push({ key: "password", label: __("Password") });
	}
	(frm.doc.secret_fields || []).forEach((row) => {
		fields.push({ key: row.field_key, label: row.label || row.field_key });
	});
	return fields;
}

function reveal_dialog(frm) {
	const fields = revealable_fields(frm);
	if (!fields.length) {
		frappe.msgprint(__("This credential has no stored fields to reveal."));
		return;
	}

	const dialog = new frappe.ui.Dialog({
		title: __("Reveal secret"),
		fields: [
			{
				fieldname: "field_key",
				label: __("Field"),
				fieldtype: "Select",
				reqd: 1,
				options: fields.map((f) => ({ value: f.key, label: f.label })),
				default: fields[0].key,
			},
			{
				fieldname: "revealed",
				label: __("Value"),
				fieldtype: "Data",
				read_only: 1,
				description: __("Every reveal and copy is recorded in the access log."),
			},
		],
		primary_action_label: __("Reveal"),
		primary_action(values) {
			fetch_secret(frm, dialog, values.field_key, "reveal");
		},
		secondary_action_label: __("Copy"),
		secondary_action() {
			fetch_secret(frm, dialog, dialog.get_value("field_key"), "copy");
		},
	});

	// Belt and braces: clear the field on close so the value does not sit in the DOM of a
	// hidden dialog for the rest of the session.
	dialog.$wrapper.on("hidden.bs.modal", () => dialog.set_value("revealed", ""));
	dialog.show();
}

function fetch_secret(frm, dialog, field_key, action) {
	if (!field_key) {
		return;
	}
	frappe.call({
		method: `${API}.reveal_secret`,
		type: "POST",
		args: { credential: frm.doc.name, field_key: field_key, action: action },
		freeze: true,
		freeze_message: __("Checking permission and recording access…"),
		callback(r) {
			if (!r.message) {
				return;
			}
			const { value, auto_hide_seconds } = r.message;

			if (action === "copy") {
				frappe.utils.copy_to_clipboard(value);
				frappe.show_alert({
					message: __("Copied. This copy is in the access log."),
					indicator: "green",
				});
				return;
			}

			dialog.set_value("revealed", value);
			const seconds = auto_hide_seconds || 30;
			setTimeout(() => dialog.set_value("revealed", ""), seconds * 1000);
			frappe.show_alert({
				message: __("Hiding again in {0}s.", [seconds]),
				indicator: "blue",
			});
		},
	});
}

function generate_dialog(frm) {
	const targets = [{ value: "password", label: __("Password (this credential)") }];
	(frm.doc.secret_fields || [])
		.filter((row) => row.is_secret)
		.forEach((row) =>
			targets.push({ value: row.field_key, label: row.label || row.field_key })
		);

	const dialog = new frappe.ui.Dialog({
		title: __("Generate a secret"),
		fields: [
			{
				fieldname: "kind",
				label: __("Kind"),
				fieldtype: "Select",
				options: ["password", "passphrase", "pin"].join("\n"),
				default: "password",
				reqd: 1,
			},
			{ fieldname: "length", label: __("Length / words / digits"), fieldtype: "Int" },
			{
				fieldname: "target",
				label: __("Write into"),
				fieldtype: "Select",
				options: targets,
				default: "password",
				reqd: 1,
				description: __(
					"The generated value is written into the form but not saved until you save the document."
				),
			},
		],
		primary_action_label: __("Generate"),
		primary_action(values) {
			const options = {};
			if (values.length) {
				if (values.kind === "password") options.length = values.length;
				if (values.kind === "passphrase") options.words = values.length;
				if (values.kind === "pin") options.digits = values.length;
			}
			frappe.call({
				method: `${API}.generate_credential_secret`,
				type: "POST",
				args: { kind: values.kind, options: JSON.stringify(options) },
				callback(r) {
					if (!r.message) {
						return;
					}
					write_generated(frm, values.target, r.message.value);
					dialog.hide();
					frappe.show_alert({
						message: __("Generated. Save the document to store it."),
						indicator: "green",
					});
				},
			});
		},
	});
	dialog.show();
}

function write_generated(frm, target, value) {
	if (target === "password") {
		frm.set_value("password", value);
		return;
	}
	const row = (frm.doc.secret_fields || []).find((r) => r.field_key === target);
	if (row) {
		frappe.model.set_value(row.doctype, row.name, "secret_value", value);
		frm.refresh_field("secret_fields");
	}
}

frappe.ui.form.on("Credential Secret Field", {
	is_secret(frm, cdt, cdn) {
		const row = locals[cdt][cdn];
		// The server rejects a secret row that also carries a plaintext value; move it
		// rather than letting the user discover that on save.
		if (row.is_secret && row.value) {
			frappe.model.set_value(cdt, cdn, "secret_value", row.value);
			frappe.model.set_value(cdt, cdn, "value", "");
			frappe.show_alert({
				message: __("Moved that value into the encrypted Secret Value field."),
				indicator: "blue",
			});
		}
	},
});
