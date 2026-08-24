// Filters for the Credential Access Report script report.
frappe.query_reports["Credential Access Report"] = {
	filters: [
		{
			fieldname: "vault_space",
			label: __("Vault Space"),
			fieldtype: "Link",
			options: "Vault Space",
		},
		{
			fieldname: "from_date",
			label: __("From Date"),
			fieldtype: "Date",
			default: frappe.datetime.add_days(frappe.datetime.get_today(), -30),
		},
		{
			fieldname: "to_date",
			label: __("To Date"),
			fieldtype: "Date",
			default: frappe.datetime.get_today(),
		},
		{
			fieldname: "action",
			label: __("Action"),
			fieldtype: "Select",
			options: [
				"",
				"reveal",
				"copy",
				"create",
				"update",
				"delete",
				"import",
				"membership",
				"health_report",
			].join("\n"),
		},
		{
			fieldname: "outcome",
			label: __("Outcome"),
			fieldtype: "Select",
			options: ["", "success", "denied"].join("\n"),
		},
		{
			fieldname: "user",
			label: __("User"),
			fieldtype: "Link",
			options: "User",
		},
		{
			fieldname: "credential",
			label: __("Credential"),
			fieldtype: "Link",
			options: "Vault Credential",
		},
	],

	// A denied row is the most interesting row in the log — make it findable at a glance.
	formatter(value, row, column, data, default_formatter) {
		value = default_formatter(value, row, column, data);
		if (data && data.outcome === "denied") {
			value = `<span style="color: var(--red-600); font-weight: 600;">${value}</span>`;
		}
		return value;
	},
};
