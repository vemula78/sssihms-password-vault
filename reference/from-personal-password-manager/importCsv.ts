// Generic CSV import (spec: "Generic CSV" under Import and Export). Parses the common
// export shape shared by Apple Passwords, Chrome, and most competitors — Title/Name,
// URL, Username, Password, Notes, and an optional OTPAuth URI — into Login item inputs.
// Pure parsing only: nothing here touches storage or crypto; the caller encrypts each
// item the normal way via VaultStore.addItem.

export interface ImportedLoginRow {
  title: string;
  fields: { username?: string; password?: string; url?: string };
  notes: string;
  /** otpauth:// URI, if the source exported one — stored as a sensitive custom field. */
  otpauth?: string;
}

export interface ParseCsvResult {
  items: ImportedLoginRow[];
  /** Rows present in the file but dropped (blank, or no title/username/password/url at all). */
  skipped: number;
  totalRows: number;
  /** True if the file was truncated to MAX_ROWS. */
  truncated: boolean;
}

export const MAX_IMPORT_ROWS = 5000;

type Col = "title" | "url" | "username" | "password" | "notes" | "otpauth";

const HEADER_ALIASES: Record<string, Col> = {
  title: "title", name: "title",
  url: "url", website: "url", "login uri": "url", uri: "url",
  username: "username", "user name": "username", login: "username", email: "username",
  password: "password",
  notes: "notes", note: "notes",
  otpauth: "otpauth", "otp auth": "otpauth", totp: "otpauth", "otp secret": "otpauth",
};

/** RFC-4180-ish CSV line splitter: handles quoted fields, embedded commas/newlines, "" escapes. */
function parseCsvRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  // Normalize line endings so \r\n inside quoted fields doesn't confuse the state machine.
  const s = text.replace(/\r\n/g, "\n");
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inQuotes) {
      if (c === '"') {
        if (s[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (c === "\r") {
      // stray lone CR — ignore
    } else {
      field += c;
    }
  }
  row.push(field);
  if (row.length > 1 || row[0] !== "") rows.push(row);
  return rows;
}

export function parseCsvToLoginItems(text: string): ParseCsvResult {
  const rows = parseCsvRows(text);
  if (rows.length === 0) return { items: [], skipped: 0, totalRows: 0, truncated: false };

  const header = rows[0]!.map((h) => h.trim().toLowerCase());
  const colFor: Partial<Record<Col, number>> = {};
  header.forEach((h, i) => {
    const mapped = HEADER_ALIASES[h];
    if (mapped && colFor[mapped] === undefined) colFor[mapped] = i;
  });

  const dataRows = rows.slice(1);
  const truncated = dataRows.length > MAX_IMPORT_ROWS;
  const limited = dataRows.slice(0, MAX_IMPORT_ROWS);

  const items: ImportedLoginRow[] = [];
  let skipped = 0;
  const get = (r: string[], key: Col): string => {
    const idx = colFor[key];
    return idx === undefined ? "" : (r[idx] ?? "").trim();
  };

  for (const r of limited) {
    if (r.every((cell) => cell.trim() === "")) {
      skipped++;
      continue;
    }
    const title = get(r, "title");
    const username = get(r, "username");
    const password = get(r, "password");
    const url = get(r, "url");
    const notes = get(r, "notes");
    const otpauth = get(r, "otpauth");

    if (!title && !username && !password && !url) {
      skipped++;
      continue;
    }

    items.push({
      title: title || url || username || "Imported login",
      fields: {
        ...(username ? { username } : {}),
        ...(password ? { password } : {}),
        ...(url ? { url } : {}),
      },
      notes,
      ...(otpauth ? { otpauth } : {}),
    });
  }

  return { items, skipped, totalRows: dataRows.length, truncated };
}
