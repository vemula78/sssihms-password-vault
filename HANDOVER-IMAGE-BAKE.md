# Handover: baking `sssihms_password_vault` into the frappe_docker image

You are taking over deployment of this app from writable-layer copies to a baked image on
`sssihms-web-vm2023`. This is the current state, the traps, and the checks that decide
whether it worked. Everything here was verified on 24-Aug-2026, not assumed.

## What the app is

`sssihms_password_vault` — a Frappe 16 custom app, an **organizational** password manager for
department-shared credentials at SSSIHMS Whitefield (bank portals, vendor logins, statutory
portals, Wi-Fi, equipment admin panels). Secrets live in Frappe `Password` fields and every
reveal is logged before the value is returned.

It is deliberately **not** zero-knowledge. There is a *different* product with a nearly
identical name — the personal zero-knowledge password manager at `~/Documents/Password
Manager` (`github.com/vemula78/password-manager`, a Node/TS monorepo) whose guarantee is that
the server can never read a vault. **They are separate products with opposite security
models. Never merge them, never share code, deployment, or repo, and never port that app's
crypto into this one.** An earlier session conflated the two and concluded this Frappe app
had no git home; it does.

- Repo: `github.com/vemula78/sssihms-password-vault` — **private**. `main` is `ad6a11e`.
- Binding docs in the repo: `BRIEF.md` (requirements), `DESIGN.md` (design), `CLAUDE.md`
  (invariants that are expensive to rediscover), `DEPLOY.md` (the runbook), `NOTES/` (one
  lesson per file — read `audit-fixes-2026-08-24.md` and `client-ip-behind-apache.md`).

## Current deployed state

- Bench: `/home/azureuser/frappe_docker`, compose file `pwd.yml`, image
  `trust-compliance:hrms-v4`, Frappe 16.31 / ERPNext 16.32.
- The app is installed **in the writable layer of all five app containers** — `backend`,
  `queue-short`, `queue-long`, `scheduler`, `websocket` — at commit `ad6a11e`, extracted from
  a `git archive`, `pip install -e`.
- Sites: **`frontend`** is the live ERPNext site and also where this app is installed at
  evaluation stage (synthetic vault data only — no real credentials have been entered yet).
  **`testspv.local`** is frappe + this app only, and is the test site. `staging.local` does
  not have the app.
- 94 tests green on `testspv.local` as of `ad6a11e`.

Recreating the containers wipes all of that, which is why baking it in is worth doing.

## Trap 1 — the repo is private, and `bench get-app` will fail

`git clone` inside the containers prompts for a GitHub username and fails; the containers
hold no credentials. `DEPLOY.md` used to document a clone-based procedure that had evidently
never been run — it was discovered the hard way, *after* it had already `rm -rf`'d the app in
all five containers.

This matters more for an image build than for a deploy, because frappe_docker's build takes
an `apps.json` of repository URLs. **Do not put a PAT in that URL.** `apps.json` is passed as
a build arg and lands in the image's layer history and metadata, so the token would be
readable by anyone who can pull the image — a credential leak that outlives the build.

Use one of, in order of preference:

1. **Copy the source into the build context** and install from the local path — no
   credential exists at any point.
2. A **BuildKit build secret** (`RUN --mount=type=secret,...`) with a deploy key, so the key
   is never written to a layer.
3. Make the repo public. It contains no secrets — but that is Praveen's call, not yours, and
   it is a decision about a credential-store's source code, so ask rather than assume.

Whichever you pick, the app must end up in the image such that all five app containers have
it. Verify per container, not just `backend` (see checks below).

## Trap 2 — migrate every site, after the code is in place

A Select option or field added to a doctype JSON does not reach the database until `migrate`
runs, and a stale Select fails at **insert** time — inside a controller `validate()`, so a
logged security event becomes a hard error on an unrelated save. On 24-Aug-2026 this left
Vault Space creation broken on `frontend` while `testspv.local` was fully green, because the
sites were migrated in the wrong order relative to the code going in.

After the image swap:

```bash
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench backend bash -lc '
  bench --site frontend migrate && bench --site frontend clear-cache
  bench --site testspv.local migrate && bench --site testspv.local clear-cache'
```

`clear-cache` is not optional — `hooks.py` changes (this app registers `has_permission`,
`permission_query_conditions`, `override_whitelisted_methods`, `doc_events` on DocShare, and
a scheduler event) are not picked up without it.

## Trap 3 — do not run tests on `frontend`

ERPNext's `before_tests` hook bootstraps master data including a fiscal year, which collides
with the fiscal years already on `frontend` and aborts the entire run before a single test
executes. Run on `testspv.local`, which has no ERPNext:

```bash
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench backend bash -lc \
  'bench --site testspv.local run-tests --app sssihms_password_vault'
```

Full green is **94 tests**, reported as two batches (40 site + 54 pure).

## Do not

- **Do not restore from `~/apps-snapshots/sssihms_password_vault-20260824T0715.tar.gz`.** It
  predates the security fixes in `553f477` and contains vulnerable code. If it is ever used,
  say so loudly and re-deploy from git immediately.
- **Do not install this app on any other site** on that VM. Several live hospital apps share
  the bench.
- **Do not enter real credentials into `frontend`** while the app is at evaluation stage.
- Do not treat `bench console` as proof that the `frappe.client.get_password` override works
  — the override is applied only on the HTTP path (`frappe/handler.py:execute_cmd` and
  `frappe/api/v2.py`). A console call bypassing it is expected, not a regression.

## One decision to put to Praveen while you are in the image

The app's audit log records a `ip_address` per reveal, and right now **every request records
`172.18.0.1`**, the Docker bridge gateway. Cause: the frontend container's nginx
`location @webserver` does `proxy_set_header X-Forwarded-For $remote_addr`, overwriting the
chain, and `set_real_ip_from 127.0.0.1` never matches because Docker port publishing makes
the container see the gateway rather than loopback. Verified: a request carrying
`X-Forwarded-For: 203.0.113.99` was logged as `172.18.0.1`, and 43 of 45 `Activity Log` rows
on the site say the same.

Two consequences: the audit trail's "from where" half is uninformative, and Frappe's IP-keyed
`@rate_limit` collapses to **one global bucket for the whole site**. (This app no longer
depends on that — `vault.api._enforce_reveal_budget` keys on the authenticated user — but
every other app on the bench still does.)

The fix is one directive in the nginx config, and an image is exactly the right place for it:

```nginx
set_real_ip_from 172.18.0.0/16;   # the docker bridge, not 127.0.0.1
real_ip_header X-Forwarded-For;
real_ip_recursive off;            # keep: nginx then takes the LAST element, the one Apache
                                  # appended — not the first one a client can invent
```

It changes whose IP the whole stack trusts and affects every app on the bench, so it needs
Praveen's approval. Details and the evidence are in `NOTES/client-ip-behind-apache.md`.

## Verification checklist after the swap

```bash
cd /home/azureuser/frappe_docker

# 1. present and importable in ALL FIVE — use env/bin/python, not `python`
for c in backend queue-short queue-long scheduler websocket; do
  printf "%-12s " "$c"
  docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench "$c" \
    bash -lc 'env/bin/python -c "import sssihms_password_vault" && echo ok || echo MISSING'
done

# 2. installed on the site
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench backend \
  bash -lc 'bench --site frontend list-apps | grep password_vault'

# 3. schema actually migrated — this is the one that was silently wrong before
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench backend bash -lc \
  'bench --site frontend mariadb --execute "select options from tabDocField where parent=\"Credential Access Log\" and fieldname=\"action\""'
#    must list 10 actions, ending: ... health_report, space, reminder

# 4. the suite
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench backend bash -lc \
  'bench --site testspv.local run-tests --app sssihms_password_vault'

# 5. the scheduler container can actually run the job
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench scheduler bash -lc \
  'bench --site frontend execute sssihms_password_vault.vault.reminders.daily_rotation_sweep'

# 6. the other hospital sites still serve
curl -s -o /dev/null -w "%{http_code}\n" https://ops.sssihms.org
curl -s -o /dev/null -w "%{http_code}\n" https://erp.sssihms.org
```

An end-to-end check worth doing once, on `frontend`, via `bench console`: create a Vault
Space, confirm it writes both a `membership` and a `space` access-log row, create a
credential, `reveal_secret` it and confirm the plaintext returns and logs `success`, then
call it with `field_key="<img src=x onerror=1>"` and confirm it is refused and logged as
`(malformed)` rather than verbatim. Delete both afterwards. That exercises the parts most
likely to be broken by a bad deploy, in about a minute.

If anything fails, report it rather than editing the app's code — the reveal path and the
audit log have invariants (documented in `CLAUDE.md`) that are easy to break silently.
