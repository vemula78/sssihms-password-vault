# Deploying sssihms_password_vault to the evaluation bench

Target: `sssihms-web-vm2023`, `/home/azureuser/frappe_docker` (`pwd.yml`), site `frontend`.
Frappe 16.31 / ERPNext 16.32. Evaluation stage — synthetic data only.

The bench's app code lives in each container's writable layer (see the
facility-management PERSISTENCE.md finding): **this GitHub repo is the source of truth**,
and the app must be present in all five app containers or background jobs crash-loop.

## Install / update

**`git clone` inside the containers does not work.** The repo is private and the containers
hold no GitHub credentials, so the clone prompts for a username and fails — the procedure
this file used to document could never have run. (Found the hard way on 24-Aug-2026, after
it had already `rm -rf`'d the app in all five containers.) The alternatives are a deploy key
or PAT baked into five containers, which puts a credential where it does not belong, or
shipping an archive of a known commit — which is what this does.

Deploy from a local clone, from the commit you intend to ship:

```bash
# On the Mac, in the repo:
git archive --format=tar.gz --prefix=sssihms_password_vault/ -o /tmp/spv.tar.gz HEAD
scp -i ~/Downloads/sssihms-web-vm2023_key.pem -P 2222 /tmp/spv.tar.gz \
    azureuser@20.219.253.136:/tmp/spv.tar.gz
```

```bash
# On the VM:
cd /home/azureuser/frappe_docker
for c in backend queue-short queue-long scheduler websocket; do
  docker cp /tmp/spv.tar.gz "frappe_docker-${c}-1:/tmp/spv.tar.gz"
  docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench "$c" bash -lc '
    rm -rf apps/sssihms_password_vault
    tar xzf /tmp/spv.tar.gz -C apps/
    env/bin/pip install -q -e apps/sssihms_password_vault
    rm -f /tmp/spv.tar.gz'
done

# First install only — register the app on the site:
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench backend bash -lc '
  grep -qx sssihms_password_vault sites/apps.txt || echo sssihms_password_vault >> sites/apps.txt
  bench --site frontend install-app sssihms_password_vault'

# Every deploy — BOTH sites, and migrate is not optional when a doctype JSON changed:
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench backend bash -lc '
  bench --site frontend migrate && bench --site frontend clear-cache
  bench --site testspv.local migrate && bench --site testspv.local clear-cache'

docker compose -f pwd.yml restart backend queue-short queue-long scheduler websocket
```

`pip install -e` only needs re-running when dependencies or entry points change; the
extract alone is enough for a pure code change, since the install is editable and points at
the same path.

**Migrate both sites, and migrate them after the code is in place.** A Select option added
to a doctype JSON does not reach the database until `migrate` runs, and a stale Select fails
at *insert* time — inside a controller `validate()`, which turns a logged security event
into a hard error on an unrelated save. Getting this out of order on 24-Aug-2026 broke Vault
Space creation on `frontend` while the tests passed on `testspv.local`.

Verify the app is actually present in all five, not just backend:

```bash
for c in backend queue-short queue-long scheduler websocket; do
  printf "%-12s " "$c"
  docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench "$c" \
    bash -lc 'env/bin/python -c "import sssihms_password_vault" && echo ok || echo MISSING'
done
```

Use `env/bin/python`, not `python` — the bare interpreter is the system one and will report
the module missing even on a perfectly good install.

## Tests on the bench

**Run tests on `testspv.local`, never on `frontend`.** `frontend` has ERPNext installed, and
ERPNext's `before_tests` hook bootstraps master data including a fiscal year — which
collides with the fiscal years already on that site and aborts the whole run before a single
test executes. `testspv.local` carries frappe plus this app only, so there is no bootstrap
to collide.

```bash
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench backend bash -lc \
  'bench --site testspv.local run-tests --app sssihms_password_vault'
```

Full green is **94 tests**: 54 pure + 31 credential + 7 access-log + 2 vault-space.
`--app` runs the site suites and the pure suites as two batches (40 then 54).

Individual modules:

```bash
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench backend bash -lc \
  'bench --site testspv.local run-tests --module sssihms_password_vault.password_vault.doctype.vault_credential.test_vault_credential'
```

## Never

- Never edit app code only inside a container — it dies on the next image pull.
- Never install on a site with real data while the app is in evaluation.
