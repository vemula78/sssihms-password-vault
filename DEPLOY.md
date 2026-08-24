# Deploying sssihms_password_vault to the evaluation bench

Target: `sssihms-web-vm2023`, `/home/azureuser/frappe_docker` (`pwd.yml`), site `frontend`.
Frappe 16.31 / ERPNext 16.32. Evaluation stage — synthetic data only.

The bench's app code lives in each container's writable layer (see the
facility-management PERSISTENCE.md finding): **this GitHub repo is the source of truth**,
and the app must be present in all five app containers or background jobs crash-loop.

## Install / update

```bash
cd /home/azureuser/frappe_docker

# 1. Fetch/refresh source in ALL FIVE app containers
for c in backend queue-short queue-long scheduler websocket; do
  docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench $c bash -lc \
    'rm -rf apps/sssihms_password_vault && \
     git clone --depth 1 https://github.com/vemula78/sssihms-password-vault apps/sssihms_password_vault && \
     env/bin/pip install -q -e apps/sssihms_password_vault'
done

# 2. Register + install on the site (backend only)
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench backend bash -lc '
  grep -qx sssihms_password_vault sites/apps.txt || echo sssihms_password_vault >> sites/apps.txt
  bench --site frontend install-app sssihms_password_vault
  bench --site frontend migrate
'

# 3. Restart workers so all containers pick up the code
docker compose -f pwd.yml restart backend queue-short queue-long scheduler websocket
```

Update = same steps (clone is idempotent via rm -rf; `install-app` is replaced by
`bench --site frontend migrate` once installed).

## Tests on the bench

```bash
docker compose -f pwd.yml exec -T -w /home/frappe/frappe-bench backend bash -lc \
  'bench --site frontend run-tests --app sssihms_password_vault'
```

## Never

- Never edit app code only inside a container — it dies on the next image pull.
- Never install on a site with real data while the app is in evaluation.
