# What the vault actually sees as a client IP (checked 24-Aug-2026)

Audit finding H2 said the reveal rate limit was bypassable by spoofing `X-Forwarded-For`,
and M4 said every log row's `ip_address` was attacker-controlled. Both rest on Frappe taking
`request_ip` from the first element of the caller's own `X-Forwarded-For`. **Neither is
exploitable in this deployment** — and what is true instead is worth knowing, because it is
not better news than it sounds.

## The chain

```
client → Apache (:443, ProxyPass to 127.0.0.1:8080) → frontend container nginx → gunicorn
```

- **Apache** sets only `X-Forwarded-Proto`. There is no `RequestHeader set X-Forwarded-For`
  anywhere in `/etc/apache2`, and `mod_remoteip` is not loaded — so `mod_proxy_http`'s
  default applies: it *appends* the real peer to whatever the client sent.
- **nginx** (`/etc/nginx/conf.d/frappe.conf` in the frontend container) is what decides it.
  `location @webserver`, which serves every dynamic request including `/api/method/...`,
  does `proxy_set_header X-Forwarded-For $remote_addr` — it **overwrites**, discarding the
  client's value entirely.
- `set_real_ip_from 127.0.0.1` does not match, because Docker port publishing means the
  container sees the connection coming from the bridge gateway (`172.18.0.1`), not
  `127.0.0.1`. So the real_ip module never rewrites `$remote_addr` either.

## Verified, not inferred

A request to `https://erp.sssihms.org/api/method/frappe.ping` carrying
`X-Forwarded-For: 203.0.113.99` was logged by nginx as `172.18.0.1`. The spoofed value never
reached Frappe. And in the site's own `tabActivity Log`:

| ip_address | rows |
|---|---|
| 172.18.0.1 | 43 |
| 103.206.8.20 | 2 |

## So what

1. **H2 does not apply. Do not remove the per-user reveal budget on that basis** — it is now
   the *only* meaningful limit, for the opposite reason. Because every request arrives as
   `172.18.0.1`, Frappe's IP-keyed `@rate_limit` collapses to one global bucket: 30 reveals
   per 5 minutes shared by every user on the site. Without the per-user budget in
   `vault.api._enforce_reveal_budget`, two busy people would have throttled each other, and
   one person could have locked out everybody.
2. **M4 lands differently.** `ip_address` is not forgeable — it is *uninformative*. Every
   audited reveal through the web path records the Docker gateway. For a log whose stated job
   is "who and from where", the second half is dead weight. `_client_ip()` recording the
   socket peer alongside it does not help here, since both are container-internal.
3. The two real public IPs are not an anomaly: `location /socket.io` uses
   `$proxy_add_x_forwarded_for`, which preserves the chain. So the true client IP *is*
   present at nginx — Apache does append it — and only `@webserver` throws it away. Note the
   corollary: on the socket.io path the header genuinely is client-influenced. No vault
   endpoint is served there.

## The fix, and why it was not applied

In the frontend container's nginx config, trust the gateway and let the real_ip module do its
job:

```nginx
set_real_ip_from 172.18.0.0/16;   # the docker bridge, not 127.0.0.1
real_ip_header X-Forwarded-For;
real_ip_recursive off;            # keep: takes the LAST element, the one Apache appended
```

`real_ip_recursive off` is what keeps this safe — nginx uses the last address in the header,
which is the peer Apache observed, not the first one a client can invent. `@webserver`'s
`$remote_addr` then becomes the true client IP.

Not applied here, deliberately. That file is frappe_docker's shared nginx config serving
every other app on this bench (`sssihms_hr`, `hospital_ops`, `facility_management`,
`patient_ticketing`, `trust_compliance`), it lives in the container's writable layer and dies
on the next image pull, and changing whose IP the whole stack trusts is not a password-vault
decision. It belongs in the image or the compose config, and it is Praveen's call.
