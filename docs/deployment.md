# Deployment and operations

**English** | [简体中文](zh-CN/deployment.md)

GovWeave 0.2.0-dev runs as one process for one organization. Linux is the primary tested platform. macOS code paths exist but still need platform verification; the current file-lock implementation does not support Windows.

This guide covers the gateway itself. You provide the model service, network access, DNS, and TLS termination. Model configuration and credential policy behavior are described in [Model gateway](model-gateway.md) and [Runtime policies](runtime-policies.md).

## Run from a source checkout

From the repository root, with Go 1.24 or later installed:

```bash
go run ./cmd/govweave -config examples/deployment.json
```

The supplied example listens on `127.0.0.1:8080` and stores data in `./data`. Build a standalone binary with `make build`, then run:

```bash
./bin/govweave -config examples/deployment.json
```

Open http://127.0.0.1:8080 and set the initial administrator password. Passwords accept 12–128 Unicode characters, including spaces. There is no default password or administrator token to copy. The first person to complete setup claims a fresh instance, so finish setup on a controlled network before opening access.

To use another port, override the listener and use the same port in your browser:

```bash
GOVWEAVE_LISTEN_ADDR=127.0.0.1:8081 ./bin/govweave -config examples/deployment.json
```

Changing the listener does not automatically change the saved public URL. Update **Deployment & access** if applications should use the new address.

## Server configuration

The server accepts deployment JSON, environment overrides, and console-saved instance settings. The contract is [deployment.schema.json](../schemas/deployment.schema.json).

```json
{
  "schema_version": 1,
  "listen_addr": "0.0.0.0:8080",
  "data_dir": "/var/lib/govweave",
  "organization_name": "Enterprise AI platform",
  "public_url": "https://ai.example.com"
}
```

`ai.example.com` is a placeholder. Replace it with your actual address, and ensure the service user can write to the data directory. Omit the organization and public URL to configure them in the console later.

| JSON field | Environment variable | Default |
| --- | --- | --- |
| `listen_addr` | `GOVWEAVE_LISTEN_ADDR` | `127.0.0.1:8080` |
| `data_dir` | `GOVWEAVE_DATA_DIR` | `./data` |
| `organization_name` | `GOVWEAVE_ORGANIZATION_NAME` | Set in the console |
| `public_url` | `GOVWEAVE_PUBLIC_URL` | Set in the console |

For organization and public URL, precedence is **environment > deployment file > saved instance > unset**. Listener and data directory use **environment > deployment file > defaults** and cannot be changed through the console. Empty environment values are rejected; unset a variable to remove its override. Deployment JSON rejects unknown fields, null or empty values, and extra JSON objects. Its size limit is 64 KiB.

Organization and public URL fields supplied by deployment configuration are read-only in the console; the API enforces the same restriction. Restart after changing a deployment file or environment variable. Removing an override restores the last complete effective settings saved through the console, including any overrides that were effective at that save. If nothing has been saved, complete setup again.

All relative paths resolve against the **process working directory**, not the deployment file's directory. Validate configuration without binding a port or creating data files:

```bash
./bin/govweave -config examples/deployment.json -check-config
./bin/govweave -version
```

**Export deployment config** includes the current listener, organization, and public URL. It excludes passwords, model connections, application keys, policies, and data-directory settings. It is not an instance backup. Using the exported file makes its organization and URL deployment-managed on the next start.

`GOVWEAVE_BASE_URL` and `GOVWEAVE_API_KEY` in client examples are application-side environment variables. They do not configure the server.

## URLs, HTTPS, and remote access

The listener controls where the process binds. `public_url` declares the root address clients should use. These are separate settings.

| Address | Example | Meaning |
| --- | --- | --- |
| Listener | `0.0.0.0:8080` | Bind all IPv4 interfaces on this host |
| Gateway root URL | `https://ai.example.com` | Console and public origin |
| Application base URL | `https://ai.example.com/v1` | Model SDK/API endpoint |
| Upstream model base URL | `http://model-server:8000/v1` | Provider endpoint configured by an administrator |

A remote application cannot reach your host by using its own `localhost`. `0.0.0.0` and `::` are binding addresses, not client base URLs.

`public_url` must be an HTTP(S) origin. A trailing slash is normalized away. Paths, including `/v1` and reverse-proxy path prefixes, credentials, queries, fragments, and wildcard listening addresses are rejected. IPv4, IPv6, loopback, and valid internal or public hostnames are supported.

For access across an enterprise network:

- Provide HTTPS through a reverse proxy; the gateway does not issue certificates or create DNS records.
- Forward the root path and preserve the original `Host`. If the proxy rewrites it, set the actual `public_url` in deployment configuration before management requests use that origin.
- Preserve request cancellation and disable response buffering for SSE. Set proxy timeouts longer than the connection's configured request timeout.
- Apply network access controls for the management interface and initialize the password before exposing it.

The service does not derive configuration or trusted client identity from forwarded headers. Management writes validate the request origin and require a custom header. CORS is not enabled. The configured URL is not automatically checked for reachability.

`GET /healthz` checks process liveness only. The console's service indicator does not prove that a configured domain, model connection, or model inference is working. `configured: true` means the organization and public URL are set, not that the model is ready. The generated MCP URL is marked `planned` and is not an implemented endpoint.

## Container deployment

From a source checkout with Docker and Compose installed:

```bash
docker compose build
docker compose up -d --no-build
docker compose logs --tail=50 govweave
```

Building requires a cached or reachable `golang:1.26.9` base image. There is no published-image download requirement in this workflow; you build the tagged `govweave:0.2.0-dev` image locally.

Compose publishes `127.0.0.1:8080` by default. The following variables configure **Compose**, rather than the server directly:

| Variable | Default | Purpose |
| --- | --- | --- |
| `GOVWEAVE_BIND_IP` | `127.0.0.1` | Host interface for the published port |
| `GOVWEAVE_PORT` | `8080` | Host port |
| `GOVWEAVE_CONFIG` | `./examples/deployment.json` | Deployment JSON mounted read-only |

For example, publish only on loopback port 8081:

```bash
GOVWEAVE_PORT=8081 docker compose up -d --no-build
```

Binding to an enterprise interface is an operator decision. `GOVWEAVE_BIND_IP=0.0.0.0` exposes the published port on all host IPv4 interfaces; arrange the proxy and network access controls accordingly.

Inside the container, Compose overrides the listener to `0.0.0.0:8080` and the data directory to `/data`. Data uses the named `govweave-data` volume, with a Compose project prefix. The image runs as UID/GID 65532 with a read-only root filesystem and a writable data volume. If replacing the named volume with a host bind mount, prepare that directory's ownership and permissions for UID/GID 65532.

Container `localhost` means the container itself. Use a network-reachable provider address for model connections. The image includes a CA trust bundle. Private CAs can be mounted read-only and configured using Go's `SSL_CERT_FILE` or `SSL_CERT_DIR`; there is no option to skip TLS verification. The upstream transport does not use `HTTP_PROXY` or `HTTPS_PROXY`.

Use `docker compose stop` to stop this deployment without deleting its data. `docker compose down -v` deletes the named volume and is not a routine restart or upgrade command.

## Offline distribution

On a build machine with the Go toolchain already installed:

```bash
make package
```

This creates `dist/govweave-0.2.0-dev-<os>-<arch>.tar.gz` and a `.sha256` file. The build disables Go module fetching. Transfer both files through your trusted distribution channel. For Linux amd64, run in the directory containing the downloaded files:

```bash
sha256sum -c govweave-0.2.0-dev-linux-amd64.tar.gz.sha256
tar -xzf govweave-0.2.0-dev-linux-amd64.tar.gz
cd govweave-0.2.0-dev-linux-amd64
./govweave -config examples/deployment.json
```

The target needs neither Go nor Node, but its OS and CPU must match the artifact. On macOS, use `shasum -a 256 -c` for checksum verification. Checksums are provided; signed releases are not implemented. The archive contains the executable, English and Chinese documentation, examples, API schemas, and licenses. It contains no instance data, credentials, model weights, or regulatory datasets. Source-build commands in these guides require a source checkout, which is not included in the binary archive.

For an offline container installation, save the locally built image:

```bash
docker save -o govweave-image.tar govweave:0.2.0-dev
```

Transfer the image archive plus `compose.yaml` and `examples/deployment.json` from the source checkout. On the target:

```bash
docker load -i govweave-image.tar
docker compose up -d --no-build --pull never
```

There is no cloud login, telemetry, CDN, model downloader, or regulatory updater in this version. Inference still needs a reachable model service. A container starting with `--network none` proves offline startup, not access to a model outside that container.

## Persistent data and backups

Files are created when their corresponding features are initialized or saved. Treat the data directory as sensitive operational state.

| File | Contents and operational role |
| --- | --- |
| `admin.password.json` | Salted PBKDF2-HMAC-SHA256 password hash and parameters; mode `0600` |
| `instance.json` | Console-saved instance settings and revision |
| `gateway.json` | Connections and applications; encrypted provider credentials, hashed application keys, and other unencrypted configuration |
| `gateway.key` | Local AES-256-GCM encryption key required to decrypt saved provider credentials |
| `policies.json` | Latest credential policy, revision, and rule-set version; created on first save |
| `calls.jsonl` | Metadata-only start and finish records; mode `0600`, capped at 128 MiB |
| `.instance.lock` | OS-held process lock; not a configuration file |
| `admin.token`, if present | Legacy migration marker only; no longer accepted for authentication |

Private state files must retain restrictive permissions. Configuration saves use a synced temporary file followed by atomic replacement and revision checks. Invalid or unsupported persisted state causes startup to fail rather than silently reset. A missing `policies.json` means the disabled initial policy, so do not delete it to change enforcement.

For a consistent backup or upgrade:

1. Stop the instance and prevent another process from using its data directory.
2. Copy the data directory, deployment file, and the deployment environment settings to protected backup storage. Keep `gateway.key` with `gateway.json`.
3. Replace the executable or image, or restore the backup to the intended data directory while stopped. Preserve ownership and private file modes.
4. Start one instance. Check `/healthz`, sign in again, and verify connections, application grants, and the saved policy before application traffic resumes.

Do not share a directory between multiple processes, containers, or hosts. The file lock is automatically released on exit or crash; deleting the lock file is not a way to unlock a running process. This version has no HA storage, automated backup, KMS integration, tamper-evident audit storage, or guaranteed power-loss recovery. The local encryption key cannot protect against an attacker who controls both the process and data directory.

For log-capacity management, see [request records and archival](model-gateway.md#request-records-and-archival).

## Administrator access and recovery

There is one administrator password, no username, SSO, or MFA. Password hashing uses a random 16-byte salt and PBKDF2-HMAC-SHA256 with 600,000 iterations. Hashing runs at setup and login, not on model requests.

The browser receives an HttpOnly, SameSite=Strict session cookie scoped to `/api/`; HTTPS sessions are marked Secure. Sessions expire after eight hours, logout revokes them, and a process restart clears them. Sessions are stored only in server memory, with a maximum of 128. Password attempts are limited globally to ten per minute, with one derivation at a time; exceeding either limit returns `429`.

If the password is lost, a deployment administrator can stop the service, move `admin.password.json` to protected backup storage, restart on a controlled network, and set a replacement password. Preserve the other state files. If a legacy token marker remains, the legacy setup restrictions below still apply. There is no public password-reset endpoint.

Application authentication is separate. Create or rotate an application key under **Applications & keys**; never use an administrator password or session as a model API key.

## Migration from token-based administration

The older `admin.token` file no longer authenticates management requests. It is retained only to identify an existing installation during migration. The deprecated `admin_token_file` and `GOVWEAVE_ADMIN_TOKEN_FILE` settings have the same migration-only purpose; omit them for new installations.

An instance with a legacy token but no password accepts password setup only through a direct loopback connection with a loopback Host and no proxy forwarding headers. For a remote host, use an SSH tunnel to reach its loopback listener. This restriction prevents upgrading a token-protected instance from opening remote password setup.

For a legacy container, proxy, or custom token location, isolate the management entry point and stop the instance. Move the old token to protected backup storage and remove its deprecated path override, then restart and complete password setup before restoring access. An explicitly configured token path that no longer exists must be corrected before startup. Model connections, application keys, instance settings, and call records remain in place.

## Console language

English is the default regardless of browser language. Choose **English / 简体中文** on the sign-in screen, console header, or editor. The choice is stored under `govweave.locale` in localStorage. Passwords and keys are not saved there. If storage is unavailable, switching still works for the page and a reload returns to English.

Changing language preserves drafts, model grants, and any currently displayed one-time key. User-entered names, aliases, URLs, and log identifiers are not translated. API messages use English; applications should branch on stable `error.code` values. Translation assets are bundled locally.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Browser cannot connect | Process logs, listener/port, firewall, and proxy routing; use the server's address for remote access |
| `address already in use` | Another service owns the port; choose an unused port and update the public URL as needed |
| Instance fields are read-only | A deployment file or environment variable manages them; change that source and restart |
| A save returns `403 origin_denied` | Root origin, HTTPS scheme, proxy Host handling, and `X-GovWeave-Request: console`; configure `public_url` correctly |
| Signed out after restart | Expected: sessions are memory-only; sign in with the existing password |
| `429 login_limited` | Wait for the indicated retry interval; the limit is shared by the instance |
| `401 invalid_api_key` on a model call | Use an active application key, not an administrator password or provider key |
| `403 model_not_allowed` | The alias exists and its connection is granted to this application |
| `403 policy_blocked` | Inspect the request ID and matched rules in Request logs; do not paste the secret into a support report |
| `503 audit_unavailable` | Disk space, write permissions, and log capacity; stop and archive records as described in the model guide |
| Connection check succeeds but inference fails | Checks only read `/models`; verify actual model support and inference permissions with an application request |
| SSE arrives all at once | Proxy buffering and timeouts; the gateway forwards complete SSE events as they arrive |
| Startup rejects a state file | Restore a consistent backup or repair it while stopped; do not delete configuration to bypass validation |

See [error codes and streaming failures](model-gateway.md#streaming-timeouts-and-errors) for model-side handling.
