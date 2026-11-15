# Command-line administration

**English** | [简体中文](zh-CN/admin-cli.md)

`govweave admin` manages a running instance through the same administrator HTTP API as the console. It is included in the standard Go binary, container and offline archive; no Python, Node or separate CLI package is needed. Commands return JSON on stdout, errors on stderr, and a nonzero exit status on failure. They do not edit the live data directory. Only the explicit `tests run` command starts configured model/tool calls.

## Run the service in the background

From the source checkout, the existing Docker deployment provides background operation:

```bash
docker compose up -d --build
docker compose logs --tail=100 -f
```

Use `docker compose stop` to stop the service while retaining its volume. See [deployment](deployment.md) for configuration and persistence. The binary server command remains foreground-managed; `admin` is a client, not a process supervisor.

Build the local client with `make build`, or use the binary from the offline archive:

```bash
./bin/govweave admin --help
./bin/govweave admin status
```

The default URL is `http://127.0.0.1:8080`. `--url` takes the gateway root, without `/v1` or another path. Remote management requires HTTPS; HTTP is allowed only for loopback addresses or `localhost`. SSH forwarding is supported. The CLI does not follow redirects or use environment HTTP proxies. `--timeout 15s` bounds each HTTP request, with an allowed range of 1–60 seconds. A timeout after a write does not prove the write failed: read current state before retrying.

## Authenticate from a terminal

For a new instance, read the initial administrator password without echoing it. The following examples use Bash:

```bash
read -r -s -p 'Administrator password: ' gw_password
printf '\n'
printf '%s\n' "$gw_password" | ./bin/govweave admin --password-stdin setup
unset gw_password
```

For an existing instance, log in once and reuse an explicitly selected session file:

```bash
session_dir=$(mktemp -d)
read -r -s -p 'Administrator password: ' gw_password
printf '\n'
printf '%s\n' "$gw_password" | ./bin/govweave admin \
  --session-file "$session_dir/govweave.session.json" --password-stdin login
unset gw_password

gw() { ./bin/govweave admin --session-file "$session_dir/govweave.session.json" "$@"; }
gw applications list
gw connections list
gw policy show
```

Global flags, including `--url`, `--session-file` and password options, go **before** the command. If selecting a remote URL, use the same `--url` for login and subsequent commands. Sessions are bound to that exact origin, expire after at most eight hours on the server, and are invalidated by logout or server restart. A session file contains an administrator credential and uses `0600` permissions; it contains no password. Existing files are never overwritten during login. Reconnect using a new file after expiry or restart.

Without `--session-file`, authenticated commands accept `--password-stdin` or `--password-file /private/path` and automatically revoke their temporary session afterward. Password files must be private regular files. The existing global limit of ten sign-in/setup attempts per minute applies to successful logins too; reuse a session for repeated commands. No command accepts a password as an argument.

## Configure applications and policies

For product control gaps, the CLI also supports `products`, `reports`, `remediations` and `tests`. See [risk remediation](remediation.md) for JSON inputs and the progress/retest/verification flow. `tests run` explicitly starts configured model/tool calls; the other remediation commands perform local management and evidence checks.

| Command | Behavior |
| --- | --- |
| `applications list`, `connections list` | Resource metadata and current gateway revision |
| `applications create --file FILE`, `connections create --file FILE` | Create from the corresponding management API JSON input |
| `applications update --id ID --file FILE`, `connections update --id ID --file FILE` | Update using the revision in the JSON input |
| `applications rotate --id ID --revision N`, `applications revoke --id ID --revision N` | Rotate a key or revoke application access |
| `policy show --application ID` | Effective settings and whether they come from the default or an independent binding |
| `policy set --application ID --revision N --mode redact` | Update only that application's settings; unspecified settings are retained |
| `policy inherit --application ID --revision N` | Remove the independent binding and use the current default |
| `policy history --application ID` | Historical effective settings, newest first |
| `policy restore --application ID --revision N --from-revision OLD` | Copy historical effective settings into a new explicit binding |
| `requests list --application ID --limit 20` | Up to 100 recent metadata records; no captured bodies |

Creation/update files must be `0600` regular files up to 16 KiB and match the inputs in [OpenAPI](../api/openapi.yaml). Use revision zero for a new resource. For update, rotation or revocation, use the revision on that specific application or connection, not the top-level gateway revision. Policy commands use the separate shared output-policy revision. Application creation and key rotation return the **one-time application key** on stdout, so direct that output to the intended secret handling process. Listing resources does not reveal existing keys or provider credentials.

For example, after reading an application's policy, replace `APP_ID` and revision `7` below with the values you inspected:

```bash
gw policy show --application APP_ID
gw policy set --application APP_ID --revision 7 \
  --mode redact --detector sensitive-text-v3 --categories credential,email,phone
gw policy history --application APP_ID
```

Omitting `--application` from `policy show`, `history` or `set` selects the default policy. Default updates preserve independent application policies. `--scope all` or a comma-separated application list changes only the default scope. `--public-emails ''` explicitly clears email exceptions. Writes do not retry on conflicts. See [application policies](sensitive-output.md#independent-application-policies) for inheritance, history and evidence semantics.

When finished:

```bash
gw logout
rmdir "$session_dir"
unset -f gw
unset session_dir
```

Logout revokes the selected session and removes its file. Browser sessions are independent. If the server is unavailable, logout reports the failure and retains the file so revocation can be retried; a successful operation with an unconfirmed temporary-session logout also reports an error rather than claiming complete cleanup.
