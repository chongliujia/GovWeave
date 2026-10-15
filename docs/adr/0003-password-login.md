# ADR 0003: Administrator password and browser sessions

**English** | [简体中文](../zh-CN/adr/0003-password-login.md)

- Status: Accepted, 2026-10-15.
- Supersedes: Administrator token handling and the Go baseline in [ADR 0001](0001-gateway-first.md).
- Motivation: Operators should set an initial password directly, without managing a token file.

## Decision

A new console asks the operator to set and confirm an administrator password, then signs them in. Subsequent visits use that password. There is no cloud account, username, default password, or manual management-token step. Refresh retains the session; logout revokes it. Sessions expire after eight hours and are cleared by process restart. The instance still has one administrator; application keys remain separate.

Store a random 16-byte salt and a PBKDF2-HMAC-SHA256 hash with 600,000 iterations in `admin.password.json`, mode `0600`. Use Go's standard `crypto/pbkdf2` implementation, raising the module baseline from Go 1.22 to 1.24. The distribution toolchain remains pinned to 1.26.9. This choice is not a claim of FIPS certification. Password derivation happens at setup/login, not in the model request path.

Generate session values using cryptographic randomness. Keep only their hashes and expiry times in server memory, capped at 128 sessions. Use an HttpOnly, SameSite=Strict cookie scoped to `/api/`, with Secure for HTTPS. Management mutations require JSON, a custom request header, and origin validation. Do not enable CORS or trust forwarding headers to establish administrator identity.

Limit password attempts globally to ten per minute and one concurrent derivation. This is a single-instance limit, not a distributed attack-prevention system.

## Setup, recovery, and migration

Complete first-time setup before opening a fresh instance to other users. An existing password file prevents reinitialization. A corrupted file fails startup rather than reopening password setup.

Legacy token files identify migration only and no longer authenticate management requests. An installation with a token but no password permits setup only by direct loopback access. For containers, proxies, and custom paths, operators isolate access before migration as described in [Deployment](../deployment.md#migration-from-token-based-administration). Connections, application keys, instance configuration, and request records remain in place.

There is no public reset API. Password recovery requires a deployment operator to stop the service and manage the password state file. Multi-administrator accounts, MFA, SSO, and an authenticated password-change UI remain future work.
