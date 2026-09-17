# Upstream sync log

This study translation tracks NVIDIA/OpenShell (Rust). This file records what
each sync pulled forward so the next one has a baseline.

## 2026-09-17

- **Baseline before sync:** upstream `596d729` (~2026-07-30) — the commit the
  translation was last based on, verified by spot-checking `secrets.rs` symbols
  against `secrets.py`.
- **Synced to:** upstream `cb93f62` (2026-09-17).
- **Scope:** refresh the already-translated core-logic modules + add net-new
  *sibling* modules in the same conceptual space. Driver/CLI/TUI churn (docker
  `lib.rs`, cli `run.rs`, tui `app.rs`, …) was intentionally **not** re-synced —
  the translation deliberately stubs those layers.

### Refreshed (existing modules)
- `openshell_core/secrets.py` — full rewrite: revisioned placeholder format
  changed (`rev:<n>:KEY` → `v<revision>_KEY`) + new stable-handle form
  (`s<hash>_KEY`); endpoint scoping (`denied`/`identity_bound` keys,
  `EndpointMismatch`); byte/header marker detection; full request-line
  path/query rewriting with `[CREDENTIAL]` redaction (`rewrite_target_for_eval`,
  `redact_target_for_policy`, `rewrite_http_header_block`).
- `openshell_core/sandbox_env.py` — `OPENSHELL_SANDBOX_COMMAND` replaced by
  versioned `MAIN_PROCESS_SPEC` + `MainProcessConfig` (JSON/base64url); new env
  vars (`ADMITTED_ISOLATION_BACKEND`, `NETWORK_RUNTIME_CAPABILITIES`,
  `PROXY_CA_CERT/KEY`, `SSH_SOCKET_SHARED`, …). Updated `podman_container.py`
  caller accordingly.
- `openshell_core/jwt.py` — grew from an `exp` reader into the session-JWT
  framework: validated newtypes (`SandboxId`, `CredentialEpoch`,
  `SessionRotation`), `SessionTokenProfile`, `SecretJwt`, auth bundles +
  `validate`, `SessionBearerTokenSlot`, `SessionJwtVerifier.validate_claims`.
  Ed25519 signing/verification stubbed with citations.
- `openshell_core/provider_credentials.py` — endpoint-scoped resolvers,
  `ChildEnvironmentSnapshot`, `installation_id`, install/revoke bound
  environment, `gcp_token_response`.
- `openshell_core/config.py` — `PolicyValidationFailureMode`, `ImagePullPolicy`,
  `AppArmorProfile`, `UpstreamProxyConfig`; `Config` gained `name`,
  `policy_validation_failure_mode`, single `compute_driver`, credential drivers;
  interceptor `resolved_audience`; `GatewayJwtConfig.sandbox_token_ttl`.
  `ComputeDriverKind`/detection kept as a compat shim (removed from
  `openshell-core::config` upstream; where detection now lives was not verified).
- `openshell_core/time.py` — protobuf Timestamp/Duration validation +
  conversion suite.
- `openshell_core/policy.py` — landlock compatibility now validates (raises)
  instead of silently defaulting; `is_valid_landlock_compatibility`.
- `openshell_core/paths.py` — Windows `%APPDATA%`/`%LOCALAPPDATA%` XDG
  fallbacks; noted `normalize_path` moved to `openshell-policy-schema` upstream.
- `openshell_core/metadata.py` — updated resource-type set (dropped
  InferenceRoute/StoredProvider*, added SandboxWorkloadTemplate);
  `object_workspace` accessor.
- `openshell_policy/compose.py` — `generated_rule_name`,
  `canonicalize_advisor_add_rule`.

### Added (new sibling modules)
- `openshell_core/secrets_body.py` — full translation of `secrets_body.rs`
  (body-credential classifier + streaming placeholder guard).
- `openshell_core/sandbox_generation.py`, `openshell_core/sandbox_session.py` —
  validated ID newtypes referenced by `jwt.py`.
- `openshell_core/rpc_error.py` — gRPC error-detail constructors.
- `openshell_policy/validate.py` — `validate_and_canonicalize_sandbox_policy`,
  `PolicyValidationError`, endpoint-ambiguity detection (`ambiguity.rs`).

### Deferred (not yet translated — genuine new concepts, next session)
- `openshell-core`: `oauth.rs` (+767), `spiffe.rs` (+177), `mcp.rs` (+339),
  `policy_identity.rs` (+177), `shell.rs`, `local_api_socket.rs`,
  `sandbox_session.rs` beyond the ID type, `inference.rs` (removed upstream).
- Deeper internals of `merge.rs`/`ambiguity.rs` overlap predicates (summarized
  with citations here).
- Driver / CLI / TUI re-sync (out of scope by design).
