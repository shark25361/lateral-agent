# Controlled Windows lab execution

This adapter is optional. For a FourCore-only mission set `LATERAL_EXECUTOR_ENABLED=false`; no executor URL, bearer token, verifier key, or credential reference is needed. The agent can review and run matching catalogue chains through FourCore after exact-plan authorization. Only the execution source must be an allowlisted, connected FourCore endpoint; the exact operator-supplied destination ID is used to match later report evidence and need not be in FourCore inventory. The generic FourCore chain-run request receives the source asset, **not** the requested destination; a preflight warning makes that visible. A completed lateral chain proves only simulation unless its execution report includes a successful step explicitly naming the requested destination asset, protocol, remote execution result, and observed destination identity. That conditional provider-reported result appears as an `observed` remote-access edge in the AD graph; signed destination-verifier evidence, when used, remains a distinct `verified` edge. The published SDK report schema does not guarantee those destination-specific fields, so a live report may leave the remote objective unknown.

For an A-to-B mission, B is an exact planning goal. A structured report may identify an intermediate C instead; the graph records A-to-C and the planner may next run a reviewed chain on C only if C is itself an allowlisted, live, connected FourCore asset. A completed sequence of explicit remote observations A-to-C-to-B can satisfy the objective only if each later step also reports `parent_execution_id` (or `pivot_execution_id`) matching the preceding hop's execution, and the final step observes the requested identity on B. Without that correlation, the graph displays two observations but does not claim an end-to-end pivot. Simulation-only reports never create machine-hop edges. When no eligible catalogue action remains, the mission reports `unattainable`—impossible **within the configured catalogue, allowlist, and evidence**, not a claim that no network path exists. The published FourCore chain-run request cannot force a chosen destination B or guarantee pivot-correlation fields; genuinely destination-directed execution still requires a destination-capable provider action or executor.

The built-in lab adapter supports one fixed action: Kerberos WinRM from an allowlisted Windows source to an allowlisted Windows destination on port 5985. It invokes a preinstalled destination verifier, not a user-supplied command. It does not implement SMB, RDP, SSH, credential dumping, or arbitrary shell payloads. FourCore simulations remain separate.

## Prepare each destination

Build `./cmd/lab-verifier` for Windows and install the binary at a fixed absolute path. On that destination, run `lab-verifier.exe keygen <dedicated-key-directory>` once. Restrict the private-key directory and verifier binary ACLs to the intended lab execution account and administrators; never put the private key in this repository or the agent `.env`. Configure the verifier process with:

- `LAB_VERIFIER_ASSET_ID`: the destination's exact allowlisted asset ID.
- `LAB_VERIFIER_HOSTNAME`: the destination's local Windows hostname.
- `LAB_VERIFIER_ALLOWED_SOURCE_IDS`: only approved source asset IDs.
- `LAB_VERIFIER_PRIVATE_KEY_PATH`: the destination-local key file.

The public key may be copied to the source executor and application. Give each destination verifier its own key and use the per-destination key maps for routes with several destinations. Do not copy a destination private key to another host.

## Prepare each source

Build `./cmd/lab-executor` for Windows. Run one instance on each source machine under a provisioned domain account with Kerberos access to the intended destination. Configure:

- `LAB_EXECUTOR_SOURCE_ASSET_ID`, `LAB_EXECUTOR_SOURCE_HOSTNAME`: exact source asset and local host.
- `LAB_EXECUTOR_DESTINATIONS`: comma-separated `destination-asset-id=host` bindings. Only list approved lab targets; use a DNS name with a valid Kerberos SPN, not a bare IP address.
- `LAB_EXECUTOR_CREDENTIAL_PROFILES`: comma-separated `opaque-reference=DOMAIN\account` mappings. The selected mapping must equal the executor's actual process identity; it is not a password or a vault fetch.
- `LAB_EXECUTOR_VERIFIER_PATH`: fixed absolute path of the preinstalled verifier binary on the destination.
- `LAB_EXECUTOR_EVIDENCE_PUBLIC_KEY`: base64 Ed25519 public key for a single destination verifier. For several destinations use `LAB_EXECUTOR_EVIDENCE_PUBLIC_KEYS` with `destination-asset-id=base64-public-key` bindings.
- `LAB_EXECUTOR_TOKEN`: a separate random bearer token of at least 24 characters.
- `LAB_EXECUTOR_DATA_DIR`: a dedicated, access-controlled directory for the durable job database.
- `LAB_EXECUTOR_LISTEN`, `LAB_EXECUTOR_TLS_CERT`, `LAB_EXECUTOR_TLS_KEY`: HTTPS listener and certificate trusted by the application host.

Do not expose the executor listener beyond the application host or approved lab management network. The executor accepts only the configured source, destination bindings, credential profiles, WinRM protocol and fixed port. It writes a durable correlation ID before launching WinRM; after an uncertain restart it fails closed and does not replay the remote action.

## Configure the application

Set `LATERAL_EXECUTOR_ENABLED=true`, `EXECUTION_ENABLED=true`, the matching `LATERAL_EXECUTOR_TOKEN`, `LATERAL_ALLOWED_DESTINATIONS`, `LATERAL_CREDENTIAL_REFS`, `LATERAL_DEFAULT_CREDENTIAL_REF` and `ALLOWED_ENDPOINT_ASSETS`. Set `LATERAL_EVIDENCE_PUBLIC_KEY` for one destination or `LATERAL_EVIDENCE_PUBLIC_KEYS` for per-destination keys. For one source, set `LATERAL_EXECUTOR_BASE_URL`; for multiple hop sources, use `LATERAL_SOURCE_EXECUTORS` with an HTTPS URL for every source. The source map takes precedence over the base URL; any missing source mapping blocks that hop. Keep all destinations and intermediate sources in the explicit endpoint allowlist.

To review a controlled-lab route without FourCore's asset inventory, set `LAB_ASSETS_FILE` to a local JSON file containing only explicitly allowlisted Windows endpoints:

```json
[
  {"id":"SOURCE_ASSET_ID","name":"source-lab-host","platform":"windows"},
  {"id":"DESTINATION_ASSET_ID","name":"destination-lab-host","platform":"windows"}
]
```

The file is an operator declaration. The UI/tool reports its live status as unknown, and mission facts record only `lab_asset_registered`; it does not assert that either machine is connected, reachable, privileged or controlled. In this mode, lab-action authorization validates the explicit registry, endpoint allowlist, source executor binding, destination host binding, typed inputs and route fingerprint without calling FourCore asset inventory. Executor health is checked in plan diagnostics, and only matching signed destination evidence can prove remote access. Omit `LAB_ASSETS_FILE` to retain the existing live FourCore inventory checks. FourCore simulation chains still require a functioning FourCore API at authorization and submission; a local catalogue snapshot contains metadata, not executable attacks.

The mission API accepts `starting_access` as an operator assumption, for example `{"asset_id":"SOURCE_ASSET_ID","access_level":"user","identity":"LAB\\alice"}`. It is stored separately from observed facts and does not mark any requirement proven or create an AD permission edge. Starting with a user account does **not** automatically require administrator rights on the source: the planner may consider a user-level route when actual evidence supports one. The desired administrator identity on the destination still requires destination-side evidence.

This adapter does **not** transfer rights from a simulated privilege-escalation chain. The source executor uses a pre-provisioned process identity, so a successful lab proof shows access under that identity, not autonomous acquisition of new rights. Demonstrating a rights-acquisition step requires evidence that the later executable context was actually obtained and securely handed to the executor, followed by destination proof bound to that same attempt. The initial user foothold itself may be an operator assumption. `ALLOW_ELEVATED=true` only permits elevated FourCore simulations; it does not grant the executor administrator rights.

Create a mission, inspect its selected edge IDs and typed action inputs, run the plan diagnostics, and authorize the exact plan hash. Each hop is executed and verified before a new plan is proposed for the next source. The application proves remote access only after checking the destination signature, the execution ID, the authorized input hash, the route, observation time and expected identity.

Automated tests use only local TLS fixtures and synthetic `attack.test`/`secattack` assets. No deployment to a Windows host or live WinRM attempt is part of the test suite. A real proof still requires provisioned lab hosts, TLS material, Kerberos access, and an operator-authorized mission. The verifier's signing key is held in the remote account's security context; a compromised privileged destination account could misuse it, so this is a controlled-lab attestation rather than hardware-backed independent evidence.
