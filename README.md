# Snitchgate

A terminal control room for OpenSnitch, built in Rust with Ratatui. A background
broker handles pending requests while the TUI provides inspection and temporary
allow/deny decisions. Optional Jev classification and Ollama explanations help
triage requests; deterministic policy controls automation.

This is an initial implementation. It has isolated gRPC and provider integration
tests; it has **not been connected to a live OpenSnitch daemon**. The service uses
its own private sockets and does not change your firewall configuration.

## Try it

Requires Linux, Rust 1.88 or newer, `protoc`, and SQLite development libraries.
On Arch, the corresponding packages are `rust`, `protobuf`, and `sqlite`.

```sh
cargo run -- demo
```

The demo uses three in-memory requests. It makes no provider calls, opens no
service sockets, and does not read or change firewall rules. Requests expire
after 100 seconds. Restart the demo to reset them.

Keys: `j/k` or arrows move; `a` allows; `d` denies; `t` toggles once/5 minutes;
`/` filters; `Tab` or `1/2/3` selects Inbox/History/Health; `PageUp/PageDown`
scrolls inspection; `q` quits. Decisions target the selected request ID, so an
expired request cannot turn a keypress into an approval for another request.

## Run the isolated service

```sh
cargo build
./target/debug/snitchgate serve
```

Defaults:

- OpenSnitch gRPC socket: `$XDG_RUNTIME_DIR/snitchgate/opensnitch.sock`
- TUI/control socket: `$XDG_RUNTIME_DIR/snitchgate/control.sock`
- SQLite history: `${XDG_STATE_HOME:-$HOME/.local/state}/snitchgate/history.sqlite3`

In other terminals:

```sh
./target/debug/snitchgate tui
./target/debug/snitchgate mock --socket "$XDG_RUNTIME_DIR/snitchgate/opensnitch.sock"
./target/debug/snitchgate status
```

The mock acts as an OpenSnitch gRPC client and submits a synthetic curl request
to loopback port 8000. Settle it in the TUI or use the full ID from `status`:

```sh
./target/debug/snitchgate decide REQUEST_ID allow
./target/debug/snitchgate decide REQUEST_ID deny --duration five-minutes
```

`serve --runtime-dir PATH --state-dir PATH` supports explicit test locations;
`tui`, `status`, `decide`, and `propose` accept `--socket PATH` for the control
socket. Runtime/state directories must be owned by the current user and private
(0700); sockets and the database use 0600. Existing sockets are never unlinked
at startup. After an unclean exit, verify no service owns a stale socket before
removing it. The service handles SIGINT and SIGTERM, denies pending requests
once, and removes its own sockets during normal shutdown.

Closing the TUI leaves the service running. A missing TUI, full queue, expired
request, or failed classifier never grants traffic or creates permanent policy.
Default request deadline: 90 seconds, below OpenSnitch 1.7.2's 120-second deadline.

## Jev and the second model

```sh
cp config.example.toml config.local.toml
./target/debug/snitchgate check-config config.local.toml
./target/debug/snitchgate serve --config config.local.toml
```

Enable `[jev]` only after provisioning `TYPESAFE_API_KEY` through your credential
manager or a private environment source. Keys are never accepted as CLI arguments
or stored in the config. Only Jev's official HTTPS endpoint is configured by
default; the pinned model is configurable and must be available to your account.
No provider calls are made by `check-config`.

Jev receives only process path, PID, UID, protocol, destination IP/host, and port.
It returns a category and confidence. Categories are `expected`, `development`,
`telemetry`, `suspicious`, and `unknown`. Arguments, environment, working directory,
raw alerts, and daemon configuration are discarded at the protocol boundary.
The remaining metadata still reveals application and network activity to an
enabled hosted provider.

The first second-model adapter uses Ollama's `/api/chat`. Configure an already
installed local model and enable `[ollama]` for explanations of requests that
need review. Snitchgate does not download a model. LLM explanations have no
authority over actions, operators, or permissions. Models receive connection
fields as untrusted data. Provider errors, invalid output, redirects, response
size limits, concurrency limits, and timeouts lead to manual review. Provider
error bodies are never saved or displayed.

For Qwen3.5:9b, keep `think = false` (the default). Snitchgate limits explanations
to 256 generated tokens and a 4096-token context; thinking can exhaust the output
budget before returning JSON. Truncated responses are rejected. The prompt asks
for observed facts and uncertainty and explicitly treats Jev's category/confidence
as model opinions, rather than evidence about rule matches or binary identity.

Run `snitchgate benchmark --help` for the reproducible local benchmark. See
[benchmarks/README.md](benchmarks/README.md) for the synthetic dataset, load and
burst measurements, and limitations. It does not send live firewall data to a
model or change decisions.

Both provider sections accept an optional absolute `unix_socket` path for a
local HTTP proxy. The endpoint still sets the HTTP request URL; HTTPS continues
to use TLS over that socket. Binary integration tests use private Unix-socket
HTTP fixtures so they need no host firewall exceptions.

Classification alone is observation mode. There are no automation scopes by
default. An explicit `[[automation]]` entry must match **all** of exact executable
path, UID, destination IP, port, protocol, category, and confidence threshold.
Automatic decisions always use `once`. Conflicting scopes and `unknown`
classifications require review. Thresholds must be evaluated against labeled
traffic; the example threshold is illustrative, not an established safety level.

Classifier endpoints need narrowly scoped, reviewed network access before live
handover, so the broker does not wait on its own API requests. If that access
fails, requests remain available for manual decisions and eventually deny once.

## Durable rule proposals

After an explicit human decision, export the captured scope into a staging
directory with a useful description:

```sh
mkdir -p proposals
./target/debug/snitchgate propose REQUEST_ID \
  --description 'Owner: Noel. Local development HTTP fixture.' \
  --output-dir proposals
```

The generated filename matches the rule name. It includes exact process, UID,
protocol, destination IP, and port constraints. Unattributed requests cannot
become durable proposals or five-minute approvals. Existing files are never
overwritten. Review the IP carefully: dynamic addresses and shared hosting often
call for a different durable policy than an individual captured connection.

For Noelarchy, review and promote appropriate proposals into its curated rules,
run `make opensnitch-validate`, and use its documented deployment workflow.
Snitchgate never writes `/etc`, invokes sudo, edits curated policy, restarts
OpenSnitch, or deploys proposals. Live rules remain the daemon's responsibility.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The vendored protocol is the complete upstream OpenSnitch v1.7.2 `ui.proto`,
compiled with Tonic/Prost. Tests use local Unix sockets and mock providers; no
credentials, root access, or live firewall are required. See [PLAN.md](PLAN.md)
for architecture, remaining work, and live handover criteria, and
[THIRD_PARTY.md](THIRD_PARTY.md) for protocol provenance and licensing.
