# Snitchgate

A terminal control room for OpenSnitch, built in Rust with Ratatui. A background
broker handles pending requests while the TUI provides inspection and temporary
allow/deny decisions. Optional Jev classification and Ollama explanations help
triage requests; deterministic policy controls automation.

This is an initial implementation with gRPC/provider integration tests and
real-daemon enforcement tests in isolated network/mount namespaces. The default
service uses private sockets. An attended host trial is a separate explicit
action; starting the service does not change firewall configuration.

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

`serve --manual` explicitly disables configured automation while retaining
classification. `--abstract-name snitchgate-1000` additionally exposes a local
Linux abstract Unix endpoint, restricted by kernel peer UID to root and this
user. For the installed OpenSnitch 1.7.2 daemon, use `unix:@snitchgate-1000` as
its UI address. Its older grpc-go client sends an invalid HTTP/2 authority with
filesystem Unix paths; an abstract name avoids that compatibility problem.
The private filesystem control socket stays the TUI/approval interface.

On Noelarchy, `/home/noel/noelarchy/docs/snitchgate-live.md` documents the
attended manual trial and `make opensnitch-snitchgate-trial`. It changes the UI
destination through a temporary runtime config mount, preserving the on-disk
config and daemon memory, and restores the existing GUI on expiry, interruption,
or broker failure. Prepare the manual broker and a single `approvals --live`
worker first; the preflight requires a live channel registration. Existing rules
still handle covered traffic. Classification and explanations accompany new
prompts; automatic decisions stay disabled.

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
raw alerts, and daemon configuration are discarded at the protocol boundary,
apart from bounded, sanitized URL hints reserved for human inspection below.
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

Classification alone leaves decisions manual. `serve` still answers requests and
denies unanswered requests once at their deadline; use `observe` below for a
passive live dry run. There are no automation scopes by default. An explicit
`[[automation]]` entry must match **all** of exact executable
path, UID, destination IP, port, protocol, category, and confidence threshold.
Automatic decisions always use `once`. Conflicting scopes and `unknown`
classifications require review. Thresholds must be evaluated against labeled
traffic; the example threshold is illustrative, not an established safety level.

Classifier endpoints need narrowly scoped, reviewed network access before live
handover, so the broker does not wait on its own API requests. If that access
fails, requests remain available for manual decisions and eventually deny once.

## Dry run with live traffic

Enable Jev and optionally a local Ollama model in your private config:

```toml
[jev]
enabled = true
[ollama]
enabled = true
model = "qwen3.5:9b"
think = false
```

Supply `TYPESAFE_API_KEY` through your credential environment, then run:

```sh
./target/debug/snitchgate observe --config config.local.toml \
  --seconds 60 --max-classifications 10 --recent 20
```

The observer reads connection events from the existing OpenSnitch GUI's SQLite
database in **read-only mode**. It discovers the active `ui*.sqlite3` file by its
latest event, including rotated databases; `--db PATH` selects one explicitly.
By default it follows new rows only; `--recent 20` also samples twenty recent
rows. This samples events already handled by OpenSnitch, rather than intercepting
pending requests. The GUI stays in control, and the observer opens no daemon or
control sockets. Configured automation scopes are never applied here.

Only process path, PID, UID, protocol, and destination IP/host/port reach providers.
Arguments and working directories are excluded in the SQL query. IPv6 protocol
labels are normalized; malformed or unsupported rows are skipped. Exact scopes
are deduplicated within the run (ignoring PID), own Snitchgate/Ollama connections
are skipped, calls run sequentially, and the invocation has a hard total
classification budget. This is a bounded sample, not a complete traffic audit.

Results go to the private 0600 `observations.sqlite3` in the Snitchgate state
directory. `--state-dir PATH` overrides that directory for both commands below.
The local database retains up to 10,000 samples, including the original observed
allow/deny action and source row reference. Console output contains counts only.
Hosted Jev still receives the whitelisted network metadata when enabled.

## Slack approvals, with room for other adapters

Create a Slack app using [slack-app-manifest.json](slack-app-manifest.json), install
it in your workspace, and generate an app-level token with `connections:write`.
Provide the bot token as `SLACK_BOT_TOKEN` (`xoxb-...`) and the app token as
`SLACK_APP_TOKEN` (`xapp-...`) through your credential manager. Each credential
also accepts a `_FILE` reference, such as `SLACK_BOT_TOKEN_FILE=/path/to/credential`;
Jev supports `TYPESAFE_API_KEY_FILE` too (using its configured key variable name).
Explicit file references take precedence and fail closed if unreadable. Files
must be regular, owned by this user, private, and at most 64 KiB. Linux sealed
memfd references work. Root-owned systemd credential files are also accepted
only directly inside the advertised root-controlled credential directory,
without write/other-user access; systemd may use named-user read ACLs.
Tokens never go in config files or CLI arguments. Slack CLI login is separate
from these credentials. The application has no OpenBao dependency or scripts.

On Noelarchy, the external launcher owns retrieval and delivers only the two
Slack fields from `personal/snitchgate`, without globally exporting them:

```sh
bao-app run snitchgate-slack -- ./target/debug/snitchgate approvals --config config.local.toml
```

The separate `bao-app run snitchgate -- ...` profile keeps only the existing Jev
key from the calling environment and performs no OpenBao lookup. These launchers
live in Noelarchy; other installations can supply credentials through their own
process supervisor or secret manager.

Configure your trusted Slack user IDs (the default is an empty allowlist):

```toml
[approvals]
review_below_confidence = 0.9
review_ttl_seconds = 900
[approvals.slack]
approvers = ["YOUR_SLACK_USER_ID"]
```

The threshold is illustrative and uncalibrated. Unknown, suspicious, failed,
and below-threshold classifications need review. High model confidence does
not authorize traffic: live requests remaining after the broker's exact scope
checks also need a human decision, regardless of confidence.

Start the bot alongside the observer, using the same state directory:

```sh
./target/debug/snitchgate approvals --config config.local.toml
```

Invite the app to whichever channel you want and, as a configured approver, send:

```text
@Snitchgate approvals here
```

That channel becomes the saved destination for this workspace and mode. Another
authorized registration can move it. Each card shows the captured scope,
classification, explanation, deadline, and explicit **DRY RUN** label. Click
**Yes**/**No**, or reply exactly `yes` or `no` in that card's thread. In dry-run
mode these record **would allow / would deny** feedback only; they cannot change
the firewall or approve future requests. Feedback expires after the configured
TTL and records the approver identity locally.

The adapter uses Slack [Socket Mode](https://docs.slack.dev/apis/events-api/using-socket-mode/),
so it needs outbound HTTPS/WebSocket access and no public inbound endpoint.
The manifest requests posting, mentions, and message events in joined public and
private channels so plain threaded replies work; messages unrelated to a tracked
request are ignored. Metadata is rendered as plain text, without unfurling links.

Live Slack cards and TUI inspection also show URL/path hints when an HTTP(S)
URL is a standalone process argument and its hostname (or literal IP) and port
match the captured destination. A raw Gist URL can therefore show the Gist ID,
revision, and filename. User info, query strings, and fragments are removed;
only three distinct URLs of at most 768 bytes are retained. Paths can still
contain sensitive identifiers: these hints are stored locally with the review
and sent to the registered Slack channel, but **never to Jev or Ollama**.
Other arguments and environment values are discarded. The dry-run observer
continues to exclude arguments entirely and has no URL hints.

Hints are unverified process claims, not observed HTTP requests. OpenSnitch has
no HTTP URL field; HTTPS encrypts the path. Requests made inside a browser or
application, embedded script URLs, redirects, and filenames absent from the
captured URL may therefore be unavailable. Cards state when the URL/file is
unavailable. Snitchgate never fetches a URL to discover a filename or inspect
contents, and approval still covers the **connection**, not a particular file.

`approvals --live` explicitly selects actual pending requests on the broker's
private control socket; `--socket PATH` can choose an isolated broker. Yes allows
**once**, No denies **once**, and the broker checks its original deadline again.
It records the Slack approver with the human decision. This flag does not attach
the broker to the live daemon; the handover criteria in PLAN.md still apply.
Live and dry-run channel registrations use separate state databases.

Reply acceptance checks workspace, configured user, original channel/thread,
request ID, expiry, and the button's opaque nonce. Duplicate replies, edited or
bot messages, and free-floating yes/no messages cannot decide anything. Socket
events are acknowledged independently of processing; a full event queue drops
work safely, and the user can retry. Reconnects preserve request deadlines.
Delivery reservations survive bot restarts. An ambiguous posting failure is
recorded locally and is not automatically reposted; delivery and update failures
never grant traffic. New cards are limited to one per second and ten per minute,
so high volume can expire before delivery. Existing TUI review remains available.

`ApprovalSource`, `ApprovalAdapter`, `Review`, and `Reply` separate transport from
decisions. A future Telegram adapter can use the same inbox, deadline, and
one-shot decision flow. Telegram transport itself is not implemented yet.

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

## Supervised workstation services

The broker sends systemd `READY=1` when serving; Slack does so after
authentication, a saved channel route for that workspace, and a Socket Mode
connection. Its status becomes `Slack reconnecting` on disconnect. A supervised
worker requires an existing route; manual launches still support initial
registration. Notification messages contain no requests or credentials.

Noelarchy owns opt-in boot units, installed release binary/configuration,
state migration, and handover guard. Its enabled `snitchgate.target` starts
at boot. Broker and Slack run as the owner UID with separate
`LoadCredentialEncrypted=` files and `_FILE` references. The root guard restores
GUI routing while the broker or Slack connection is down and resumes after
recovery. App code does not install or enable units. See
`/home/noel/noelarchy/docs/snitchgate-live.md` for setup, status, rotation, and
disable commands. Jev/Slack source secrets remain outside this repository.

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

`python scripts/kernel-smoke.py` is an opt-in Arch/Noelarchy enforcement and
handover check requiring sudo, the installed OpenSnitch daemon, nftables, iproute2,
curl, and Noelarchy's trial helper. It creates fresh network/mount namespaces,
uses only loopback fixtures and isolated rules/config, verifies allow/deny/timeout
and hot rollback, and never connects to the host daemon's socket or changes its
network/config. Private evidence is kept under the user runtime directory.
