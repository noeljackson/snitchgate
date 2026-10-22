# Snitchgate implementation plan

## Architecture

```text
OpenSnitch daemon -- gRPC / Unix socket --> broker -- SQLite decision history
                                            |
                                      bounded Jev calls
                                            |
                              exact scope / category / confidence gate
                                     |                  |
                               decide once         manual review
                                                        |
                                              Ollama explanation
                                                        |
                           Ratatui / approval adapters <-- private control socket
                                                        |
                                            staged JSON proposal
```

The broker and TUI have separate lifetimes. The broker owns pending requests,
deadlines, classifier budgets, and decisions. The control socket is authenticated
with Unix peer credentials and private filesystem permissions. The OpenSnitch
socket lives in the same private runtime directory and must remain local.

Rules come from captured request metadata and deterministic code. Jev supplies
category/confidence; the LLM supplies optional prose. Neither can write files,
change scope, execute tools, or authorize actions outside configured scopes.
Captured hostname and executable path do not prove identity or intent.

## Delivered in the initial build

- Rust CLI and Ratatui Inbox, History, and Health views, plus an offline demo.
- OpenSnitch 1.7.2 gRPC interface: Ping, Subscribe, AskRule, Notifications,
  PostAlert; no management notifications are emitted.
- Temporary decisions with process/user/protocol/IP/port constraints.
- Bounded queue, independent deadlines, deny-once fallback, duplicate-decision
  rejection, and SQLite history with configured row retention.
- Jev HTTP adapter and strict category/confidence parsing; Ollama explanation
  adapter, each optional and bounded by timeout/concurrency/body size.
- Opt-in exact automation scopes, automatically deciding once only.
- Explicit human-decision export into a staged durable JSON rule proposal.
- Protocol, policy, persistence, IPC, provider, and TUI rendering tests.
- Bounded read-only live GUI database observer, redacted metadata ingestion,
  private dry-run classifications, and durable human feedback.
- Transport-independent approval source/adapter contracts and a Slack Socket Mode
  adapter with channel registration, trusted approvers, Yes/No buttons and exact
  threaded replies, expiry, duplicate rejection, and persistent delivery state.
- Bounded destination-matching command-line URL hints in live Slack cards and
  TUI inspection, with user info/query/fragment removal and explicit missing-data
  labels. Hints stay outside both model inputs and all permission scopes.

The observer reads already-decided GUI events and never connects to the daemon.
Its approvals record feedback only. Explicit `approvals --live` reviews actual
pending broker requests once; it does not perform daemon handover. Neither
confidence nor a chat response creates permanent policy. Telegram is a future
transport adapter. Slack needs separate bot/app credentials and an authorized
channel registration before it can post.

An isolated real OpenSnitch 1.7.2 daemon now verifies packet enforcement for
allow/deny/timeout, non-persistence, hot UI handover, and config rollback without
a restart. Its grpc-go 1.32 client requires the slash-free `unix:@NAME` endpoint;
the optional abstract listener enforces root/owner peer credentials. `--manual`
clears automation explicitly. Noelarchy provides a bounded attended host trial;
the full eBPF host traffic mix and operational longevity remain to be verified.

## Next milestones

1. **Replay and evaluation.** Import redacted OpenSnitch event samples into a
   labeled dataset, replay classification, and report false allows, unnecessary
   denies, review coverage, latency, and cost. Split by executable and destination
   to avoid evaluating near duplicates as independent evidence. Pin model/prompt
   versions before calibrating thresholds. Current category/confidence output is
   a recommendation; there is no measured accuracy claim.
2. **Investigation context.** Add bounded local package ownership and ancestry
   lookup, with PID/start-time checks to avoid reuse races. Add DNS evidence with
   clear attribution limits. Treat executable upgrades as cache-invalidating
   events. No automatic URL browsing or command execution by models.
3. **Request grouping.** Group identical captured scopes while preserving each
   original deadline and response. Bulk actions must show explicit membership;
   late arrivals cannot silently join a previously approved group. Add a bounded
   cache keyed by policy version, binary identity, and exact connection scope.
4. **Rules and drift.** Read-only curated/live rule inventory, precedence/conflict
   inspection, proposal comparison, and checksums. Add a Rules TUI view and
   reviewed promotion through the existing policy repository. No silent root
   writes, rule pruning, or daemon restarts.
5. **Operational hardening and handover.** Supervised user service, recovery of
   interrupted audit state, retention by time as well as rows, explicit provider
   budgets, and a verified live cutover/rollback procedure.

## Live handover criteria

The installed firewall has not been reconfigured by this build. Before using it
as the active UI server:

- Verify the exact installed protocol and daemon settings against 1.7.2,
  including subscription, notification lifetime, duration handling, attribution
  failures, daemon reconnects, and client RPC cancellation.
- Verify daemon behavior against a second isolated daemon/network namespace,
  including a malicious or malformed request. Mock wire tests alone do not prove
  kernel enforcement behavior.
- Prepare narrow provider egress independently of the decision path.
- Back up current UI/daemon settings and preserve curated rules. Determine
  whether handover requires restart and what happens to in-memory approvals.
- Explicitly switch the daemon's configured UI socket during an attended test;
  keep a rollback to the existing GUI ready. Verify DNS, browser, VPN, SSH,
  agent APIs, temporary decisions, and absence of permanent timeout rules.
- Keep automation scopes empty during observation. Add only evaluated scopes
  with a documented purpose and bounded consequences.

## Limits of this version

- No live handover, installation, systemd enablement, package installation, or
  network policy change is performed automatically.
- A full queue returns a deny-once rule directly, outside detailed audit history.
  Live adoption needs an explicit overload counter and operational alert.
- History is a bounded local audit log, not a tamper-proof security ledger.
  A transport disconnect can mean a recorded decision was not received by the
  daemon. History describes broker decisions, not confirmed kernel enforcement.
- Pending requests are in memory and are lost after a crash; daemon reconnect
  and fallback behavior must be verified before live adoption.
- The TUI shows requests reaching this broker, not all network connections.
  Ping statistics are not imported as a complete network activity database.
- Automation scope matching uses captured process path and IP, not a verified
  executable identity. Do not use it to treat an arbitrary file at a trusted path
  as the trusted binary. Executable identity checks are a later milestone.
- Model outputs are not sufficient evidence of safety. Exact scope permission
  and evaluated thresholds remain the owner's responsibility.

## Upstream references

- [OpenSnitch 1.7.2 protocol](https://github.com/evilsocket/opensnitch/blob/v1.7.2/proto/ui.proto)
- [OpenSnitch daemon UI client](https://github.com/evilsocket/opensnitch/blob/v1.7.2/daemon/ui/client.go)
- [TypeSafe System One API](https://docs.typesafe.ai/api/system-one)
- [Ollama chat API](https://docs.ollama.com/api/chat)
- [Ratatui](https://ratatui.rs/)
