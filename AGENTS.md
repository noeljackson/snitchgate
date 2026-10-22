# Snitchgate agent instructions

Snitchgate is a Rust/Ratatui OpenSnitch request broker. Read README.md and PLAN.md
before changing its decision or deployment behavior.

- Start with `git status --short`; preserve unrelated edits.
- Use `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo test --all-targets` before delivery.
- Tests and demos must use isolated sockets, fixtures, and mock providers.
  Never attach to the machine's live OpenSnitch socket as a test.
- Never reconfigure the firewall, change `/etc`, enable a service, deploy a rule,
  restart a daemon, or install a package without explicit task authorization.
- Model output cannot execute commands, form rule operators, broaden scope, or
  create permanent policy. Automation requires exact configured constraints.
- Failures and timeouts must never write permanent denies or silently allow.
- Do not log raw arguments, environment variables, credentials, provider error
  bodies, or incoming daemon configs. Pass secrets through environment sources,
  never CLI arguments or committed files.
- Preserve the vendored protocol's provenance and license. Do not hand-edit
  protocol definitions without updating the version and compatibility tests.
