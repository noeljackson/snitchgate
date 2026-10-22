# Third-party material

`proto/ui.proto` is vendored unchanged from
[OpenSnitch v1.7.2](https://github.com/evilsocket/opensnitch/blob/v1.7.2/proto/ui.proto).
OpenSnitch is distributed under the GNU General Public License, version 3.
Its license is retained in [proto/OPENSNITCH-LICENSE](proto/OPENSNITCH-LICENSE).

Protocol bindings are generated during the Cargo build; generated output is
not checked in. Cargo.lock records Rust dependency versions; each dependency
retains its own upstream license. This repository is not configured for Cargo
publication.
