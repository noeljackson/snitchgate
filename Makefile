.PHONY: check demo build

check:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test --all-targets

demo:
	cargo run -- demo

build:
	cargo build --release
