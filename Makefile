.PHONY: check demo build benchmark

check:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test --all-targets

demo:
	cargo run -- demo

build:
	cargo build --release

# Requires a local Ollama server and a model already present on disk.
BENCHMARK_OUTPUT ?= benchmarks/results/local-$(shell date +%Y%m%d-%H%M%S).json
benchmark:
	cargo run -- benchmark --thinking off --output $(BENCHMARK_OUTPUT)
