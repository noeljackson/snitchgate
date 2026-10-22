# Local explanation benchmark

The `snitchgate benchmark` command exercises the same request builder and JSON
parser as the production Ollama adapter. It sends synthetic firewall metadata
directly to a literal loopback Ollama endpoint. It never reads live firewall
events, changes network policy, invokes Jev, or settles a request.

`cases.json` contains sixteen fixed cases: ordinary browser/DNS/SSH traffic,
interpreters, IPv4/IPv6 loopback, private LAN, missing attribution, temporary and
misleading executable paths, low confidence, conflicting labels, and instruction
injection through process and hostname fields. Each case has a human review
rubric. Categories/confidence are fixtures, not verified Jev predictions.

## Reproduce

Install Ollama with the appropriate GPU backend, then run a loopback-only server:

```sh
OLLAMA_HOST=127.0.0.1:11434 \
OLLAMA_MODELS="$HOME/.local/share/ollama/models" \
OLLAMA_NO_CLOUD=1 \
OLLAMA_NUM_PARALLEL=2 \
OLLAMA_CONTEXT_LENGTH=4096 \
OLLAMA_KEEP_ALIVE=10m \
ollama serve
```

In another terminal:

```sh
ollama pull qwen3.5:9b
cargo build
mkdir -p benchmarks/results

# Baseline: leave the model's thinking behavior unspecified.
./target/debug/snitchgate benchmark --thinking auto --repeats 1 \
  --concurrency 1 --output benchmarks/results/baseline.json

# Short explanations with thinking explicitly disabled.
./target/debug/snitchgate benchmark --thinking off --repeats 2 \
  --concurrency 1 --output benchmarks/results/serial.json

# Burst behavior with the broker's default four concurrent classifier slots.
./target/debug/snitchgate benchmark --thinking off --repeats 2 \
  --concurrency 4 --output benchmarks/results/burst.json
```

Every run first unloads the selected model and measures one load-inclusive
request, then records the warm samples. This does not flush Linux's file cache;
the first request is not a cold-storage measurement. Run phases sequentially.
Do not overlap them with other inference work if you want an idle-GPU estimate.

The command pins context to 4096 and the default generated-token limit to 256.
`--max-tokens` and `--timeout-seconds` can override benchmark limits. The default
benchmark timeout is 30 seconds so responses over production's 15-second timeout
can still be observed. Reports count only complete, schema-valid responses within
15 seconds as usable under the production deadline.

Reports include model digest/quantization and loaded VRAM from Ollama, request
latencies, load durations, token counts/rates, completion reason, schema validity,
fixture inputs, system prompt and prompt revision, and generated explanations.
Thinking text is not retained; only its character count is recorded. Files are
created with mode 0600 and never overwritten.

## Interpretation

The summary uses nearest-rank p50/p95 over all warm requests, including failures.
`valid_json` means the explanation passes the production parser. `complete`
additionally requires Ollama's `done=true` and `done_reason=stop`. Throughput is
warm requests divided by the wall time of the warm phase.

This measures explanation reliability and latency on a small synthetic dataset.
Human review is required for unsupported assertions, handling of uncertainty,
and resistance to instructions embedded in metadata. It is not a classification
accuracy benchmark, an adversarial safety guarantee, or evidence for increasing
automation permissions. Repeated deterministic prompts and prompt caching make
the warm measurements optimistic for novel requests.

The initial measurements used `explanation-v1-classification-rationale`, which
invited the model to justify a supplied category. Manual review found invented
rule/inventory checks and destination trust. `explanation-v2-observed-facts`
explicitly separates supplied opinions from facts and forbids these claims.
The same small dataset was used to diagnose and evaluate this prompt change;
results are not held-out validation. Older v1 artifacts retain the exact prompt.
The final v3 payload names `destination_ip`, `destination_hostname`, and
`destination_port` explicitly, after v2 review found prose that sometimes
described these destination fields as the source. It also asks the model to
call out missing process attribution. All revisions are retained for comparison.
