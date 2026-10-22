use crate::{
    broker::demo_connection,
    config::{OllamaConfig, validate_endpoint},
    model::{Assessment, Category, Connection},
    providers,
};
use anyhow::{Context, Result, ensure};
use clap::{Args as ClapArgs, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::Write,
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Thinking {
    Auto,
    Off,
    On,
}

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[arg(long, default_value = "qwen3.5:9b")]
    pub model: String,
    #[arg(long, default_value = "http://127.0.0.1:11434/api/chat")]
    pub endpoint: String,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long, default_value_t = 2)]
    pub repeats: usize,
    #[arg(long, default_value_t = 1)]
    pub concurrency: usize,
    #[arg(long, value_enum, default_value = "off")]
    pub thinking: Thinking,
    #[arg(long, default_value_t = 256)]
    pub max_tokens: u32,
    #[arg(long, default_value_t = 30)]
    pub timeout_seconds: u64,
}

#[derive(Clone, Deserialize, Serialize)]
struct Case {
    id: String,
    process: String,
    host: String,
    ip: String,
    port: u16,
    category: Category,
    confidence: f64,
    review: String,
    #[serde(default = "default_uid")]
    uid: u32,
}
fn default_uid() -> u32 {
    1000
}
impl Case {
    fn connection(&self) -> Connection {
        let mut connection = demo_connection(&self.process, &self.host, &self.ip, self.port);
        connection.uid = self.uid;
        connection
    }
    fn assessment(&self) -> Assessment {
        Assessment {
            category: self.category,
            confidence: self.confidence,
            model: "fixture-not-a-live-jev-judgment".into(),
            explanation: String::new(),
            llm_model: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct Sample {
    case: String,
    repeat: usize,
    latency_seconds: f64,
    json_valid: bool,
    complete: bool,
    done_reason: Option<String>,
    error: Option<String>,
    explanation: Option<String>,
    load_seconds: f64,
    prompt_tokens: u64,
    generated_tokens: u64,
    thinking_characters: usize,
    generation_tokens_per_second: Option<f64>,
}

#[derive(Debug, Serialize)]
struct Summary {
    samples: usize,
    valid_json: usize,
    complete: usize,
    within_production_15s: usize,
    p50_seconds: f64,
    p95_seconds: f64,
    max_seconds: f64,
    wall_seconds: f64,
    requests_per_second: f64,
}

fn summary(samples: &[Sample], wall: f64) -> Summary {
    let mut times: Vec<f64> = samples.iter().map(|s| s.latency_seconds).collect();
    times.sort_by(f64::total_cmp);
    let percentile =
        |p: f64| times[((times.len() as f64 * p).ceil() as usize).saturating_sub(1)].to_owned();
    Summary {
        samples: samples.len(),
        valid_json: samples.iter().filter(|s| s.json_valid).count(),
        complete: samples.iter().filter(|s| s.complete).count(),
        within_production_15s: samples
            .iter()
            .filter(|s| s.complete && s.json_valid && s.latency_seconds <= 15.0)
            .count(),
        p50_seconds: percentile(0.5),
        p95_seconds: percentile(0.95),
        max_seconds: times.last().copied().unwrap_or_default(),
        wall_seconds: wall,
        requests_per_second: samples.len() as f64 / wall,
    }
}

async fn sample(
    client: reqwest::Client,
    config: OllamaConfig,
    case: Case,
    repeat: usize,
    thinking: Thinking,
    max_tokens: u32,
) -> Sample {
    let mut body = providers::ollama_body(&config, &case.connection(), &case.assessment());
    match thinking {
        Thinking::Auto => {
            body.as_object_mut().unwrap().remove("think");
        }
        Thinking::Off => body["think"] = json!(false),
        Thinking::On => body["think"] = json!(true),
    }
    body["options"]["num_predict"] = json!(max_tokens);
    body["options"]["num_ctx"] = json!(4096);
    body["keep_alive"] = json!("10m");
    let start = Instant::now();
    let result = async {
        let response = client
            .post(&config.endpoint)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .json(&body)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("transport_or_timeout"))?;
        providers::response_json(response).await
    }
    .await;
    let latency_seconds = start.elapsed().as_secs_f64();
    let mut sample = Sample {
        case: case.id,
        repeat,
        latency_seconds,
        json_valid: false,
        complete: false,
        done_reason: None,
        error: None,
        explanation: None,
        load_seconds: 0.0,
        prompt_tokens: 0,
        generated_tokens: 0,
        thinking_characters: 0,
        generation_tokens_per_second: None,
    };
    match result {
        Err(_) => sample.error = Some("transport_timeout_or_invalid_provider_response".into()),
        Ok(body) => {
            sample.done_reason = body["done_reason"].as_str().map(str::to_owned);
            sample.complete = body["done"] == true && body["done_reason"] == "stop";
            sample.load_seconds = body["load_duration"].as_u64().unwrap_or_default() as f64 / 1e9;
            sample.prompt_tokens = body["prompt_eval_count"].as_u64().unwrap_or_default();
            sample.generated_tokens = body["eval_count"].as_u64().unwrap_or_default();
            sample.thinking_characters = body["message"]["thinking"]
                .as_str()
                .map_or(0, |s| s.chars().count());
            if let Some(duration) = body["eval_duration"].as_u64().filter(|d| *d > 0) {
                sample.generation_tokens_per_second =
                    Some(sample.generated_tokens as f64 * 1e9 / duration as f64);
            }
            match providers::parse_ollama(&body) {
                Ok((explanation, _)) => {
                    sample.json_valid = true;
                    sample.explanation = Some(explanation);
                }
                Err(_) => sample.error = Some("explanation_schema_failed".into()),
            }
        }
    }
    eprintln!(
        "{} r{}: {:.3}s / json={} / complete={} / {} tokens",
        sample.case,
        repeat,
        latency_seconds,
        sample.json_valid,
        sample.complete,
        sample.generated_tokens
    );
    sample
}

pub async fn run(args: Args) -> Result<()> {
    validate_endpoint(&args.endpoint)?;
    let mut base = reqwest::Url::parse(&args.endpoint)?;
    ensure!(
        base.host_str().is_some_and(|h| h
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())),
        "benchmark only supports literal loopback providers"
    );
    ensure!(
        (1..=8).contains(&args.concurrency) && (1..=10).contains(&args.repeats),
        "concurrency must be 1..8 and repeats 1..10"
    );
    ensure!(
        (64..=1024).contains(&args.max_tokens) && (1..=120).contains(&args.timeout_seconds),
        "invalid benchmark token or timeout limit"
    );
    ensure!(
        !args.output.exists(),
        "output already exists; choose a new path"
    );
    let cases: Vec<Case> = serde_json::from_str(include_str!("../benchmarks/cases.json"))?;
    ensure!(!cases.is_empty(), "empty benchmark dataset");
    let config = OllamaConfig {
        endpoint: args.endpoint.clone(),
        model: args.model.clone(),
        timeout_seconds: args.timeout_seconds,
        ..Default::default()
    };
    let client = providers::client()?;
    base.set_path("/api/version");
    let version = providers::response_json(
        client
            .get(base.clone())
            .timeout(Duration::from_secs(3))
            .send()
            .await?,
    )
    .await?;
    // An explicit unload makes first-request model loading measurable. It does
    // not flush the OS page cache, so this is not a cold-storage benchmark.
    base.set_path("/api/generate");
    providers::response_json(
        client
            .post(base.clone())
            .timeout(Duration::from_secs(10))
            .json(&json!({"model":args.model,"keep_alive":0}))
            .send()
            .await?,
    )
    .await?;
    let cold = sample(
        client.clone(),
        config.clone(),
        cases[0].clone(),
        0,
        args.thinking,
        args.max_tokens,
    )
    .await;
    let start = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    let mut samples = Vec::new();
    for repeat in 1..=args.repeats {
        for case in &cases {
            if tasks.len() >= args.concurrency {
                samples.push(
                    tasks
                        .join_next()
                        .await
                        .context("missing benchmark task")??,
                );
            }
            tasks.spawn(sample(
                client.clone(),
                config.clone(),
                case.clone(),
                repeat,
                args.thinking,
                args.max_tokens,
            ));
        }
    }
    while let Some(result) = tasks.join_next().await {
        samples.push(result?);
    }
    let wall = start.elapsed().as_secs_f64();
    let summary = summary(&samples, wall);
    base.set_path("/api/ps");
    let loaded = providers::response_json(
        client
            .get(base)
            .timeout(Duration::from_secs(3))
            .send()
            .await?,
    )
    .await?;
    let report = json!({"model":args.model,"endpoint":args.endpoint,"ollama_version":version["version"],
        "prompt_version":providers::OLLAMA_PROMPT_VERSION,"system_prompt":providers::OLLAMA_SYSTEM_PROMPT,
        "thinking":args.thinking,"max_tokens":args.max_tokens,"context_length":4096,"repeats":args.repeats,"concurrency":args.concurrency,
        "dataset":"synthetic-v1; fixed categories, no live Jev calls or firewall events", "cases":cases, "cold":cold,"summary":summary,
        "loaded_models":loaded["models"],"review_rubric":cases.iter().map(|c| json!({"case":c.id,"review":c.review})).collect::<Vec<_>>(),"samples":samples});
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.output)?;
    writeln!(file, "{}", serde_json::to_string_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report["summary"])?);
    println!("Report: {}", args.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixtures_are_redacted_and_cover_injection_and_missing_attribution() {
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../benchmarks/cases.json")).unwrap();
        assert!(cases.iter().any(|c| c.process.is_empty()));
        assert!(cases.iter().any(|c| c.id.contains("injection")));
        for case in cases {
            assert!(case.connection().port > 0);
            assert!(!case.review.is_empty());
        }
    }
}
