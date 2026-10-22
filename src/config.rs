use crate::model::{Action, Category};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub request_timeout_seconds: u64,
    pub max_pending: usize,
    pub classifier_concurrency: usize,
    pub history_limit: usize,
    pub jev: JevConfig,
    pub ollama: OllamaConfig,
    pub automation: Vec<Scope>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            request_timeout_seconds: 90,
            max_pending: 256,
            classifier_concurrency: 4,
            history_limit: 10_000,
            jev: JevConfig::default(),
            ollama: OllamaConfig::default(),
            automation: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JevConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub model: String,
    pub api_key_env: String,
    pub timeout_seconds: u64,
    pub unix_socket: Option<PathBuf>,
}
impl Default for JevConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "https://api.typesafe.ai/v1/systemone".into(),
            model: "jev-1.13.0".into(),
            api_key_env: "TYPESAFE_API_KEY".into(),
            timeout_seconds: 10,
            unix_socket: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OllamaConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub model: String,
    pub timeout_seconds: u64,
    pub explain_below_confidence: f64,
    pub unix_socket: Option<PathBuf>,
    pub think: bool,
}
impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://127.0.0.1:11434/api/chat".into(),
            model: String::new(),
            timeout_seconds: 15,
            explain_below_confidence: 0.9,
            unix_socket: None,
            think: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub process: String,
    pub uid: u32,
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub category: Category,
    pub action: Action,
    pub min_confidence: f64,
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let config = match path {
            Some(path) => toml::from_str(&std::fs::read_to_string(path).context("read config")?)
                .context("parse config")?,
            None => Self::default(),
        };
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=100).contains(&self.request_timeout_seconds),
            "request timeout must be 1..100 seconds (daemon deadline is 120s)"
        );
        ensure!(
            (1..=512).contains(&self.max_pending),
            "max_pending must be 1..512"
        );
        ensure!(
            (1..=32).contains(&self.classifier_concurrency),
            "classifier_concurrency must be 1..32"
        );
        ensure!(
            (100..=100_000).contains(&self.history_limit),
            "history_limit must be 100..100000"
        );
        ensure!(
            self.automation.is_empty() || self.jev.enabled,
            "automation requires Jev"
        );
        ensure!(
            !self.ollama.enabled || self.jev.enabled,
            "Ollama requires Jev classification"
        );
        ensure!(
            (0.0..=1.0).contains(&self.ollama.explain_below_confidence),
            "invalid explanation threshold"
        );
        for (enabled, endpoint, model, timeout) in [
            (
                self.jev.enabled,
                &self.jev.endpoint,
                &self.jev.model,
                self.jev.timeout_seconds,
            ),
            (
                self.ollama.enabled,
                &self.ollama.endpoint,
                &self.ollama.model,
                self.ollama.timeout_seconds,
            ),
        ] {
            if enabled {
                validate_endpoint(endpoint)?;
                ensure!(!model.is_empty(), "enabled providers need a model");
                ensure!(
                    (1..=30).contains(&timeout),
                    "provider timeout must be 1..30 seconds"
                );
            }
        }
        for socket in [
            self.jev.unix_socket.as_ref(),
            self.ollama.unix_socket.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            ensure!(
                socket.is_absolute(),
                "provider Unix socket paths must be absolute"
            );
        }
        for scope in &self.automation {
            ensure!(
                scope.process.starts_with('/')
                    && !scope.process.contains('*')
                    && scope.process.chars().all(|c| !c.is_control()),
                "automation needs an exact absolute process path"
            );
            ensure!(
                matches!(scope.protocol.as_str(), "tcp" | "udp"),
                "automation protocol must be tcp or udp"
            );
            ensure!(
                scope.port > 0 && !scope.ip.is_unspecified(),
                "automation needs an exact destination"
            );
            ensure!(
                (0.0..=1.0).contains(&scope.min_confidence),
                "invalid confidence threshold"
            );
            ensure!(
                scope.category != Category::Unknown,
                "unknown requests require review"
            );
        }
        Ok(())
    }
}

pub fn validate_endpoint(endpoint: &str) -> Result<()> {
    let url = reqwest::Url::parse(endpoint).context("invalid provider URL")?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "provider URL cannot contain credentials, query, or fragment"
    );
    let local = url
        .host_str()
        .map(|host| {
            host.trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        })
        .unwrap_or(false);
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && local),
        "provider URL requires HTTPS or literal loopback HTTP"
    );
    Ok(())
}

pub fn runtime_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("XDG_RUNTIME_DIR")
            .context("XDG_RUNTIME_DIR is required; use --runtime-dir otherwise")?,
    )
    .join("snitchgate"))
}

pub fn state_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is required")?)
            .join(".local/state"),
    };
    Ok(base.join("snitchgate"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_transport_and_strict_config() {
        assert!(validate_endpoint("http://example.com/api").is_err());
        assert!(validate_endpoint("https://user:secret@example.com/api").is_err());
        assert!(validate_endpoint("http://127.0.0.1:11434/api/chat").is_ok());
        assert!(toml::from_str::<Config>("automaton = true").is_err());
        Config::default().validate().unwrap();
    }
}
