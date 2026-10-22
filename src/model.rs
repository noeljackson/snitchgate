use crate::protocol;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Control and formatting characters are never passed through to a terminal.
pub fn display_text(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(4096)
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub process: String,
    pub pid: u32,
    pub uid: u32,
    pub protocol: String,
    pub ip: IpAddr,
    pub host: String,
    pub port: u16,
}

impl TryFrom<protocol::Connection> for Connection {
    type Error = anyhow::Error;
    fn try_from(raw: protocol::Connection) -> Result<Self> {
        ensure!(
            raw.process_path.len() <= 4096 && raw.dst_host.len() <= 253,
            "oversized connection metadata"
        );
        ensure!(
            raw.process_path.chars().all(|c| !c.is_control()),
            "invalid process path"
        );
        ensure!(
            raw.dst_host.is_ascii()
                && raw
                    .dst_host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')),
            "invalid hostname"
        );
        let protocol = raw.protocol.to_ascii_lowercase();
        ensure!(
            matches!(protocol.as_str(), "tcp" | "udp"),
            "unsupported protocol"
        );
        Ok(Self {
            process: raw.process_path,
            pid: raw.process_id,
            uid: raw.user_id,
            protocol,
            ip: raw.dst_ip.parse()?,
            host: raw.dst_host,
            port: u16::try_from(raw.dst_port)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}
impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Duration {
    Once,
    FiveMinutes,
}
impl Duration {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::FiveMinutes => "5m",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub action: Action,
    pub duration: Duration,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Expected,
    Development,
    Telemetry,
    Suspicious,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub category: Category,
    pub confidence: f64,
    pub model: String,
    pub explanation: String,
    pub llm_model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub connection: Connection,
    pub received: u64,
    pub deadline: u64,
    pub assessment: Option<Assessment>,
    pub classifier_status: String,
    pub verdict: Option<Verdict>,
    pub finished: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Health {
    pub daemon: Option<String>,
    pub last_ping: Option<u64>,
    pub rule_count: usize,
    pub alerts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub pending: Vec<Entry>,
    pub history: Vec<Entry>,
    pub health: Health,
    pub mode: String,
    pub classifier_enabled: bool,
    pub automation_scopes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drops_secrets_at_protocol_boundary() {
        let raw = protocol::Connection {
            dst_ip: "127.0.0.1".into(),
            protocol: "tcp".into(),
            process_args: vec!["secret-token".into()],
            process_env: [("SECRET".into(), "password".into())].into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&Connection::try_from(raw).unwrap()).unwrap();
        assert!(!json.contains("secret") && !json.contains("password"));
    }
    #[test]
    fn rejects_malformed_destination() {
        assert!(
            Connection::try_from(protocol::Connection {
                dst_ip: "bad".into(),
                protocol: "tcp".into(),
                ..Default::default()
            })
            .is_err()
        );
    }
    #[test]
    fn sanitizes_terminal_control_characters() {
        assert_eq!(display_text("hi\x1b[31m\n\u{202e}end"), "hi[31mend");
    }
}
