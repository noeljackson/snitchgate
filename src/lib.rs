pub mod approvals;
pub mod benchmark;
pub mod broker;
pub mod config;
pub mod credentials;
pub mod ipc;
pub mod model;
pub mod observe;
pub mod policy;
pub mod providers;
pub mod server;
pub mod service;
pub mod slack;
pub mod store;
pub mod tui;

pub mod protocol {
    tonic::include_proto!("protocol");
}
