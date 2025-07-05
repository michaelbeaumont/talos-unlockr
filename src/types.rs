use core::net;
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct Attempt {
    pub addr: net::IpAddr,
    pub node: Uuid,
    pub kind: AttemptKind,
    pub resp: AttemptResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttemptKind {
    Seal,
    Unseal,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AttemptResponse {
    Block,
    Allow,
}

pub type ClusterNodes = HashMap<String, HashSet<(net::IpAddr, Uuid)>>;

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Toggle {
    pub ip: net::IpAddr,
    pub uuid: Uuid,
    pub kind: ToggleKind,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ToggleKind {
    Allow,
    Block,
}
