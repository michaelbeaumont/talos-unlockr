use core::net;
use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

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

#[derive(Clone, Debug)]
pub struct ClusterNodes(HashMap<String, HashSet<(net::IpAddr, Uuid)>>);

impl Deref for ClusterNodes {
    type Target = HashMap<String, HashSet<(net::IpAddr, Uuid)>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<HashMap<String, HashSet<(net::IpAddr, Uuid)>>> for ClusterNodes {
    fn from(value: HashMap<String, HashSet<(net::IpAddr, Uuid)>>) -> Self {
        Self(value)
    }
}

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
