use std::collections::HashMap;
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TempFile {
    pub file_id: String,
    pub file_name: String,
    pub block_ids: HashMap<String, usize>,
    pub block_vecs: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealerOutput {
    pub sector_size: u64,
    pub sealer_id: String,
    pub num: usize,
    pub sealed_cid: String,
    pub unsealed_cid: String,
    pub proof: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerMetadata {
    pub capacity: usize,
    pub stored_size: usize,
    pub willing: f32,
    pub file: HashMap<String, FileMeta>,
    pub data_blocks: HashMap<String, DataBlock>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileMeta {
    pub name: String,
    pub file_id: String,
    pub data_blocks: Vec<String>,
    pub parity_blocks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DataBlock {
    pub block_id: String,
    pub size: usize,
    pub recovery_nodes: Vec<String>,
    pub public: bool,
    pub file_id: String,
    pub local: bool,
    pub peers: Vec<String>,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ListMode {
    ALL,
    One(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockResponse {
    pub file_id: String,
    pub block_id: String,
    pub data: Vec<u8>,
    pub receiver: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoverRequest {
    pub uuid: String,
    pub block_id: String,
    pub receiver: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoverResponse {
    pub uuid: String,
    pub block_id: String,
    pub data: Vec<u8>,
    pub receiver: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofResponse {
    // file_id: String,
    pub num: usize,
    pub block_id: String,
    pub sector_size: u64,
    pub sealed_cid: String,
    pub proof: Vec<u8>,
}

// #[derive(Debug, Serialize, Deserialize)]
// pub struct TestResponse {
//     peer_id: String,
// }

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockRequest {
    pub block_id: String,
    pub receiver: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListRequest {
    pub mode: ListMode,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfoBroadcast {
    pub peer_id: String,
    pub files: HashMap<String, FileMeta>,
    pub local_blocks: HashMap<String, BroadcastBlock>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BroadcastBlock {
    pub size: usize,
    pub recovery_nodes: Vec<String>,
    pub file_id: String,
    pub peers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListResponse {
    pub mode: ListMode,
    pub unsealed_ids: Vec<String>,
    pub receiver: String,
}