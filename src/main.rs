use libp2p::{
    Multiaddr,
    core::upgrade,
    gossipsub::{Gossipsub, GossipsubConfig, GossipsubConfigBuilder, GossipsubEvent, IdentTopic, MessageAuthenticity},
    identity,
    mdns::{MdnsEvent, Mdns},
    mplex,
    noise::{Keypair, NoiseConfig, X25519Spec},
    swarm::{NetworkBehaviourEventProcess, Swarm, SwarmBuilder},
    tcp::TcpConfig,
    NetworkBehaviour, PeerId, Transport,
};
use log::{error, info, debug, warn};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::{fs, io::AsyncBufReadExt, sync::mpsc};
#[macro_use]
extern crate lazy_static;
extern crate libc;
use uuid::Uuid;
use std::sync::Mutex;
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use num_cpus;

mod types;
use types::*;
mod block;
use block::*;
mod benchmark;
use benchmark::*;
mod porep;
use porep::*;

static mut CPU_CNT: usize = 1;

fn load_peer_data() -> PeerMetadata {
    let content = std::fs::read(STORAGE_FILE_PATH).unwrap();
    serde_json::from_slice(&content).unwrap()
}

lazy_static! {
    pub static ref PEERINFO: Mutex<PeerMetadata> = {
        let p: PeerMetadata = load_peer_data();
        Mutex::new(p)
    };

    static ref PROVE_STATUS: Mutex<HashMap<String, HashMap<String, bool>>> = {
        let p: HashMap<String, HashMap<String, bool>> = HashMap::new();
        Mutex::new(p)
    };

    static ref LOCAL_BLOCKS: Mutex<HashMap<String, DataBlock>> = {
        let local_blocks: HashMap<String, DataBlock> = HashMap::new();
        Mutex::new(local_blocks)
    };
}

pub const CODE_M: u8 = 6;
// const CODE_N: u8 = 4;
pub const STORAGE_FILE_PATH: &str = "./data.json";
pub const STORAGE_BLOCK_PATH: &str = "./blocks/";

// openssl genrsa -out private.pem 2048
// openssl pkcs8 -in private.pem -inform PEM -topk8 -out private.pk8 -outform DER -nocrypt
static KEYS: Lazy<identity::Keypair> = Lazy::new(|| identity::Keypair::rsa_from_pkcs8(&mut std::fs::read("private.pk8").unwrap()).unwrap());
static PEER_ID: Lazy<PeerId> = Lazy::new(|| PeerId::from(KEYS.public()));
// lazy_static! {
//     static ref TOPIC: IdentTopic = IdentTopic::new("datablocks");
// }
static TOPIC: Lazy<IdentTopic> = Lazy::new(|| IdentTopic::new("datablocks".to_string()));

enum EventType {
    Response(ListResponse),
    BlockResponse(BlockResponse),
    ProofPublish(SealerOutput),
    ProofResponse(ProofResponse),
    RecoverRequest(RecoverRequest),
    RecoverReqResponse(RecoverResponse),
    RecoverRespResponse(RecoverResponse),
    Broadcast(String),
    Input(String),
    // Timer(),
    // TestResponse(TestResponse),
}

#[derive(NetworkBehaviour)]
struct DataBlockBehaviour {
    gossipsub: Gossipsub,
    mdns: Mdns,
    #[behaviour(ignore)]
    addresses: HashMap<PeerId, Multiaddr>,
    #[behaviour(ignore)]
    response_sender: mpsc::UnboundedSender<ListResponse>,
    #[behaviour(ignore)]
    block_sender: mpsc::UnboundedSender<BlockResponse>,
    #[behaviour(ignore)]
    recoverreq_sender: mpsc::UnboundedSender<RecoverResponse>,
    #[behaviour(ignore)]
    recoverresp_sender: mpsc::UnboundedSender<RecoverResponse>,
    #[behaviour(ignore)]
    broadcast_sender: mpsc::UnboundedSender<String>,
    // #[behaviour(ignore)]
    // proof_sender: mpsc::UnboundedSender<ProofResponse>,
    // #[behaviour(ignore)]
    // test_sender: mpsc::UnboundedSender<TestResponse>,
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for DataBlockBehaviour {
    fn inject_event(&mut self, event: GossipsubEvent) {
        match event {
            GossipsubEvent::Message{propagation_source: peer_id, message_id: msg_id, message: msg} => {
                if let Ok(broad) = serde_json::from_slice::<PeerInfoBroadcast>(&msg.data) {
                    debug!("{:?}", broad);
                    let mut p = PEERINFO.lock().unwrap();
                    // let peer_id = broad.peer_id;
                    for (block_id, block) in broad.local_blocks.iter() {
                        let remote_block = DataBlock {
                            block_id: block_id.to_string(),
                            size: block.size,
                            recovery_nodes: block.recovery_nodes.clone(),
                            public: true,
                            file_id: block.file_id.clone(),
                            local: false,
                            peers: block.peers.clone(),
                            path: block_id.to_string(),
                        };
                        p.data_blocks.insert(block_id.to_string(), remote_block);
                    }
                    for (file_id, file) in broad.files.iter() {
                        p.file.insert(file_id.to_string(), file.clone());
                    }
                    let j = serde_json::to_string(&*p).unwrap();
                    std::fs::write(STORAGE_FILE_PATH, j).expect("Unable to write file");
                } else if let Ok(resp) = serde_json::from_slice::<ListResponse>(&msg.data) {
                    debug!("{:?}", resp);
                    if resp.receiver == PEER_ID.to_string() {
                        info!("Response from {}:", peer_id);
                        resp.unsealed_ids.iter().for_each(|r| info!("{:?}", r));
                    }
                } else if let Ok(req) = serde_json::from_slice::<ListRequest>(&msg.data) {
                    debug!("{:?}", req);
                    match req.mode {
                        ListMode::ALL => {
                            info!("Received ALL req: {:?} from {:?}", req, peer_id);
                            respond_list(
                                self.response_sender.clone(),
                                peer_id.to_string(),
                            );
                        }
                        ListMode::One(ref peer_id) => {
                            if peer_id == &PEER_ID.to_string() {
                                info!("Received req: {:?} from {:?}", req, peer_id);
                                respond_list(
                                    self.response_sender.clone(),
                                    peer_id.to_string(),
                                );
                            }
                        }
                    }
                } else if let Ok(resp) = serde_json::from_slice::<BlockResponse>(&msg.data) {
                    debug!("{:?}", resp);
                    if resp.receiver == PEER_ID.to_string() {
                        info!("Response from {}:", peer_id);
                        extract_block(resp);
                    }
                } else if let Ok(req) = serde_json::from_slice::<RecoverResponse>(&msg.data) {
                    debug!("{:?}", req);
                    if req.receiver == PEER_ID.to_string() {
                        self.recoverresp_sender.send(req).expect("recover failed");
                    }
                } else if let Ok(req) = serde_json::from_slice::<RecoverRequest>(&msg.data) {
                    debug!("{:?}", req);
                    if req.receiver == PEER_ID.to_string() {
                        respond_block(
                            self.recoverreq_sender.clone(),
                            peer_id.to_string(),
                            req.block_id,
                            req.uuid,
                        );
                    }
                } else if let Ok(resp) = serde_json::from_slice::<ProofResponse>(&msg.data) {
                    debug!("{:?}", resp);
                    let sealed_cid = resp.block_id.clone();
                    println!("proof of block {:?} received", sealed_cid);
                    std::thread::spawn(move || {
                        let res: bool = verify_file(resp);
                        if !res {
                            warn!("Proof of block {} is invalid", sealed_cid);
                        } else {
                            {
                                let mut prove_status = PROVE_STATUS.lock().unwrap();
                                if let Some(s) = prove_status.get_mut(&peer_id.to_string()).unwrap().get_mut(&sealed_cid) {
                                    *s = true;
                                }
                            }
                        }
                    });
                } else if let Ok(req) = serde_json::from_slice::<BlockRequest>(&msg.data) {
                    debug!("{:?}", req);
                    if req.receiver == PEER_ID.to_string() {
                        respond_data(
                            self.block_sender.clone(),
                            peer_id.to_string(),
                            req.block_id,
                        );
                    }
                }
            }
            _ => (),
        }
    }
}

fn respond_list(sender: mpsc::UnboundedSender<ListResponse>, receiver: String) {
    tokio::spawn(async move {
        match read_local_block_metadata().await {
            Ok(id) => {
                let resp = ListResponse {
                    mode: ListMode::ALL,
                    receiver,
                    unsealed_ids: id,
                };
                if let Err(e) = sender.send(resp) {
                    error!("error sending response via channel, {}", e);
                }
            }
            Err(e) => error!("error fetching local recipes to answer ALL request, {}", e),
        }
    });
}

fn respond_data(sender: mpsc::UnboundedSender<BlockResponse>, receiver: String, block_id: String) {
    tokio::spawn(async move {
        match read_block_data(block_id.clone()).await {
            Ok((filemeta, bytes)) => {
                let resp = BlockResponse {
                    file_id: filemeta.file_id,
                    block_id,
                    data: bytes,
                    receiver,
                };
                if let Err(e) = sender.send(resp) {
                    error!("error sending response via channel, {}", e);
                }
            }
            Err(e) => error!("error fetching local recipes to answer ALL request, {}", e),
        }
    });
}

fn respond_block(sender: mpsc::UnboundedSender<RecoverResponse>, receiver: String, block_id: String, uuid: String) {
    tokio::spawn(async move {
        match read_block_data(block_id.clone()).await {
            Ok((_, bytes)) => {
                let resp = RecoverResponse {
                    uuid,
                    block_id,
                    data: bytes,
                    receiver,
                };
                if let Err(e) = sender.send(resp) {
                    error!("error sending response via channel, {}", e);
                }
            }
            Err(e) => error!("error fetching local recipes to answer ALL request, {}", e),
        }
    });
}

impl NetworkBehaviourEventProcess<MdnsEvent> for DataBlockBehaviour {
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(discovered_list) => {
                for (peer, _addr) in discovered_list {
                    let some_addresses = self.addresses.get_mut(&peer);
                    match some_addresses {
                        Some(_addr) => {},
                        None => {
                            self.addresses.insert(peer.clone(), _addr);
                            self.gossipsub.add_explicit_peer(&peer);
                        }
                    }
                }
            }
            MdnsEvent::Expired(expired_list) => {
                for (peer, _addr) in expired_list {
                    warn!("peer {:?} expired", peer.to_string());
                    if let Some(addr) = self.addresses.get_mut(&peer) {
                        self.addresses.remove(&peer);
                    }
                    if !self.mdns.has_node(&peer) {
                        self.gossipsub.remove_explicit_peer(&peer);
                    }
                }
            }
        }
    }
}

async fn get_metadataby_id(block_id: String) -> std::result::Result<DataBlock, &'static str> {
    let content = fs::read(STORAGE_FILE_PATH).await.unwrap();
    let result: PeerMetadata = serde_json::from_slice(&content).unwrap();
    if result.data_blocks.contains_key(&block_id) {
        Ok(result.data_blocks.get(&block_id).unwrap().clone())
    } else {
        Err("no block id")
    }
}

async fn read_local_block_metadata() -> Result<Vec<String>> {
    let content = fs::read(STORAGE_FILE_PATH).await?;
    let result: PeerMetadata = serde_json::from_slice(&content)?;
    let mut vec: Vec<String> = Vec::new();
    for (_, b) in result.data_blocks.iter() {
        if b.local {
            vec.push(b.block_id.clone());
        }
    }
    Ok(vec)
}

async fn store_file(cmd: &str, _swarm: &mut Swarm<DataBlockBehaviour>) {
    let rest = cmd.strip_prefix("store ");
    match rest {
        Some(file_name) => {
            let file_id = Uuid::new_v4().to_simple().to_string();
            let mut file_meta = FileMeta {
                name: file_name.to_string(),
                file_id: file_id.clone(),
                data_blocks: Vec::new(),
                parity_blocks: Vec::new(),
            };
            let file_bytes = read_file(file_name).await.unwrap();
            let file_size = file_bytes.len();
            let block_size = file_size / usize::from(CODE_M);
        
            let mut vec: Vec<Vec<u8>> = Vec::new();
            let mut uuids: Vec<String> = Vec::new();
            for i in 0..usize::from(CODE_M) {
                let block = file_bytes[i * block_size..(i+1) * block_size].to_vec();
                vec.push(block.clone());
                let uuid = Uuid::new_v4().to_simple().to_string();
                let uid = store_file_block(uuid, block).await;
                file_meta.data_blocks.push(uid.clone());
                uuids.push(uid);
            }
            let mut vec_temp: Vec<u8> = Vec::new();
            for i in 0..block_size {
                vec_temp.push(vec[1][i] ^ 0);
            }
            vec.push(vec_temp.clone());
            let uuid6 = Uuid::new_v4().to_simple().to_string();
            let uid6 = store_file_block(uuid6, vec_temp).await;
            file_meta.parity_blocks.push(uid6.clone());
            uuids.push(uid6);
            vec_temp = Vec::new();
            for i in 0..block_size {
                vec_temp.push(vec[5][i] ^ 0);
            }
            vec.push(vec_temp.clone());
            let uuid7 = Uuid::new_v4().to_simple().to_string();
            let uid7 = store_file_block(uuid7, vec_temp).await;
            file_meta.parity_blocks.push(uid7.clone());
            uuids.push(uid7);
            vec_temp = Vec::new();
            for i in 0..block_size {
                vec_temp.push(vec[0][i] ^ vec[3][i]);
            }
            vec.push(vec_temp.clone());
            let uuid8 = Uuid::new_v4().to_simple().to_string();
            let uid8 = store_file_block(uuid8, vec_temp).await;
            file_meta.parity_blocks.push(uid8.clone());
            uuids.push(uid8);
            vec_temp = Vec::new();
            for i in 0..block_size {
                vec_temp.push(vec[2][i] ^ vec[4][i]);
            }
            vec.push(vec_temp.clone());
            let uuid9 = Uuid::new_v4().to_simple().to_string();
            let uid9 = store_file_block(uuid9, vec_temp).await;
            file_meta.parity_blocks.push(uid9.clone());
            uuids.push(uid9);

            let mut p = PEERINFO.lock().unwrap();
            let mut group: Vec<DataBlock> = Vec::new();
            for i in 0..vec.len() {
                let mut recovery_nodes: Vec<String> = Vec::new();
                if i == 3 || i == 8 {
                    recovery_nodes.push(uuids.get(0).unwrap().to_string());
                } else if i == 6 {
                    recovery_nodes.push(uuids.get(1).unwrap().to_string());
                } else if i == 4 || i == 9 {
                    recovery_nodes.push(uuids.get(2).unwrap().to_string());
                } else if i == 0 || i == 8 {
                    recovery_nodes.push(uuids.get(3).unwrap().to_string());
                } else if i == 2 || i == 9 {
                    recovery_nodes.push(uuids.get(4).unwrap().to_string());
                } else if i == 7 {
                    recovery_nodes.push(uuids.get(5).unwrap().to_string());
                } else if i == 1 {
                    recovery_nodes.push(uuids.get(6).unwrap().to_string());
                } else if i == 5 {
                    recovery_nodes.push(uuids.get(7).unwrap().to_string());
                } else if i == 0 || i == 3 {
                    recovery_nodes.push(uuids.get(8).unwrap().to_string());
                } else if i == 2 || i == 4 {
                    recovery_nodes.push(uuids.get(9).unwrap().to_string());
                }
                let data_block = DataBlock {
                    block_id: uuids.get(i).unwrap().to_string(),
                    size: block_size,
                    recovery_nodes,
                    public: true,
                    file_id: file_id.clone(),
                    local: true,
                    path: uuids.get(i).unwrap().to_string(),
                    peers: vec![PEER_ID.to_string()],
                };
                group.push(data_block.clone());
                p.data_blocks.insert(data_block.block_id.clone(), data_block);
                // save_file(&vec[i], &uuids.get(i).unwrap()[..], STORAGE_BLOCK_PATH).unwrap();
            }
            p.stored_size += file_size;
            p.file.insert(file_id.clone(), file_meta);
            add_to_prove_group(&mut group, &mut p).unwrap();
            let j = serde_json::to_string(&*p).unwrap();
            fs::write(STORAGE_FILE_PATH, j).await.expect("Unable to write file");
            info!("Stored file id {}", file_id);
        },
        None => error!("No file specified"),
    }
}

async fn extract_file(cmd: &str, swarm: &mut Swarm<DataBlockBehaviour>) {
    let rest = cmd.strip_prefix("load ");
    match rest {
        Some(file_id) => {
            let filemeta = get_file_meta(file_id.to_string()).await.unwrap();
            let data_blocks = filemeta.data_blocks;
            let file_name = filemeta.name;
            let mut vec: Vec<Vec<u8>> = Vec::new();
            let mut mb: HashMap<String, usize> = HashMap::new();
            for i in 0..data_blocks.len() {
                let vtemp: Vec<u8> = Vec::new();
                vec.push(vtemp);
                mb.insert(data_blocks.get(i).unwrap().to_string(), i);
            }
            let file_tmp = TempFile {
                file_id: file_id.to_string(),
                file_name,
                block_ids: mb,
                block_vecs: vec,
            };
            let mut m = block::PENDING_FILES.lock().unwrap();
            m.insert(file_id.to_string(), file_tmp);
            for b in data_blocks.into_iter() {
                let block_meta = get_metadataby_id(b.to_string()).await.unwrap();
                if block_meta.local {
                    let (_, bytes): (DataBlock, Vec<u8>) = read_block_data(b.to_string()).await.unwrap();
                    let ft = m.get_mut(file_id).unwrap();
                    let seq: usize = *ft.block_ids.get(&b).unwrap();
                    let bv = ft.block_vecs.get_mut(seq).unwrap();
                    for by in bytes.into_iter() {
                        bv.push(by);
                    }
                    ft.block_ids.remove(&b.to_string());
                } else {
                    let req = BlockRequest {
                        block_id: block_meta.block_id.to_string(),
                        receiver: block_meta.peers.first().unwrap().to_string(),
                    };
                    let json = serde_json::to_string(&req).expect("can jsonify request");
                    swarm.gossipsub.publish(TOPIC.clone(), json.as_bytes()).expect("swarm publish failed");
                }
            }
            let ft = m.get_mut(file_id).unwrap();
            if ft.block_ids.len() == 0 {
                let padded: Vec<u8> = merge(&mut ft.block_vecs, usize::from(CODE_M));
                let unpadded: Vec<u8> = unpadding(padded);
                save_file(&unpadded, &ft.file_name, "./extract/").unwrap();
                m.remove(file_id);
            }
        },
        None => error!("No file to extract"),
    };
}

async fn handle_list_blocks(cmd: &str, swarm: &mut Swarm<DataBlockBehaviour>) {
    let rest = cmd.strip_prefix("ls r ");
    match rest {
        Some("all") => {
            let req = ListRequest {
                mode: ListMode::ALL,
            };
            let json = serde_json::to_string(&req).expect("can jsonify request");
            swarm.gossipsub.publish(TOPIC.clone(), json.as_bytes());
        }
        Some(recipes_peer_id) => {
            let req = ListRequest {
                mode: ListMode::One(recipes_peer_id.to_owned()),
            };
            let json = serde_json::to_string(&req).expect("can jsonify request");
            swarm.gossipsub.publish(TOPIC.clone(), json.as_bytes());
        }
        None => {
            match read_local_block_metadata().await {
                Ok(v) => {
                    info!("Local Recipes ({})", v.len());
                    v.iter().for_each(|r| info!("{:?}", r));
                }
                Err(e) => error!("error fetching local recipes: {}", e),
            };
        }
    };
}

async fn handle_list_peers(swarm: &mut Swarm<DataBlockBehaviour>) {
    info!("Discovered Peers:");
    let nodes = swarm.mdns.discovered_nodes();
    info!("{:?}", swarm.addresses);
    let mut unique_peers = HashSet::new();
    for peer in nodes {
        unique_peers.insert(peer);
    }
    unique_peers.iter().for_each(|p| info!("{}", p));
}

async fn handle_get_block(cmd: &str, swarm: &mut Swarm<DataBlockBehaviour>) {
    let rest = cmd.strip_prefix("get ");
    match rest {
        Some(block_id) => {
            let block_meta = get_metadataby_id(block_id.to_string()).await.unwrap();
            if block_meta.local {
                let (_, bytes): (DataBlock, Vec<u8>) = read_block_data(block_id.to_string()).await.unwrap();
                info!("{:?}", bytes);
            } else {
                // let mut receiver: String;
                // for pid in block_meta.peers {
                //     if pid != PEER_ID.to_string() {
                //         receiver = pid;
                //         break;
                //     }
                // }
                let req = BlockRequest {
                    block_id: block_meta.block_id.to_string(),
                    receiver: block_meta.peers.first().unwrap().to_string(),
                };
                let json = serde_json::to_string(&req).expect("can jsonify request");
                swarm.gossipsub.publish(TOPIC.clone(), json.as_bytes()).expect("swarm publish failed");
            }
        },
        None => error!("error fetching local recipes to answer ALL request"),
    };
}

async fn get_file_meta(file_id: String) -> std::result::Result<FileMeta, &'static str> {
    let content = fs::read(STORAGE_FILE_PATH).await.unwrap();
    let result: PeerMetadata = serde_json::from_slice(&content).unwrap();
    let file = result.file.get(&file_id);
    match file {
        Some(f) => Ok(f.clone()),
        None => Err("no such file"),
    }    
}

// async fn get_blockids_of_file(file_id: String) -> std::result::Result<Vec<String>, &'static str> {
//     let content = fs::read(STORAGE_FILE_PATH).await.unwrap();
//     let result: PeerMetadata = serde_json::from_slice(&content).unwrap();
//     for f in result.file.into_iter() {
//         if f.file_id == file_id {
//             return Ok(f.data_blocks)
//         }
//     }
//     Err("no such file")
// }

// async fn verify_proof(proof: GoSlice, unsealed_id: String, sealed_id: String, sector_size: GoString) -> bool {

// }

async fn recover_block(data_blocks: HashMap<String, DataBlock>, block_id: String, tx: mpsc::UnboundedSender<RecoverRequest>, mut rx: mpsc::UnboundedReceiver<RecoverResponse>, uuid: String) -> std::result::Result<Vec<u8>, &'static str> {
    let peer_id = PEER_ID.to_string();
    let find_block_info =  data_blocks.get(&block_id);
    match find_block_info {
        Some(block_info) => {
            let block_size = block_info.size;
            let mut vec: Vec<u8> = vec![0; block_size];
            let mut recover_num = block_info.recovery_nodes.len();
            for rec in &block_info.recovery_nodes {
                let block = data_blocks.get(rec).unwrap();
                for pid in &block.peers {
                    if pid.to_string() == peer_id {
                        if block_id != *rec {
                            let (_, vec_tmp) = read_block_data(rec.clone()).await.unwrap();
                            for i in 0..block_size {
                                vec[i] = vec[i] ^ vec_tmp[i];
                            }
                            recover_num -= 1;
                            break;
                        }
                    } else {
                        let req = RecoverRequest {
                            uuid: uuid.clone(),
                            block_id: rec.clone(),
                            receiver: pid.to_string(),
                        };
                        // let json = serde_json::to_string(&req).expect("can jsonify request");
                        tx.send(req).expect("recover failed");
                        // swarm.gossipsub.publish(&TOPIC, json.as_bytes());
                        break;
                    }
                }
            }
            for _n in 0..recover_num {
                let vec_tmp =  rx.recv().await.unwrap().data;
                for i in 0..block_size {
                    vec[i] = vec[i] ^ vec_tmp[i];
                }
            }
            Ok(vec)
        },
        None => Err("block not found!"),
    }
}

async fn start_period(prove_tx: mpsc::UnboundedSender<SealerOutput>) {
    {
        let mut prove_status = PROVE_STATUS.lock().unwrap();
        println!("{:?}", prove_status);
        for (peer_id, peer_status) in prove_status.iter_mut() {
            for (block_id, status) in peer_status.iter_mut() {
                if *status == true {
                    *status = false;
                }
                else {

                }
            }
        }
    }

    let mut p: HashMap<String, DataBlock> = HashMap::new();
    {
        let tmp = PEERINFO.lock().unwrap();
        p = tmp.data_blocks.clone();
    }
    // let mut childs = std::collections::VecDeque::new();
    // for (block_id, block) in p.iter() {
    //     if block.local == false {
    //         continue;
    //     }
    //     let sealer_id = Uuid::new_v4().to_simple().to_string();
    //     let cmd1: String = block_id.to_string().clone();
    //     let thread_id = sealer_id.clone();
    //     let child = tokio::spawn(prove_file(cmd1, prove_tx.clone(), thread_id));
    //     childs.push_back(child);
    //     if childs.len() > 0 {
    //         let child = childs.pop_front().unwrap();
    //         tokio::join!(child);
    //     }
    // }
}

// async fn test(cmd: &str, swarm: &mut Swarm<DataBlockBehaviour>) {
    // let rest = cmd.strip_prefix("test ");
    // match rest {
    //     Some(id) => {
    //         let peer_id: PeerId = "QmcsSnZFhKyZzq3FkZcDij5vAeEvqNyPBaGxcZdZtuSkpq".parse().unwrap();
    //         let addr = swarm.addresses.get(&peer_id).unwrap();
    //         let resp = TestResponse {
    //             peer_id: peer_id.to_string(),
    //         };
    //         // swarm.test_sender.send(resp);
    //         // let noise_keys = Keypair::<X25519Spec>::new().into_authentic(&KEYS).unwrap();
    //         // let cfg = libp2p::request_response::RequestResponseConfig::default();
    //         // let trans = libp2p::tcp::TcpConfig::new()
    //         //     .nodelay(true)
    //         //     .upgrade(upgrade::Version::V1)
    //         //     .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
    //         //     .multiplex(libp2p::yamux::YamuxConfig::default())
    //         //     .boxed();
    //         // let protocols = std::iter::once((PingProtocol(), ProtocolSupport::Full));
    //         // let ping_proto2 = libp2p::request_response::RequestResponse::new(PingCodec(), protocols, cfg);
    //         // let v: Vec<u8> = "ping".to_string().into_bytes();
    //         // let mut peer_id: PeerId = "QmcsSnZFhKyZzq3FkZcDij5vAeEvqNyPBaGxcZdZtuSkpq".parse().unwrap();
    //         // let addr = swarm.addresses.get(&peer_id).unwrap();
    //         // let mut swarm2 = Swarm::new(trans, ping_proto2, peer_id.clone());
    //         // swarm2.add_address(&peer_id, addr.clone());
    //         // swarm2.send_request(&peer_id, v);
    //     },
    //     None => error!("No file to extract"),
    // };
// }

async fn broadcast(sender: mpsc::UnboundedSender<String>, local_blocks: HashMap<String, DataBlock>) {
    let peer_info = PEERINFO.lock().unwrap();
    let mut tmp = HashMap::new();
    for (id, block) in local_blocks.iter() {
        let t = BroadcastBlock {
            size: block.size,
            recovery_nodes: block.recovery_nodes.clone(),
            file_id: block.file_id.clone(),
            peers: block.peers.clone(),
        };
        tmp.insert(id.clone(), t);
    }
    let req = PeerInfoBroadcast {
        peer_id: PEER_ID.to_string(),
        files: peer_info.file.clone(),
        local_blocks: tmp,
    };
    let json = serde_json::to_string(&req).expect("can jsonify request");
    if let Err(e) = sender.send(json) {
        error!("error sending response via channel, {}", e);
    }
}

fn cleanup() {
    let mut peer_info = PEERINFO.lock().unwrap();
    peer_info.file.clear();
    peer_info.data_blocks.clear();
    peer_info.proof_groups.clear();
    peer_info.stored_size = 0;
    let j = serde_json::to_string(&*peer_info).unwrap();
    std::fs::write(STORAGE_FILE_PATH, j).expect("Unable to write file");
}

// async fn load_file(fname: &str) -> Result<Vec<u8>> {
//     let mut path = STORAGE_BLOCK_PATH.to_string();
//     path.push_str(fname);
//     let bytes = fs::read(path).await?;
//     let padding: u8 = bytes.last().unwrap().clone();
//     let unpadded_bytes = bytes[..bytes.len()-usize::from(padding)].to_vec();
//     Ok(unpadded_bytes)
// }

#[tokio::main]
async fn main() -> Result<()>
{
    unsafe { CPU_CNT = num_cpus::get(); }
    pretty_env_logger::init();

    info!("Peer Id: {}", PEER_ID.clone());
    let (response_sender, mut response_rcv) = mpsc::unbounded_channel();
    let (block_sender, mut block_rcv) = mpsc::unbounded_channel();
    let (recoverreq0_sender, mut recoverreq0_rcv) = mpsc::unbounded_channel();
    let (recoverreq_sender, mut recoverreq_rcv) = mpsc::unbounded_channel();
    let (recoverresp_sender, mut recoverresp_rcv) = mpsc::unbounded_channel();
    let (prove_tx, mut prove_rx) = mpsc::unbounded_channel();
    let (broadcast_sender, mut broadcast_rcv) = mpsc::unbounded_channel();
    let mut channels: HashMap<String, mpsc::UnboundedSender<RecoverResponse>> = HashMap::new();
    let peer_info = load_peer_data();
    let data_blocks = peer_info.data_blocks.clone();
    {
        let mut local_blocks = LOCAL_BLOCKS.lock().unwrap();
        for (block_id, block) in data_blocks.iter() {
            for peer in block.peers.iter() {
                if *peer != PEER_ID.to_string() {
                    let mut prove_status = PROVE_STATUS.lock().unwrap();
                    let peer_prove_status = prove_status.get_mut(peer);
                    match peer_prove_status {
                        Some(status) => {
                            status.insert(block_id.clone(), true);
                        },
                        None => {
                            let mut tmp = HashMap::new();
                            tmp.insert(block_id.clone(), true);
                            prove_status.insert(peer.to_string(), tmp);
                        },
                    }
                }
            }
            if block.local == true {
                local_blocks.insert(block_id.clone(), block.clone());
            }
        }
    }
    
    // let mut sealer_threads: HashMap<String, std::thread::JoinHandle<_>> = HashMap::new();
    // let (test_sender, mut test_rcv) = mpsc::unbounded_channel();

    let auth_keys = Keypair::<X25519Spec>::new()
        .into_authentic(&KEYS)
        .expect("can create auth keys");

    let mut mplex_config = mplex::MplexConfig::new();
    mplex_config.set_max_buffer_size(1024);

    let transp = TcpConfig::new()
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(auth_keys).into_authenticated()) // XX Handshake pattern, IX exists as well and IK - only XX currently provides interop with other libp2p impls
        .multiplex(mplex_config)
        .boxed();

    let mut gossipsub_configbuilder = GossipsubConfigBuilder::default();
    // gossipsub_configbuilder.heartbeat_interval(Duration::from_secs(5));
    gossipsub_configbuilder.max_transmit_size(65536*16);
    let gossipsub_config = gossipsub_configbuilder.build().unwrap();
    let message_authenticity = MessageAuthenticity::Signed(KEYS.clone());
    let mut behaviour = DataBlockBehaviour {
        gossipsub: Gossipsub::new(message_authenticity, gossipsub_config).unwrap(),
        mdns: Mdns::new().await.expect("can create mdns"),
        addresses: HashMap::new(),
        response_sender,
        block_sender,
        recoverreq_sender,
        recoverresp_sender,
        broadcast_sender: broadcast_sender.clone(),
        // proof_sender,
        // test_sender,
    };

    behaviour.gossipsub.subscribe(&TOPIC).expect("topic subscribe failed");

    let mut swarm = SwarmBuilder::new(transp, behaviour, PEER_ID.clone())
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build();

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    Swarm::listen_on(
        &mut swarm,
        "/ip4/0.0.0.0/tcp/0"
            .parse()
            .expect("can get a local socket"),
    )
    .expect("swarm can be started");

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(180));
    loop {
        let evt = {
            tokio::select! {
                line = stdin.next_line() => Some(EventType::Input(line.expect("can get line").expect("can read line from stdin"))),
                event = swarm.next() => {
                    info!("Unhandled Swarm Event: {:?}", event);
                    None
                },
                response = response_rcv.recv() => Some(EventType::Response(response.expect("response exists"))),
                block_response = block_rcv.recv() => Some(EventType::BlockResponse(block_response.expect("response exists"))),
                recover0_response = recoverreq0_rcv.recv() => Some(EventType::RecoverRequest(recover0_response.expect("response exists"))),
                recover_response = recoverreq_rcv.recv() => Some(EventType::RecoverReqResponse(recover_response.expect("response exists"))),
                recoverresp_response = recoverresp_rcv.recv() => Some(EventType::RecoverRespResponse(recoverresp_response.expect("response exists"))),
                sealer_output = prove_rx.recv() => Some(EventType::ProofPublish(sealer_output.expect("response exists"))),
                broadcast_response = broadcast_rcv.recv() => Some(EventType::Broadcast(broadcast_response.expect("response exists"))),
                // _timer = interval.tick() => Some(EventType::Timer()),
                // test_response = test_rcv.recv() => Some(EventType::TestResponse(test_response.expect("response exists"))),
            }
        };

        if let Some(event) = evt {
            match event {
                EventType::Response(resp) => {
                    let json = serde_json::to_string(&resp).expect("can jsonify response");
                    swarm.gossipsub.publish(TOPIC.clone(), json.as_bytes()).expect("swarm publish failed");
                }
                EventType::Broadcast(json) => {
                    swarm.gossipsub.publish(TOPIC.clone(), json.as_bytes()).expect("swarm publish failed");
                }
                EventType::BlockResponse(resp) => {
                    let json = serde_json::to_string(&resp).expect("can jsonify response");
                    swarm.gossipsub.publish(TOPIC.clone(), json.as_bytes()).expect("swarm publish failed");
                }
                EventType::ProofResponse(resp) => {
                    let json = serde_json::to_string(&resp).expect("can jsonify response");
                    swarm.gossipsub.publish(TOPIC.clone(), json.as_bytes()).expect("swarm publish failed");
                }
                EventType::RecoverRequest(resp) => {
                    let json = serde_json::to_string(&resp).expect("can jsonify response");
                    swarm.gossipsub.publish(TOPIC.clone(), json.as_bytes()).expect("swarm publish failed");
                }
                EventType::RecoverReqResponse(resp) => {
                    let json = serde_json::to_string(&resp).expect("can jsonify response");
                    swarm.gossipsub.publish(TOPIC.clone(), json.as_bytes()).expect("swarm publish failed");
                }
                EventType::RecoverRespResponse(resp) => {
                    let tx = channels.get(&resp.uuid).unwrap();
                    tx.send(resp).expect("recover response failed");
                }
                EventType::ProofPublish(resp) => {
                    let resp = ProofResponse {
                        num: resp.num,
                        block_id: resp.unsealed_cid,
                        sector_size: resp.sector_size,
                        sealed_cid: resp.sealed_cid,
                        proof: resp.proof,
                    };
                    let json = serde_json::to_string(&resp).expect("can jsonify response");
                    swarm.gossipsub.publish(TOPIC.clone(), json.as_bytes());
                    println!("proof of {:?} sent", resp.block_id);
                    // send_proof(&mut swarm).await;
                    // let child = sealer_threads.get(&resp.sealer_id).unwrap();
                    // child.join().unwrap();
                }
                EventType::Input(line) => match line.as_str() {
                    "ls p" => handle_list_peers(&mut swarm).await,
                    cmd if cmd.starts_with("ls r") => handle_list_blocks(cmd, &mut swarm).await,
                    cmd if cmd.starts_with("get") => handle_get_block(cmd, &mut swarm).await,
                    cmd if cmd.starts_with("load") => extract_file(cmd, &mut swarm).await,
                    cmd if cmd.starts_with("store") => store_file(cmd, &mut swarm).await,
                    cmd if cmd.starts_with("cast") => {
                        tokio::spawn(broadcast(broadcast_sender.clone(), LOCAL_BLOCKS.lock().unwrap().clone()));
                    },
                    cmd if cmd.starts_with("recover") => {
                        {
                            let rest = cmd.strip_prefix("recover ");
                            match rest {
                                Some(block_id) => {
                                    let (tx, rx) = mpsc::unbounded_channel();
                                    let uuid = Uuid::new_v4().to_simple().to_string();
                                    channels.insert(uuid.clone(), tx);
                                    let p = PEERINFO.lock().unwrap();
                                    let data_blocks = p.data_blocks.clone();
                                    let _child = tokio::spawn(recover_block(data_blocks, block_id.to_string(), recoverreq0_sender.clone(), rx, uuid));
                                },
                                None => error!("No block specified"),
                            }
                        };
                    },
                    cmd if cmd.starts_with("prove") => {
                        let rest = cmd.strip_prefix("prove ");
                        match rest {
                            Some(file_name) => {
                                let proof_groups: Vec<ProofGroup>;
                                {
                                    let peer_info = PEERINFO.lock().unwrap();
                                    proof_groups = peer_info.proof_groups.clone();
                                }
                                if let Some(proof_group) = proof_groups.iter().find(|&p| p.unsealed_cid == file_name) {
                                    let sector_size: u64 = proof_group.sector_size;
                                    let sealer_id = Uuid::new_v4().to_simple().to_string();
                                    let thread_id = sealer_id.clone();
                                    let tx = prove_tx.clone();
                                    let ct = Arc::new(AtomicBool::new(true));
                                    let thread_group = proof_group.clone();
                                    std::thread::spawn(move || prove_file(thread_group, tx, thread_id, sector_size, 4, ct));
                                }
                                else {
                                    error!("No such block in local");
                                }
                            },
                            None => error!("No file specified"),
                        }
                    },
                    cmd if cmd.starts_with("cid") => {
                        let rest = cmd.strip_prefix("cid ").unwrap();
                        let mut opt = rest.split(" ");
                        let vec: Vec<&str> = opt.collect();
                        let file_name = vec[0];
                        let ssize = vec[1];
                        let proof_groups: Vec<ProofGroup>;
                        {
                            let peer_info = PEERINFO.lock().unwrap();
                            proof_groups = peer_info.proof_groups.clone();
                        }
                        if let Some(proof_group) = proof_groups.iter().find(|&p| p.unsealed_cid == file_name) {
                            let sector_size: u64;
                            match ssize {
                                "8" => {
                                    sector_size = 8388608;
                                    let _child = tokio::spawn(get_cid(proof_group.clone(), sector_size));
                                },
                                "512" => {
                                    sector_size = 536870912;
                                    let _child = tokio::spawn(get_cid(proof_group.clone(), sector_size));
                                },
                                "32" => {
                                    sector_size = 34359738368;
                                    let _child = tokio::spawn(get_cid(proof_group.clone(), sector_size));
                                },
                                _ => error!("Wrong sector size specified"),
                            }
                        }
                        else {
                            error!("No such block in local");
                        }
                    },
                    cmd if cmd.starts_with("clean") => {
                        cleanup();
                    },
                    cmd if cmd.starts_with("bench") => {
                        let rest = cmd.strip_prefix("bench ");
                        match rest {
                            Some(cmd) if cmd.starts_with("prove") => {
                                if let Some(rest) = cmd.strip_prefix("prove ") {
                                    let args: Vec<&str> = rest.split(" ").collect();
                                    tokio::spawn(bench_prove(args[0].parse().unwrap(), args[1].parse().unwrap(), prove_tx.clone()));
                                }
                                else {
                                    error!("parallel num not provided");
                                }
                            },
                            Some(_) => {

                            }
                            None => error!("No bench specified"),
                        }
                    },
                    _ => error!("unknown command"),
                }
                // EventType::Timer() => {
                //     let child = tokio::spawn(start_period(prove_tx.clone()));
                // }
                // EventType::TestResponse(resp) => {
                //     let json = serde_json::to_string(&resp).expect("can jsonify response");
                //     swarm.gossipsub.publish(&TOPIC, json.clone().as_bytes());
                //     info!("{:?}", json);
                // }
            }
        }
    }
}