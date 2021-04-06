use tokio::{sync::mpsc};
use std::fs::{create_dir_all, remove_dir_all, File, OpenOptions};
use std::path::PathBuf;
use log::{info};
use std::io::{BufReader};
use uuid::Uuid;
use std::fs;
use base64;
use std::sync::Mutex;
use std::time::Duration;
use std::io::prelude::*;
use std::io::Cursor;

mod seal;
mod registry;
mod prove;

use registry::{RegisteredSealProof};
use seal::{generate_piece_commitment, Labels, VanillaSealProof};
use prove::{FilePoRep, FileProver, porep_verifier, cid_2_bytes, bytes_2_cid};

use storage_proofs::sector::{SectorId};
use filecoin_proofs_v1::{types::{
    Commitment, PaddedBytesAmount, PieceInfo, ProverId, Ticket,
    UnpaddedByteIndex, UnpaddedBytesAmount,
}, Labels as RawLabels};
use filecoin_hashers::{
    poseidon::{PoseidonDomain},
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::block::*;
use crate::types::{ProofResponse, SealerOutput, ProofGroup};
use crate::STORAGE_BLOCK_PATH;


lazy_static! {
    #[derive(Debug)]
    static ref GPU_UTIL: Mutex<usize> = {
        let p: usize = 0;
        Mutex::new(p)
    };    
}

pub fn get_group_unsealed_id(group: &ProofGroup) -> String {
    let registered_proof: RegisteredSealProof;
    let sector_size = group.sector_size;
    match sector_size {
        536870912 => {
            registered_proof = RegisteredSealProof::StackedDrg512MiBV1_1
        },
        8388608 => {
            registered_proof = RegisteredSealProof::StackedDrg8MiBV1_1
        },
        _ => panic!("sector size not supported"),
    };

    let uuid = Uuid::new_v4().to_simple().to_string();
    let mut sealer_dir = PathBuf::from("sealer_cache");
    sealer_dir.push(uuid.clone());
    let mut cache_path = sealer_dir.clone();
    cache_path.push("cache");
    if !cache_path.exists() {
        create_dir_all(&cache_path).unwrap();
    }
    let sector_size_unpadded_bytes_amount = sector_size - (sector_size / 128);

    // let mut tmp_file = cache_path.clone();
    // tmp_file.push(uuid);
    // let f_data = OpenOptions::new()
    //     .read(true)
    //     .write(true)
    //     .create(true)
    //     .open(&tmp_file).unwrap();

    let mut buffer = Vec::new();
    for block in &group.blocks {
        let mut path = STORAGE_BLOCK_PATH.to_string();
        path.push_str(&block);
        let mut file = OpenOptions::new().read(true).open(path).unwrap();
        file.read_to_end(&mut buffer).unwrap();
    }
    buffer.resize(sector_size_unpadded_bytes_amount as usize, 0);
    let source = Cursor::new(buffer);

    // Zero-pad the data to the requested size by extending the underlying file if needed.
    // f_data.set_len(sector_size_unpadded_bytes_amount as u64).unwrap();
    // let source = BufReader::new(File::open(&tmp_file).expect("File open failed"));

    let piece_size =
        UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size));
    let meta = generate_piece_commitment(
        registered_proof.into(),
        source,
        piece_size,
    ).unwrap();
    let commitment = meta.commitment;
    bytes_2_cid(commitment)
}

pub async fn get_unsealed_id(filename: &String, sector_size: u64) -> String {
    let registered_proof: RegisteredSealProof;
    match sector_size {
        536870912 => {
            registered_proof = RegisteredSealProof::StackedDrg512MiBV1_1
        },
        8388608 => {
            registered_proof = RegisteredSealProof::StackedDrg8MiBV1_1
        },
        _ => panic!("sector size not supported"),
    };

    let uuid = Uuid::new_v4().to_simple().to_string();
    let mut sealer_dir = PathBuf::from("sealer_cache");
    sealer_dir.push(uuid.clone());
    let mut cache_path = sealer_dir.clone();
    cache_path.push("cache");
    if !cache_path.exists() {
        create_dir_all(&cache_path).unwrap();
    }
    let sector_size_unpadded_bytes_amount = sector_size - (sector_size / 128);

    let mut tmp_file = cache_path.clone();
    let name = PathBuf::from(filename);
    let name = name.file_name().unwrap();
    tmp_file.push(name);
    fs::copy(&filename, &tmp_file).unwrap();

    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&tmp_file).unwrap();
    // Zero-pad the data to the requested size by extending the underlying file if needed.
    f_data.set_len(sector_size_unpadded_bytes_amount as u64).unwrap();
    let source = BufReader::new(File::open(&tmp_file).expect("File open failed"));

    let piece_size =
        UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size));
    let meta = generate_piece_commitment(
        registered_proof.into(),
        source,
        piece_size,
    ).unwrap();
    let commitment = meta.commitment;
    bytes_2_cid(commitment)
}

pub async fn get_cid(group: ProofGroup, sector_size: u64) -> std::result::Result<Vec<u8>, &'static str> {
    let sector_id = SectorId::from(0);
    let prover_id: [u8; 32] = [1; 32];
    let ticket_bytes: [u8; 32] = [1; 32];
    let seed: [u8; 32] = [1; 32];
    let registered_proof: RegisteredSealProof;
    match sector_size {
        536870912 => {
            registered_proof = RegisteredSealProof::StackedDrg512MiBV1_1
        },
        8388608 => {
            registered_proof = RegisteredSealProof::StackedDrg8MiBV1_1
        },
        _ => panic!("sector size not supported"),
    };

    let uuid = Uuid::new_v4().to_simple().to_string();
    let mut sealer_dir = PathBuf::from("sealer_cache");
    sealer_dir.push(uuid.clone());
    let mut cache_path = sealer_dir.clone();
    cache_path.push("cache");
    if !cache_path.exists() {
        create_dir_all(&cache_path).unwrap();
    }
    let mut sealed_path = sealer_dir.clone();
    sealed_path.push("sealed");

    let mut prover = FileProver{
        registered_proof,
        group,
        cache_path,
        sealed_path,
        sector_size,
        seed,
        ticket_bytes,
        prover_id,
        sector_id,
        comm_d: [0; 32],
        comm_r: [0; 32],
        labels: Labels::StackedDrg8MiBV1(RawLabels::new(Vec::new())),
        config: filecoin_proofs_v1::StoreConfig::new("", "", 0),
        piece_infos: Vec::new(),
        vanilla_proofs: VanillaSealProof::StackedDrg8MiBV1(Vec::new()),
        replica_id: PoseidonDomain::default(),
    };
    prover.pre_commit1().unwrap();
    prover.pre_commit2();
    prover.commit1();
    let proof = prover.commit2();
    info!("{:?}", &proof);
    let porep = FilePoRep{
        registered_proof,
        comm_d: prover.comm_d,
        comm_r: prover.comm_r,
        prover_id,
        sector_id,
        ticket_bytes,
        seed,
        proof: proof.clone(),
    };
    let res = porep_verifier(porep);
    info!("{:?}", &res);
    Ok(proof)
}

fn prove_file_inner(sealer_id: &String, group: &ProofGroup, sector_size: u64, gpu_parallel: usize) -> std::result::Result<SealerOutput, &'static str> {
    let sector_id = SectorId::from(0);
    let prover_id: [u8; 32] = [1; 32];
    let ticket_bytes: [u8; 32] = [1; 32];
    let seed: [u8; 32] = [1; 32];
    let uuid = Uuid::new_v4().to_simple().to_string();
    let mut sealer_dir = PathBuf::from("sealer_cache");
    sealer_dir.push(uuid.clone());
    let mut cache_path = sealer_dir.clone();
    cache_path.push("cache");
    if !cache_path.exists() {
        create_dir_all(&cache_path).unwrap();
    }
    let mut sealed_path = sealer_dir.clone();
    sealed_path.push("sealed");

    let mut prover: FileProver;
    match sector_size {
        8388608 => {
            let registered_proof = RegisteredSealProof::StackedDrg8MiBV1_1;
            prover = FileProver{
                registered_proof,
                group: group.clone(),
                cache_path,
                sealed_path,
                sector_size,
                seed,
                ticket_bytes,
                prover_id,
                sector_id,
                comm_d: [0; 32],
                comm_r: [0; 32],
                labels: Labels::StackedDrg8MiBV1(RawLabels::new(Vec::new())),
                config: filecoin_proofs_v1::StoreConfig::new("", "", 0),
                piece_infos: Vec::new(),
                vanilla_proofs: VanillaSealProof::StackedDrg8MiBV1(Vec::new()),
                replica_id: PoseidonDomain::default(),
            };
        },
        536870912 => {
            let registered_proof = RegisteredSealProof::StackedDrg512MiBV1_1;
            prover = FileProver{
                registered_proof,
                group: group.clone(),
                cache_path,
                sealed_path,
                sector_size,
                seed,
                ticket_bytes,
                prover_id,
                sector_id,
                comm_d: [0; 32],
                comm_r: [0; 32],
                labels: Labels::StackedDrg512MiBV1(RawLabels::new(Vec::new())),
                config: filecoin_proofs_v1::StoreConfig::new("", "", 0),
                piece_infos: Vec::new(),
                vanilla_proofs: VanillaSealProof::StackedDrg512MiBV1(Vec::new()),
                replica_id: PoseidonDomain::default(),
            };
        },
        _ => {
            panic!("not supported");
        }
    }

    if let Err(e) = prover.pre_commit1() {
        return Err(e)
    }

    let mut flg = true;
    let ten_millis = Duration::from_millis(10);
    // while flg {
    //     {
    //         let mut gpu_util = GPU_UTIL.lock().unwrap();
    //         if *gpu_util < gpu_parallel {
    //             *gpu_util += 1;
    //             flg = false;
    //         }
    //     }
    //     if !flg {
    //         break;
    //     }
    //     std::thread::sleep(ten_millis);
    // }
    // flg = true;
    prover.pre_commit2();
    // {
    //     let mut gpu_util = GPU_UTIL.lock().unwrap();
    //     *gpu_util -= 1;
    // }
    prover.commit1();

    while flg {
        {
            let mut gpu_util = GPU_UTIL.lock().unwrap();
            if *gpu_util < gpu_parallel {
                *gpu_util += 1;
                flg = false;
            }
        }
        if !flg {
            break;
        }
        std::thread::sleep(ten_millis);
    }
    let proof = prover.commit2();
    {
        let mut gpu_util = GPU_UTIL.lock().unwrap();
        *gpu_util -= 1;
    }

    let unsealed_id = bytes_2_cid(prover.comm_d);
    let sealed_id = bytes_2_cid(prover.comm_r);
    let sealer_output = SealerOutput {
        sector_size,
        sealer_id: sealer_id.clone(),
        num: 1,
        sealed_cid: sealed_id,
        unsealed_cid: unsealed_id,
        proof,
    };
    remove_dir_all(sealer_dir).unwrap();
    Ok(sealer_output)
}

pub fn prove_file(group: ProofGroup, tx: mpsc::UnboundedSender<SealerOutput>, sealer_id: String, sector_size: u64, gpu_parallel: usize, counter: Arc<AtomicBool>) {
    info!("prove thread {} start", sealer_id);
    if let Ok(received) = prove_file_inner(&sealer_id, &group, sector_size, gpu_parallel) {
        tx.send(received).expect("Send Seal failed");
    }
    else {
        info!("File corruption, try recovering");
    }
    info!("prove thread {} finished", sealer_id);
}

pub fn verify_file(proof_resp: ProofResponse) -> bool {
    let sector_id = SectorId::from(0);
    let prover_id: [u8; 32] = [1; 32];
    let ticket_bytes: [u8; 32] = [1; 32];
    let seed: [u8; 32] = [1; 32];
    let registered_proof: RegisteredSealProof;
    match proof_resp.sector_size {
        536870912 => {
            registered_proof = RegisteredSealProof::StackedDrg512MiBV1_1
        },
        8388608 => {
            registered_proof = RegisteredSealProof::StackedDrg8MiBV1_1
        },
        _ => panic!("sector size not supported"),
    };
    let comm_d = cid_2_bytes(proof_resp.block_id);
    let comm_r = cid_2_bytes(proof_resp.sealed_cid);
    let porep = FilePoRep{
        registered_proof,
        comm_d,
        comm_r,
        prover_id,
        sector_id,
        ticket_bytes,
        seed,
        proof: proof_resp.proof.clone(),
    };
    let res = porep_verifier(porep);
    info!("proof {:?}", res);
    res
}
