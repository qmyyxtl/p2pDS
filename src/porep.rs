use tokio::{sync::mpsc};
use std::fs::{create_dir_all, remove_dir_all, File, OpenOptions};
use std::path::PathBuf;
use log::{info};
use std::io::{BufReader};
use uuid::Uuid;
use std::fs;
use base64;
use std::sync::Mutex;
use std::time::{SystemTime, Duration};
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
use crate::{STORAGE_BLOCK_PATH, CPU_CNT};
use sysinfo::{ProcessExt, SystemExt};

lazy_static! {
    static ref GPU_UTIL: Mutex<usize> = {
        let p: usize = 0;
        Mutex::new(p)
    };

    pub static ref CWND: Mutex<usize> = {
        let cwnd: usize = 1;
        Mutex::new(cwnd)
    };

    pub static ref NTHREADS: Mutex<usize> = {
        let nthreads: usize = 0;
        Mutex::new(nthreads)
    };

    pub static ref MP_PHASES: Mutex<usize> = {
        let cnt: usize = 0;
        Mutex::new(cnt)
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
        34359738368 => {
            registered_proof = RegisteredSealProof::StackedDrg32GiBV1_1
        },
        _ => panic!("sector size not supported"),
    };

    let uuid = Uuid::new_v4().to_simple().to_string();
    let mut sealer_dir = PathBuf::from("./test/sealer_cache");
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
        34359738368 => {
            registered_proof = RegisteredSealProof::StackedDrg32GiBV1_1
        },
        _ => panic!("sector size not supported"),
    };

    let uuid = Uuid::new_v4().to_simple().to_string();
    let mut sealer_dir = PathBuf::from("./test/sealer_cache");
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
    let cpu_cnt = unsafe { CPU_CNT };
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
        34359738368 => {
            registered_proof = RegisteredSealProof::StackedDrg32GiBV1_1
        },
        _ => panic!("sector size not supported"),
    };

    let uuid = Uuid::new_v4().to_simple().to_string();
    let mut sealer_dir = PathBuf::from("./test/sealer_cache");
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

    let start = SystemTime::now();
    
    prover.pre_commit1().unwrap();
    prover.pre_commit2(8);
    prover.commit1(8);
    let proof = prover.commit2(0);
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
    let end = SystemTime::now();
    let diff = end
        .duration_since(start)
        .expect("Time went backwards");
    info!("Bench time {:?}", diff);

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
    let mut sealer_dir = PathBuf::from("./test/sealer_cache");
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
        34359738368 => {
            let registered_proof = RegisteredSealProof::StackedDrg32GiBV1_1;
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
                labels: Labels::StackedDrg32GiBV1(RawLabels::new(Vec::new())),
                config: filecoin_proofs_v1::StoreConfig::new("", "", 0),
                piece_infos: Vec::new(),
                vanilla_proofs: VanillaSealProof::StackedDrg32GiBV1(Vec::new()),
                replica_id: PoseidonDomain::default(),
            };
        },
        _ => {
            panic!("not supported");
        }
    }
    let ten_millis = Duration::from_millis(100);

    loop {
        {
            let cwnd = CWND.lock().unwrap();
            let mut n_thread = NTHREADS.lock().unwrap();
            if *n_thread < *cwnd {
                *n_thread += 1;
                break;
            }
        }
        std::thread::sleep(ten_millis);
    }
    info!("thread {} p1 start", sealer_id);
    if let Err(e) = prover.pre_commit1() {
        let mut n_thread = NTHREADS.lock().unwrap();
        *n_thread -= 1;
        return Err(e)
    }
    info!("thread {} p1 finish", sealer_id);
    {
        let mut n_thread = NTHREADS.lock().unwrap();
        *n_thread -= 1;
    }

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
    let mut num_threads = 0;
    loop {
        {
            let cwnd = CWND.lock().unwrap();
            let mut n_thread = NTHREADS.lock().unwrap();
            if *n_thread < *cwnd {
                num_threads = *cwnd - *n_thread;
                *n_thread = *cwnd;
                break;
            }
        }
        std::thread::sleep(ten_millis);
    }
    // loop {
    //     {
    //         let mut cnt = MP_PHASES.lock().unwrap();
    //         if *cnt < 4 {
    //             *cnt += 1;
    //             break;
    //         }
    //     }
    //     std::thread::sleep(ten_millis);
    // }
    info!("thread {} p2 start", sealer_id);
    prover.pre_commit2(48);
    info!("thread {} p2 finish", sealer_id);
    {
        let mut n_thread = NTHREADS.lock().unwrap();
        *n_thread -= num_threads;
    }
    num_threads = 0;
    // {
    //     let mut gpu_util = GPU_UTIL.lock().unwrap();
    //     *gpu_util -= 1;
    // }

    loop {
        {
            let cwnd = CWND.lock().unwrap();
            let mut n_thread = NTHREADS.lock().unwrap();
            if *n_thread < *cwnd {
                num_threads = *cwnd - *n_thread;
                *n_thread = *cwnd;
                break;
            }
        }
        std::thread::sleep(ten_millis);
    }
    info!("thread {} c1 start", sealer_id);
    prover.commit1(48);
    info!("thread {} c1 finish", sealer_id);
    // {
    //     let mut cnt = MP_PHASES.lock().unwrap();
    //     *cnt -= 1;
    // }
    {
        let mut n_thread = NTHREADS.lock().unwrap();
        *n_thread -= num_threads;
    }
    num_threads = 0;

    if gpu_parallel == 0{
        loop {
            {
                let cwnd = CWND.lock().unwrap();
                let mut n_thread = NTHREADS.lock().unwrap();
                if *n_thread < *cwnd {
                    num_threads = *cwnd - *n_thread;
                    *n_thread = *cwnd;
                    break;
                }
            }
            std::thread::sleep(ten_millis);
        }
    }
    else {
        loop {
            {
                let mut gpu_util = GPU_UTIL.lock().unwrap();
                if *gpu_util < gpu_parallel {
                    *gpu_util += 1;
                    break;
                }
            }
            std::thread::sleep(ten_millis);
        }
    }

    info!("thread {} c2 start", sealer_id);
    let proof = prover.commit2(num_threads);
    info!("thread {} c2 finish", sealer_id);
    if gpu_parallel == 0{
        let mut n_thread = NTHREADS.lock().unwrap();
        *n_thread -= num_threads;
        num_threads = 0;
    }
    else {
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
        34359738368 => {
            registered_proof = RegisteredSealProof::StackedDrg32GiBV1_1
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
