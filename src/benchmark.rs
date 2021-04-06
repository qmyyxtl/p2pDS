use uuid::Uuid;
use std::collections::{HashMap};
use crate::types::*;
use crate::porep::*;
use crate::{PEERINFO};
use tokio::{sync::mpsc};
use log::info;
use std::time::{SystemTime};
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub async fn bench_prove(parallel_num: usize, gpu_parallel: usize, prove_tx: mpsc::UnboundedSender<SealerOutput>) {
    std::process::Command::new("/bin/bash").arg("kill.sh").spawn().expect("sh command failed to start");
    std::thread::sleep(Duration::from_millis(5000));
    let proof_groups: Vec<ProofGroup>;
    {
        let peer_info = PEERINFO.lock().unwrap();
        proof_groups = peer_info.proof_groups.clone();
    }
    let counter = Arc::new(AtomicBool::new(true));
    let ten_millis = Duration::from_millis(10);
    for proof_group in proof_groups {
        let sector_size: u64 = proof_group.sector_size;
        // let pool = rayon::ThreadPoolBuilder::new().num_threads(parallel_num).build().unwrap();
        std::process::Command::new("/bin/bash").arg("monitor.sh").spawn().expect("sh command failed to start");
        let start = SystemTime::now();
        for _i in 0..1000 {
            // let sealer_id = Uuid::new_v4().to_simple().to_string();
            let thread_id = _i.to_string();
            let tx = prove_tx.clone();
            let ct = Arc::clone(&counter);
            while Arc::strong_count(&counter) > parallel_num + 1 {
                std::thread::sleep(ten_millis);
            }
            let thread_group = proof_group.clone();
            std::thread::spawn(move || prove_file(thread_group, tx, thread_id, sector_size, gpu_parallel, ct));
            // pool.install(move || prove_file(cmd1, tx, thread_id, sector_size, ct));
        }
        let wait_millis = Duration::from_millis(10);
        while Arc::strong_count(&counter) > 1 {
            std::thread::sleep(wait_millis);
        }
        
        let end = SystemTime::now();
        let diff = end
            .duration_since(start)
            .expect("Time went backwards");
        info!("Bench time {:?}", diff);
        std::process::Command::new("/bin/bash").arg("kill.sh").spawn().expect("sh command failed to start");
        break;
    }
    info!("Bench finished");
}