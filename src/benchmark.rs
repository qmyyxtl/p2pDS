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
    let mut p: HashMap<String, DataBlock> = HashMap::new();
    {
        let tmp = PEERINFO.lock().unwrap();
        p = tmp.data_blocks.clone();
    }
    let counter = Arc::new(AtomicBool::new(true));
    for (block_id, block) in p.iter() {
        let mut sector_size: u64 = 8388608;
        if block.size > 8323072 {
            sector_size = 536870912;
        }
        let pool = rayon::ThreadPoolBuilder::new().num_threads(parallel_num).build().unwrap();
        if block.local == false {
            continue;
        }
        std::process::Command::new("/bin/bash").arg("monitor.sh").spawn().expect("sh command failed to start");
        let start = SystemTime::now();
        let ten_millis = Duration::from_millis(10);
        for _i in 0..1000 {
            // let sealer_id = Uuid::new_v4().to_simple().to_string();
            let sealer_id = _i.to_string();
            let cmd1: String = block_id.to_string().clone();
            let thread_id = sealer_id.clone();
            let tx = prove_tx.clone();
            let ct = Arc::clone(&counter);
            while Arc::strong_count(&counter) > parallel_num + 1 {
                std::thread::sleep(ten_millis);
            }
            std::thread::spawn(move || prove_file(cmd1, tx, thread_id, sector_size, gpu_parallel, ct));
            // pool.install(move || prove_file(cmd1, tx, thread_id, sector_size, ct));
        }
        let wait_millis = Duration::from_millis(100);
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