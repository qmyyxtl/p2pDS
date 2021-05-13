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
use std::fs::File;
use std::io::prelude::*;
use sysinfo::{ProcessorExt, ProcessExt, SystemExt, System};
use crate::porep::{CWND, NTHREADS};
use crate::{CPU_CNT};

fn timer(parallel_num: usize) {
    let mut s = System::new_all();
    let cpu_cnt = unsafe { CPU_CNT };
    let mut ccnt = 0;
    let mut icnt = 0;
    let mut increase_n = 1;
    let ten_millis = Duration::from_millis(100);
    let mut stat_file = File::create("nthreads.txt").unwrap();
    let mut time_cnt = 0;
    let mut n_thread = parallel_num;
    let mut self_cpu: f32 = 0.0;
    let start = SystemTime::now();
    loop {
        std::thread::sleep(ten_millis);
        s.refresh_all();
        for process in s.get_process_by_name("DS-porep") {
            self_cpu = process.cpu_usage();
            // info!("{:?}", self_cpu);
        }
        let cpu_util = s.get_global_processor_info().get_cpu_usage() * (cpu_cnt as f32);
        let other_cpu_util = cpu_util - self_cpu;
        // info!("{:?}", other_cpu_util);
        if time_cnt == 9 {
            time_cnt = 0;
            let t = SystemTime::now().duration_since(start).unwrap().as_secs();
            write!(stat_file, "{} {} {}\n", t, other_cpu_util, n_thread).unwrap();
        }
        else {
            time_cnt += 1;
        }
        if cpu_util > 90.0 * (cpu_cnt as f32) && other_cpu_util > 200.0 {
            icnt = 0;
            if ccnt == 20 {
                ccnt = 0;
                increase_n = 1;
                if n_thread > 1 {
                    n_thread /= 2;
                    {
                        let mut cwnd = CWND.lock().unwrap();
                        *cwnd = n_thread;
                    }
                }
            }
            else {
                ccnt += 1;
            }
        }
        else {
            ccnt = 0;
            if icnt == 50 {
                icnt = 0;
                if n_thread < cpu_cnt {
                    n_thread += increase_n;
                    increase_n *= 2;
                    {
                        let mut cwnd = CWND.lock().unwrap();
                        *cwnd = n_thread;
                    }
                }
                else {
                    n_thread = cpu_cnt;
                    {
                        let mut cwnd = CWND.lock().unwrap();
                        *cwnd = n_thread;
                    }
                }
            } else {
                icnt += 1;
            }
        }
    }
}

pub async fn bench_prove(parallel_num: usize, gpu_parallel: usize, prove_tx: mpsc::UnboundedSender<SealerOutput>) {
    if gpu_parallel == 0 {
        std::env::set_var("BELLMAN_NO_GPU", "1");
    }
    std::process::Command::new("/bin/bash").arg("kill.sh").spawn().expect("sh command failed to start");
    std::thread::sleep(Duration::from_millis(5000));
    let proof_groups: Vec<ProofGroup>;
    {
        let peer_info = PEERINFO.lock().unwrap();
        proof_groups = peer_info.proof_groups.clone();
    }
    let counter = Arc::new(AtomicBool::new(true));
    let ten_millis = Duration::from_millis(100);
    let mut n_thread = parallel_num;
    let thread_n = parallel_num;
    {
        let mut cwnd = CWND.lock().unwrap();
        *cwnd = n_thread;
    }
    std::thread::spawn(move || timer(thread_n));
    for proof_group in proof_groups {
        let sector_size: u64 = proof_group.sector_size;
        // let pool = rayon::ThreadPoolBuilder::new().num_threads(n_thread).build().unwrap();
        std::process::Command::new("/bin/bash").arg("monitor.sh").spawn().expect("sh command failed to start");
        let start = SystemTime::now();
        for _i in 0..256 {
            // let sealer_id = Uuid::new_v4().to_simple().to_string();
            let thread_id = _i.to_string();
            let tx = prove_tx.clone();
            let ct = Arc::clone(&counter);
            while Arc::strong_count(&counter) > n_thread + 1 {
                std::thread::sleep(ten_millis);
                {
                    let cwnd = CWND.lock().unwrap();
                    n_thread = *cwnd;
                }
                // info!("{:?}", n_thread);
            }
            let thread_group = proof_group.clone();
            // prove_file(thread_group, tx, thread_id, sector_size, gpu_parallel, ct);
            std::thread::spawn(move || prove_file(thread_group, tx, thread_id, sector_size, gpu_parallel, ct));
            // pool.spawn(move || prove_file(thread_group, tx, thread_id, sector_size, gpu_parallel, ct));
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