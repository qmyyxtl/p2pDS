use std::fs::File;
use std::io::prelude::*;
use std::sync::Mutex;
use std::collections::{HashMap};
use log::{info};
use tokio::{fs};
use crate::porep::{get_unsealed_id, get_group_unsealed_id};

use crate::types::*;
use crate::STORAGE_FILE_PATH;
use crate::STORAGE_BLOCK_PATH;
use crate::{CODE_M, PEERINFO};

lazy_static! {
    pub static ref PENDING_FILES: Mutex<HashMap<String, TempFile>> = {
        let m: HashMap<String, TempFile> = HashMap::new();
        Mutex::new(m)
    };    
}

pub async fn store_file_block(uuid: String, vec: Vec<u8>) -> String {
    let mut path = STORAGE_BLOCK_PATH.to_string();
    path.push_str(&uuid);
    save_file(&vec, &uuid, STORAGE_BLOCK_PATH).unwrap();
    let sector_size: u64;
    if vec.len() > 8323072 {
        sector_size = 536870912
    } else {
        sector_size = 8388608
    }
    let output: String = get_unsealed_id(&path, sector_size).await;
    let mut rename_path = STORAGE_BLOCK_PATH.to_string();
    rename_path.push_str(&output);
    fs::rename(path, rename_path).await.unwrap();
    output
}

pub async fn read_block_data(block_id: String) -> std::result::Result<(DataBlock, Vec<u8>), &'static str> {
    let content = fs::read(STORAGE_FILE_PATH).await.unwrap();
    let result: PeerMetadata = serde_json::from_slice(&content).unwrap();
    let some_block = result.data_blocks.get(&block_id);
    info!("{:?}", block_id);
    match some_block {
        Some(b) => {
            if b.local {
                let mut path = STORAGE_BLOCK_PATH.to_string();
                path.push_str(&b.path.clone());
                let file_bytes=fs::read(path).await.unwrap();
                Ok((b.clone(), file_bytes))
            } else {
                Err("Not local block")
            }
        }
        None => Err("no such block")
    }
}

pub fn unpadding(bytes: Vec<u8>) -> Vec<u8> {
    let padding: u8 = bytes.last().unwrap().clone();
    let unpadded_bytes = bytes[..bytes.len()-usize::from(padding)].to_vec();
    unpadded_bytes
}

pub fn save_file(file_bytes: &Vec<u8>, output_file: &str, parent: &str) -> std::io::Result<()> {
    let mut pos = 0;
    let mut path = parent.to_string();
    path.push_str(output_file);
    let mut buffer = File::create(path)?;
    while pos < file_bytes.len() {
        let bytes_written = buffer.write(&file_bytes[pos..])?;
        pos += bytes_written;
    }
    Ok(())
}

pub fn merge(byte_vecs:&mut Vec<Vec<u8>>, num: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::new();
    for i in 0..num {
        vec.append(&mut byte_vecs[i]);
    }
    vec
}

pub async fn read_file(fname: &str) -> Result<Vec<u8>> {
    let mut file_bytes=fs::read(fname).await?;
    let metadata = fs::metadata(fname).await?;
    let mut padding: u8 = (u64::from(CODE_M) - metadata.len() % u64::from(CODE_M)) as u8;
    // println!("{:?}", metadata.len());
    if padding < 1 {
        padding += CODE_M;
    }
    for _i in 0..padding - 1 {
        file_bytes.push(0);
    }
    // let padding_b = format!("{:b}", padding);
    file_bytes.push(padding);
    Ok(file_bytes)
}

pub fn extract_block(resp: BlockResponse) {
    let mut map = PENDING_FILES.lock().unwrap();
    let ft = map.get_mut(&resp.file_id).unwrap();
    let seq: usize = *ft.block_ids.get(&resp.block_id).unwrap();
    let bv = ft.block_vecs.get_mut(seq).unwrap();
    for by in resp.data.into_iter() {
        bv.push(by);
    }
    ft.block_ids.remove(&resp.block_id.to_string());
    if ft.block_ids.len() == 0 {
        let padded: Vec<u8> = merge(&mut ft.block_vecs, usize::from(CODE_M));
        let unpadded: Vec<u8> = unpadding(padded);
        save_file(&unpadded, &ft.file_name, "./extract/").unwrap();
        map.remove(&resp.file_id);
    }
}

pub fn recover_node(block_id: &str) -> bool {
    info!("Recovering block {}", block_id);
    // let p = PEERINFO.lock().unwrap();
    // let mut block_info: &DataBlock;
    // for block in &p.data_blocks {
    //     if block.block_id == block_id {
    //         block_info = block;
    //     }
    // }
    // let block_size = block_info.size;
    // let mut vec: Vec<u8> = vec![0; block_size];
    true
}

pub fn add_to_prove_group(blocks: &mut Vec<DataBlock>, peer_info: &mut PeerMetadata) -> std::result::Result<(), &'static str>{
    let proof_groups = &mut peer_info.proof_groups;
    let mut block_head: &DataBlock = &blocks[0];
    let mut block_updated = false;
    for proof_group in proof_groups {
        let block_size = block_head.size as u64;
        if block_size + proof_group.size <= proof_group.unpadded_size {
            proof_group.size += block_size;
            proof_group.blocks.push(block_head.block_id.clone());
            blocks.remove(0);
            if blocks.len() == 0 {
                break;
            }
            block_head = &blocks[0];
            block_updated = true;
        } else {
            if block_updated {
                proof_group.unsealed_cid = get_group_unsealed_id(&proof_group);
            }
        }
    }
    if blocks.len() > 0 {
        let proof_groups = &mut peer_info.proof_groups;
        let mut new_group = ProofGroup {
            unsealed_cid: String::new(),
            sector_size: 536870912,
            unpadded_size: 532676608,
            size: 0,
            blocks: Vec::new(),
        };
        for block in blocks {
            new_group.size += block.size as u64;
            new_group.blocks.push(block.block_id.clone());
        }
        new_group.unsealed_cid = get_group_unsealed_id(&new_group);
        proof_groups.push(new_group);
    }
    Ok(())
}
