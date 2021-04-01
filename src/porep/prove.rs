use std::fs;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::io::{BufReader};
use super::seal::*;
use super::registry::{RegisteredSealProof};
use tempfile::{NamedTempFile};
pub use filecoin_proofs_v1::types::{
    ChallengeSeed, Commitment, PaddedBytesAmount, PieceInfo, PoStType, ProverId, Ticket,
    UnpaddedByteIndex, UnpaddedBytesAmount, MerkleTreeTrait,
};
pub use filecoin_proofs_v1::{FallbackPoStSectorProof, SnarkProof, VanillaProof, add_piece};
pub use storage_proofs::api_version::ApiVersion;
pub use storage_proofs::parameter_cache::get_verifying_key_data;
pub use storage_proofs::error::Error as StorageProofsError;
pub use storage_proofs::post::election::Candidate;
pub use storage_proofs::sector::{OrderedSectorSet, SectorId};
use filecoin_hashers::{Hasher};

pub struct FilePoRep {
    pub registered_proof: RegisteredSealProof,
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
    pub prover_id: [u8; 32],
    pub sector_id: SectorId,
    pub ticket_bytes: [u8; 32],
    pub seed: [u8; 32],
    pub proof: Vec<u8>,
}

pub struct FileProver {
    pub registered_proof: RegisteredSealProof,
    pub file_path: String,
    pub cache_path: PathBuf,
    pub sealed_path: PathBuf,
    pub sector_size: u64,
    pub seed: [u8; 32],
    pub ticket_bytes: [u8; 32],
    pub prover_id: [u8; 32],
    pub sector_id: SectorId,
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
    pub labels: Labels,
    pub config: filecoin_proofs_v1::StoreConfig,
    pub piece_infos: Vec<PieceInfo>,
    pub vanilla_proofs: VanillaSealProof,
    pub replica_id: <filecoin_proofs_v1::constants::DefaultTreeHasher as Hasher>::Domain,
}

impl FileProver {
    pub fn pre_commit1(&mut self) {
        File::create(self.sealed_path.clone()).unwrap();
        let sector_size_unpadded_bytes_amount = self.sector_size - (self.sector_size / 128);

        let mut tmp_file = self.cache_path.clone();
        let name = PathBuf::from(&self.file_path);
        let name = name.file_name().unwrap();
        tmp_file.push(name);
        fs::copy(&self.file_path, &tmp_file).unwrap();

        let f_data = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tmp_file).unwrap();
        // Zero-pad the data to the requested size by extending the underlying file if needed.
        f_data.set_len(sector_size_unpadded_bytes_amount as u64).unwrap();
        let source = BufReader::new(File::open(&tmp_file).expect("File open failed"));

        let piece_size =
            UnpaddedBytesAmount::from(PaddedBytesAmount(self.sector_size));
        let meta = generate_piece_commitment(
            self.registered_proof.into(),
            source,
            piece_size,
        ).unwrap();
        let mut source = File::open(&tmp_file).expect("File open failed");
        let commitment = meta.commitment;
        let mut staged_sector_file = NamedTempFile::new().unwrap();
        add_piece(
            &mut source,
            &mut staged_sector_file,
            piece_size,
            &[],
        ).unwrap();
        let piece_info = PieceInfo::new(commitment, piece_size).unwrap();
        self.piece_infos = vec![piece_info];
        let p1result = seal_pre_commit_phase1(
            self.registered_proof,
            self.cache_path.clone(),
            staged_sector_file.path(),
            self.sealed_path.clone(),
            self.prover_id,
            self.sector_id,
            self.ticket_bytes,
            &self.piece_infos,
        ).unwrap();
        self.comm_d = p1result.comm_d;
        self.config = p1result.config;
        self.labels = p1result.labels;
    }

    pub fn pre_commit2(&mut self) {
        let phase1_output = SealPreCommitPhase1Output {
            registered_proof: self.registered_proof,
            labels: self.labels.clone(),
            config: self.config.clone(),
            comm_d: self.comm_d,
        };
        let phase2_output = seal_pre_commit_phase2(
            phase1_output,
            self.cache_path.clone(),
            self.sealed_path.clone(),
        ).unwrap();
        self.comm_r = phase2_output.comm_r;
    }

    pub fn commit1(&mut self) {
        let pc = SealPreCommitPhase2Output {
            registered_proof: self.registered_proof,
            comm_r: self.comm_r,
            comm_d: self.comm_d
        };
        let phase1_output = seal_commit_phase1::<PathBuf>(
            self.cache_path.clone(),
            self.sealed_path.clone(),
            self.prover_id,
            self.sector_id,
            self.ticket_bytes,
            self.seed,
            pc,
            &self.piece_infos,
        ).unwrap();
        self.vanilla_proofs = phase1_output.vanilla_proofs;
        self.replica_id = phase1_output.replica_id;
    }

    pub fn commit2(&mut self) -> Vec<u8> {
        let phase1_output = SealCommitPhase1Output {
            registered_proof: self.registered_proof,
            vanilla_proofs: self.vanilla_proofs.clone(),
            comm_r: self.comm_r,
            comm_d: self.comm_d,
            replica_id: self.replica_id,
            seed: self.seed,
            ticket: self.ticket_bytes,
        };
        let phase2_output = seal_commit_phase2(
            phase1_output,
            self.prover_id,
            self.sector_id,
        ).unwrap();
        phase2_output.proof
    }
}

pub fn porep_verifier(porep: FilePoRep) -> bool {
    let verify_result = verify_seal(
        porep.registered_proof,
        porep.comm_r,
        porep.comm_d,
        porep.prover_id,
        porep.sector_id,
        porep.ticket_bytes,
        porep.seed,
        &porep.proof,
    ).unwrap();
    verify_result
}