#![allow(dead_code)]
use std::path::PathBuf;

use anyhow::{ensure, Result};
use storage_proofs::api_version::ApiVersion;
use filecoin_proofs_v1::types::{
    MerkleTreeTrait, PoRepConfig, PoRepProofPartitions, SectorSize,
};
use filecoin_proofs_v1::{constants, with_shape};
use serde::{Deserialize, Serialize};

/// Available seal proofs.
/// Enum is append-only: once published, a `RegisteredSealProof` value must never change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisteredSealProof {
    StackedDrg2KiBV1,
    StackedDrg8MiBV1,
    StackedDrg512MiBV1,
    StackedDrg32GiBV1,
    StackedDrg64GiBV1,

    StackedDrg2KiBV1_1,
    StackedDrg8MiBV1_1,
    StackedDrg512MiBV1_1,
    StackedDrg32GiBV1_1,
    StackedDrg64GiBV1_1,
}

// Hack to delegate to self config types.
macro_rules! self_shape {
    ($name:ident, $selfty:ty, $self:expr, $ret:ty) => {{
        fn $name<Tree: 'static + MerkleTreeTrait>(s: $selfty) -> Result<$ret> {
            s.as_v1_config().$name::<Tree>()
        }

        with_shape!(u64::from($self.sector_size()), $name, $self)
    }};
}

impl RegisteredSealProof {
    /// Return the version for this proof.
    pub fn version(self) -> ApiVersion {
        use RegisteredSealProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
            | StackedDrg64GiBV1 => ApiVersion::V1_0_0,
            StackedDrg2KiBV1_1 | StackedDrg8MiBV1_1 | StackedDrg512MiBV1_1
            | StackedDrg32GiBV1_1 | StackedDrg64GiBV1_1 => ApiVersion::V1_1_0,
        }
    }

    /// Return the major version for this proof.
    pub fn major_version(self) -> u64 {
        self.version().as_semver().major
    }

    /// Return the minor version for this proof.
    pub fn minor_version(self) -> u64 {
        self.version().as_semver().minor
    }

    /// Return the patch version for this proof.
    pub fn patch_version(self) -> u64 {
        self.version().as_semver().patch
    }

    /// Return the sector size for this proof.
    pub fn sector_size(self) -> SectorSize {
        use RegisteredSealProof::*;
        let size = match self {
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 => constants::SECTOR_SIZE_2_KIB,
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 => constants::SECTOR_SIZE_8_MIB,
            StackedDrg512MiBV1 | StackedDrg512MiBV1_1 => constants::SECTOR_SIZE_512_MIB,
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 => constants::SECTOR_SIZE_32_GIB,
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 => constants::SECTOR_SIZE_64_GIB,
        };
        SectorSize(size)
    }

    /// Return the number of partitions for this proof.
    pub fn partitions(self) -> u8 {
        use RegisteredSealProof::*;
        match self {
            StackedDrg2KiBV1 | StackedDrg2KiBV1_1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_2_KIB)
                .expect("invalid sector size"),
            StackedDrg8MiBV1 | StackedDrg8MiBV1_1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_8_MIB)
                .expect("invalid sector size"),
            StackedDrg512MiBV1 | StackedDrg512MiBV1_1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_512_MIB)
                .expect("invalid sector size"),
            StackedDrg32GiBV1 | StackedDrg32GiBV1_1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_32_GIB)
                .expect("invalid sector size"),
            StackedDrg64GiBV1 | StackedDrg64GiBV1_1 => *constants::POREP_PARTITIONS
                .read()
                .expect("porep partitions read error")
                .get(&constants::SECTOR_SIZE_64_GIB)
                .expect("invalid sector size"),
        }
    }

    pub fn single_partition_proof_len(self) -> usize {
        use RegisteredSealProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
            | StackedDrg64GiBV1 | StackedDrg2KiBV1_1 | StackedDrg8MiBV1_1
            | StackedDrg512MiBV1_1 | StackedDrg32GiBV1_1 | StackedDrg64GiBV1_1 => {
                filecoin_proofs_v1::SINGLE_PARTITION_PROOF_LEN
            }
        }
    }

    fn nonce(self) -> u64 {
        #[allow(clippy::match_single_binding)]
        match self {
            // If we ever need to change the nonce for any given RegisteredSealProof, match it here.
            _ => 0,
        }
    }

    fn porep_id(self) -> [u8; 32] {
        let mut porep_id = [0; 32];
        let registered_proof_id = self as u64;
        let nonce = self.nonce();

        porep_id[0..8].copy_from_slice(&registered_proof_id.to_le_bytes());
        porep_id[8..16].copy_from_slice(&nonce.to_le_bytes());
        porep_id
    }

    pub fn as_v1_config(self) -> PoRepConfig {
        use RegisteredSealProof::*;

        match self {
            StackedDrg2KiBV1 | StackedDrg8MiBV1 | StackedDrg512MiBV1 | StackedDrg32GiBV1
            | StackedDrg64GiBV1 => {
                assert_eq!(self.version(), ApiVersion::V1_0_0);
                PoRepConfig {
                    sector_size: self.sector_size(),
                    partitions: PoRepProofPartitions(self.partitions()),
                    porep_id: self.porep_id(),
                    api_version: self.version(),
                }
            }
            StackedDrg2KiBV1_1 | StackedDrg8MiBV1_1 | StackedDrg512MiBV1_1
            | StackedDrg32GiBV1_1 | StackedDrg64GiBV1_1 => {
                assert_eq!(self.version(), ApiVersion::V1_1_0);
                PoRepConfig {
                    sector_size: self.sector_size(),
                    partitions: PoRepProofPartitions(self.partitions()),
                    porep_id: self.porep_id(),
                    api_version: self.version(),
                }
            } // _ => panic!("Can only be called on V1 configs"),
        }
    }

    /// Returns the circuit identifier.
    pub fn circuit_identifier(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 => {
                self_shape!(get_cache_identifier, RegisteredSealProof, self, String)
            }
        }
    }

    pub fn cache_verifying_key_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 => self_shape!(
                get_cache_verifying_key_path,
                RegisteredSealProof,
                self,
                PathBuf
            ),
        }
    }

    pub fn cache_params_path(self) -> Result<PathBuf> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 => {
                self_shape!(get_cache_params_path, RegisteredSealProof, self, PathBuf)
            }
        }
    }

    pub fn verifying_key_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 => {
                let id = self.circuit_identifier()?;
                let params = storage_proofs::parameter_cache::get_verifying_key_data(&id);
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params
                    .expect("verifying key cid params failure")
                    .cid
                    .clone())
            }
        }
    }

    pub fn params_cid(self) -> Result<String> {
        match self.version() {
            ApiVersion::V1_0_0 | ApiVersion::V1_1_0 => {
                let id = self.circuit_identifier()?;
                let params = storage_proofs::parameter_cache::get_parameter_data(&id);
                ensure!(params.is_some(), "missing params for {}", &id);

                Ok(params.expect("param cid failure").cid.clone())
            }
        }
    }
}
