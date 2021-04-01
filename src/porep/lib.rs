#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::too_many_arguments)]
//requires nightly, or later stable version
//#![warn(clippy::unwrap_used)]

pub mod post;
pub mod seal;
pub mod prove;

mod registry;

pub use crate::porep::registry::{RegisteredSealProof};
pub use crate::porep::types::{PrivateReplicaInfo, PublicReplicaInfo};
pub use prove::file_porep;

pub use storage_proofs::api_version::ApiVersion;
pub use storage_proofs::error::Error as StorageProofsError;
pub use storage_proofs::fr32;
pub use storage_proofs::post::election::Candidate;
pub use storage_proofs::sector::{OrderedSectorSet, SectorId};
pub use filecoin_proofs_v1::types::{
    ChallengeSeed, Commitment, PaddedBytesAmount, PieceInfo, PoStType, ProverId, Ticket,
    UnpaddedByteIndex, UnpaddedBytesAmount,
};
pub use filecoin_proofs_v1::{FallbackPoStSectorProof, SnarkProof, VanillaProof};
