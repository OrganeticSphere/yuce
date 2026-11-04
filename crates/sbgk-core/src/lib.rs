//! SBGK-P0: a deterministic byte-graph epistemic kernel.
//!
//! Agents stream flat JSONL events; this crate binds quotes to source bytes, resolves entities,
//! checks rule applications, computes the least fixed point with DRed maintenance, erases every
//! agent-local name and commits the result into a content-addressed `bytes[]` container.

// `KernelError` carries the kernel's expected value and repair obligation by value: boxing it would change the public API of
// every fallible call. The rule tables (`(rule, premise ids)` maps) and the frame builder keep their explicit signatures.
#![allow(clippy::result_large_err, clippy::type_complexity, clippy::too_many_arguments)]

pub mod arena;
pub mod audit;
pub mod cdc;
pub mod codec;
pub mod cone;
pub mod container;
pub mod directive;
pub mod engine;
pub mod error;
pub mod hash;
pub mod jcs;
pub mod journal;
pub mod merkle;
pub mod node;
pub mod ontology;
pub mod session;
pub mod swarm;
pub mod wal;

pub use arena::{Arena, ByteAnchor};
pub use cdc::CdcParams;
pub use cone::{project_full, project_minimal_cone};
pub use container::{build_container, merkle_diff, open_session, verify_container, ContainerView};
pub use directive::{analyze as analyze_frontier, emit_batch_frames, emit_batch_frames_live, frontier_json, DirectiveCache, Priority, Targets};
pub use engine::{CanonOp, Engine};
pub use error::{Code, KernelError};
pub use ontology::Ontology;
pub use session::Session;
pub use swarm::{auto_close_ready, LockMode, SwarmConfig, SwarmSession};
pub use wal::reconstruct_at_byte_offset;
