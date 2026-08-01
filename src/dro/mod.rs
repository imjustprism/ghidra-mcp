//! Distilled Nebula3 / Drakensang Online knowledge for MCP agents.
//! Packet tables adapted from DSO-Reconstruction research (see NOTICE).

mod raknet;

pub use raknet::{lookup, overview_markdown, packet_flows_markdown, packet_ids_markdown};
