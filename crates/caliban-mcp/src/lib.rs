//! MCP integration (docs/research/04-agent-orchestration.md §4 and §5; P3 M4).
//!
//! Caliban is the MCP **client** of its tenants' tool servers, which are untrusted. This crate
//! holds the parts that are enforced in Rust, never in prompts:
//! - [`manifest`]: tool manifests and their pins (`mcp://server/tool#sha256:...`);
//! - [`scan`]: the injection scan of descriptions and schemas, run when a manifest is approved;
//! - [`egress`]: only registered server URLs are reachable; each connection resolves the host
//!   once, checks every address and pins the one it uses (no DNS rebinding); link-local and cloud
//!   metadata addresses are always refused;
//! - [`token`]: short-lived, audience-bound tokens minted per call and signed by a Caliban key
//!   (clients' tokens are never passed through), and the JWKS servers verify them with;
//! - [`client`]: the Streamable HTTP client (the official `rmcp` SDK) that lists a server's tools
//!   and calls one.
//!
//! **No stdio servers.** MCP also defines a stdio transport where the client spawns the server as
//! a child process. Caliban does not support it: spawning processes from the gateway would put
//! arbitrary tenant-supplied executables inside the data plane's trust boundary (its keyring, its
//! network position, its memory), with no egress control. Tool servers are reached over
//! Streamable HTTP only, like any other untrusted network service.
//!
//! TODO(P3 M5): the `rmcp` server exposing published nodes as tools. TODO(P3 M8): A2A.

pub mod client;
pub mod egress;
pub mod manifest;
pub mod scan;
#[cfg(feature = "test-server")]
pub mod testing;
pub mod token;

pub use manifest::ToolManifest;
