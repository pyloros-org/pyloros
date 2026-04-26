//! Request filtering and pattern matching

mod credentials;
pub mod lfs;
pub mod matcher;
pub mod pack;
pub mod pktline;
pub mod redirect_whitelist;
mod rules;
pub mod sigv4;
pub mod upstream_negotiate;

pub use credentials::CredentialEngine;
pub use matcher::PatternMatcher;
pub use redirect_whitelist::RedirectWhitelist;
pub use rules::{BranchFilter, CompiledRule, FilterEngine, FilterResult, RequestInfo};
