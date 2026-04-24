//! Approvals feature: runtime rule approvals requested by agents inside the sandbox.
//!
//! See `devdocs/design/approvals.md` for the product-level design and
//! `devdocs/SPEC.md#approvals` for user-facing semantics.
//!
//! The feature is opt-in: activated by the `[approvals]` section in the
//! config file. When absent, `ApprovalManager` is never constructed and the
//! agent API at `https://pyloros.internal/` returns 404.

pub mod api;
pub mod dashboard;
pub mod state;
pub mod storage;
pub mod types;

pub use state::ApprovalManager;
pub use types::{
    ApprovalDecision, ApprovalError, ApprovalRequest, ApprovalStatus, DecisionAction, Lifetime,
    NotifierEvent, TriggeredBy,
};
