use std::fmt;

use crate::capability::BackendKind;
use crate::ownership::ResourceId;

/// Crate-wide result type.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The typed error model of `osdns`.
///
/// Variants carry structured context (backend, resource) instead of collapsing
/// everything into strings. Platform-specific detail lives in the message
/// fields of each variant.
///
/// # Operational semantics
///
/// - [`Error::Unsupported`]: nothing was mutated. The backend cannot
///   represent the request. Do not retry without changing the configuration;
///   probe [`Capabilities`](crate::Capabilities) first.
/// - [`Error::RequiresPrivilege`]: nothing was mutated. Re-run with elevated
///   privileges; `osdns` never escalates on its own.
/// - [`Error::BackendUnavailable`]: nothing was mutated. The backend or an OS
///   resource it depends on is missing. The caller may retry later or select
///   a different backend.
/// - [`Error::Timeout`]: the operation (usually lock acquisition) exceeded its
///   deadline. Nothing was mutated by this call, but another lease may hold
///   the resource; retry with backoff or abandon.
/// - [`Error::Conflict`]: nothing was mutated by this call. Another lease or
///   an unresolved journal blocks ownership; see [`ConflictReason`]. A lease
///   that reports this remains usable.
/// - [`Error::ExternalModification`]: nothing was mutated. Current state
///   matches neither the applied nor the original snapshot. The lease remains
///   usable: retry [`Lease::restore`](crate::Lease::restore), or call
///   [`Lease::abandon`](crate::Lease::abandon) to leave external state in
///   place. Journal state is retained for recovery.
/// - [`Error::InvalidConfig`]: nothing was mutated. The request failed
///   validation before any lock, journal write, or OS call; fix the input.
/// - [`Error::VerificationFailed`]: the mutation was applied but read-back did
///   not match. A rollback to the captured state was attempted (best-effort)
///   and the journal record was kept, so [`DnsManager::recover_stale`](crate::DnsManager::recover_stale)
///   can finish the work. The lease remains usable.
/// - [`Error::JournalCorrupt`]: no mutation was attempted. The call fails
///   closed; inspect or clear the state directory manually.
/// - [`Error::Io`] / [`Error::Platform`]: the effect is backend-dependent.
///   Assume the state may have changed, keep the lease, and use read-back
///   ([`DnsManager::snapshot`](crate::DnsManager::snapshot)) or recovery to
///   determine the outcome before retrying.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The active backend cannot represent or perform the requested operation.
    ///
    /// Nothing was mutated. Check [`Capabilities`](crate::Capabilities) before
    /// retrying with a different configuration.
    #[error("unsupported operation on {backend}: {reason}")]
    Unsupported {
        /// The backend that rejected the operation.
        backend: BackendKind,
        /// Why the operation is not supported.
        reason: String,
    },
    /// The current process lacks the privileges required for the operation.
    ///
    /// Nothing was mutated. `osdns` never elevates privileges on its own;
    /// re-run with elevated privileges.
    #[error("operation requires elevated privileges: {0}")]
    RequiresPrivilege(String),
    /// The backend or an OS resource it depends on is not available.
    ///
    /// Nothing was mutated. Retry later or select a different backend.
    #[error("backend is unavailable: {0}")]
    BackendUnavailable(String),
    /// A bounded operation (e.g. acquiring a resource lock) exceeded its deadline.
    ///
    /// Nothing was mutated by this call, but another lease may hold the
    /// resource. Retry with backoff.
    #[error("operation timed out on {resource}: {operation}")]
    Timeout {
        /// The resource the operation targeted.
        resource: ResourceId,
        /// What timed out.
        operation: String,
    },
    /// The resource cannot be mutated right now because someone else owns it
    /// or a previous transaction blocks ownership.
    ///
    /// Nothing was mutated by this call; see [`ConflictReason`]. The calling
    /// lease, if any, remains usable.
    #[error("resource conflict on {resource}: {reason}")]
    Conflict {
        /// The contended resource.
        resource: ResourceId,
        /// Why the conflict occurred.
        reason: ConflictReason,
    },
    /// Another actor changed the DNS state after we applied ours.
    ///
    /// The current state is neither the state we applied nor the state we
    /// captured before applying. Per the ownership invariant, nothing was
    /// mutated and the journal record was kept. The lease remains usable:
    /// retry [`Lease::restore`](crate::Lease::restore) or
    /// [`Lease::abandon`](crate::Lease::abandon) it.
    #[error("external modification detected on {resource}: {detail}")]
    ExternalModification {
        /// The resource whose state changed externally.
        resource: ResourceId,
        /// Detail about what was detected.
        detail: String,
    },
    /// The requested configuration is invalid or not representable.
    ///
    /// Nothing was mutated; validation runs before locks, journals, or OS
    /// calls. Fix the input and retry.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// A mutation was applied but the read-back from the system did not match
    /// the desired semantics.
    ///
    /// A rollback to the captured state was attempted best-effort and the
    /// journal record was kept for
    /// [`DnsManager::recover_stale`](crate::DnsManager::recover_stale). The
    /// lease remains usable.
    #[error("verification failed on {resource}: {detail}")]
    VerificationFailed {
        /// The resource that failed verification.
        resource: ResourceId,
        /// Detail about the mismatch.
        detail: String,
    },
    /// A journal record could not be parsed or uses an unknown schema.
    ///
    /// This is always treated as fail-closed: no mutation is attempted.
    /// Inspect the state directory manually.
    #[error("journal is corrupt: {0}")]
    JournalCorrupt(String),
    /// An I/O error occurred while operating on state or lock files.
    ///
    /// The effect depends on when the failure happened; assume state may have
    /// changed and use read-back or recovery before retrying.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A platform API returned an unexpected error.
    ///
    /// The effect is backend-dependent; assume state may have changed, keep
    /// the lease, and verify with
    /// [`DnsManager::snapshot`](crate::DnsManager::snapshot) before retrying.
    #[error("platform error on {backend}: {message}")]
    Platform {
        /// The backend that produced the error.
        backend: BackendKind,
        /// Detail from the platform API.
        message: String,
    },
}

impl Error {
    pub(crate) fn invalid_config(message: impl fmt::Display) -> Self {
        Error::InvalidConfig(message.to_string())
    }

    pub(crate) fn unsupported(backend: BackendKind, reason: impl fmt::Display) -> Self {
        Error::Unsupported {
            backend,
            reason: reason.to_string(),
        }
    }

    pub(crate) fn platform(backend: BackendKind, message: impl fmt::Display) -> Self {
        Error::Platform {
            backend,
            message: message.to_string(),
        }
    }

    /// Returns `true` when this error is [`Error::ExternalModification`].
    pub fn is_external_modification(&self) -> bool {
        matches!(self, Error::ExternalModification { .. })
    }
}

/// Why a resource conflict occurred.
///
/// All variants imply nothing was mutated by the call that reported them.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConflictReason {
    /// A live lease in this process already owns the resource.
    #[error("the resource is already owned by an active lease in this process")]
    AlreadyLeasedInProcess,
    /// A journal record from a previous lease exists and cannot be safely
    /// resolved automatically (typically because the current state matches
    /// neither the recorded applied state nor the original state).
    #[error("an unresolved journal record from a previous lease blocks this operation: {detail}")]
    StaleJournalUnresolved {
        /// Detail about the unresolved journal.
        detail: String,
    },
    /// The lease has already been restored, abandoned, or invalidated.
    #[error("the lease is no longer active")]
    LeaseNotActive,
    /// The resource already exists and is claimed by someone else (another
    /// osdns owner or a manual configuration). Nothing was mutated.
    #[error("the resource is already occupied and is not owned by this lease: {detail}")]
    ResourceOccupied {
        /// Detail about the existing claim.
        detail: String,
    },
}
