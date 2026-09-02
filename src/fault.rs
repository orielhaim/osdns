/// Transaction checkpoints where tests can inject failures or simulate
/// process death. Every checkpoint fires *after* the named step completed.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TxPoint {
    /// After configuration validation.
    AfterValidate,
    /// After the backend resolved the target resource.
    AfterResolve,
    /// After the exclusive resource lock was acquired.
    AfterLock,
    /// After any stale journal for the resource was inspected and recovered.
    AfterRecovery,
    /// After the current state was captured.
    AfterCapture,
    /// After the semantic no-op decision.
    AfterNoopDecision,
    /// After the `Prepared` journal record was persisted.
    AfterPrepared,
    /// After the OS mutation returned.
    AfterApply,
    /// After the post-mutation read-back.
    AfterReadback,
    /// After verification of the read-back state.
    AfterVerify,
    /// After the `Applied` journal record was persisted.
    AfterApplied,
    /// After scope-consistency was checked on lease update.
    AfterUpdateResolve,
    /// After the current state was read on lease update.
    AfterUpdateCapture,
    /// After the no-op decision on lease update.
    AfterUpdateNoopCheck,
    /// After the updated `Prepared` journal record was persisted.
    AfterUpdatePrepared,
    /// After the OS mutation returned during lease update.
    AfterUpdateApply,
    /// After the post-mutation read-back during lease update.
    AfterUpdateReadback,
    /// After verification during lease update.
    AfterUpdateVerify,
    /// After the `Applied` journal record was persisted during lease update.
    AfterUpdateApplied,
    /// After the current state was read at the start of restore.
    AfterRestoreReadback,
    /// After the backend restored the original snapshot.
    AfterRestoreRestore,
    /// After the journal record was removed at the end of restore.
    AfterRestoreJournal,
    /// After the current state was read at the start of journal recovery.
    AfterRecoveryReadback,
    /// After the recovery restore of the original snapshot.
    AfterRecoveryRestore,
    /// After the journal record was removed at the end of recovery.
    AfterRecoveryJournal,
}

#[allow(dead_code)]
pub(crate) enum FaultAction {
    Continue,
    Crash,
    Fail(String),
}

pub(crate) trait FaultHook: Send + Sync {
    fn on_point(&self, point: TxPoint) -> FaultAction;
}

/// Panic payload used to simulate abrupt process death mid-transaction.
#[derive(Debug)]
pub(crate) struct CrashSignal;
