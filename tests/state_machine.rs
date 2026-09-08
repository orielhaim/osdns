//! Randomized state-machine verification of the ownership invariant.
#![cfg(feature = "test-util")]

mod common;

use common::*;
use osdns::testing::{CrashOutcome, FakeState, FaultInjector, TxPoint};
use osdns::{DnsConfig, Error, Lease, RecoveryOutcome};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Plan {
    A,
    B,
    C,
}

const PLANS: [Plan; 3] = [Plan::A, Plan::B, Plan::C];

fn plan_config(plan: Plan) -> DnsConfig {
    match plan {
        Plan::A => iface_config(1, "1.1.1.1"),
        Plan::B => iface_config(1, "8.8.8.8"),
        Plan::C => DnsConfig::builder(iface_scope(1))
            .nameserver(ip("1.0.0.1"))
            .search_domain("corp.example")
            .build()
            .unwrap(),
    }
}

fn plan_state(plan: Plan) -> FakeState {
    match plan {
        Plan::A => state_with("1.1.1.1"),
        Plan::B => state_with("8.8.8.8"),
        Plan::C => FakeState::Configured {
            nameservers: vec![ip("1.0.0.1")],
            search_domains: vec!["corp.example".parse().unwrap()],
            routing_domains: vec![],
            default_route: None,
        },
    }
}

const EXTERNALS: [&str; 2] = ["9.9.9.9", "149.112.112.112"];

fn external_state(i: usize) -> FakeState {
    state_with(EXTERNALS[i])
}

#[derive(Clone, Debug, PartialEq)]
struct Rec {
    before: FakeState,
    desired: FakeState,
    applied: Option<FakeState>,
}

#[derive(Clone, Debug, PartialEq)]
enum LeaseM {
    Noop,
    Owned {
        before: FakeState,
        applied: FakeState,
    },
}

#[derive(Clone, Debug, Default)]
struct Model {
    current: FakeState,
    lease: Option<LeaseM>,
    journal: Option<Rec>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum CrashPhase {
    Prepared,
    Applied,
    UpdatePrepared,
    UpdateApplied,
}

#[derive(Clone, Debug)]
enum Op {
    Apply(Plan),
    ApplyWhileLeased(Plan),
    Update(Plan),
    External(usize),
    Restore,
    Abandon,
    DropLease,
    CrashApply(Plan, CrashPhase),
    CrashUpdate(Plan, CrashPhase),
    Recover,
}

enum RecDecision {
    Cleared,
    Restored,
    Conflict,
}

struct Runner {
    fixture: Fixture,
    live: Option<Lease>,
    model: Model,
}

impl Runner {
    /// Mirrors production recovery exactly: only verified state counts.
    /// `current == desired` alone never proves ownership.
    fn recover_decision(&self, rec: &Rec) -> RecDecision {
        if self.model.current == rec.before {
            RecDecision::Cleared
        } else if rec.applied.as_ref() == Some(&self.model.current) {
            RecDecision::Restored
        } else {
            RecDecision::Conflict
        }
    }

    fn apply_recovering(&mut self, plan: Plan, step: usize) {
        if let Some(rec) = self.model.journal.clone() {
            match self.recover_decision(&rec) {
                RecDecision::Cleared => {
                    self.model.journal = None;
                }
                RecDecision::Restored => {
                    self.model.current = rec.before.clone();
                    self.model.journal = None;
                }
                RecDecision::Conflict => {
                    let error = self.fixture.manager.apply(&plan_config(plan)).unwrap_err();
                    assert!(
                        matches!(error, Error::Conflict { .. }),
                        "step {step}: expected conflict, got {error:?}"
                    );
                    return;
                }
            }
        }
        if self.model.current == plan_state(plan) {
            // Semantic no-op, but still a fully owned lease: journal with
            // applied == before.
            let lease = self.fixture.manager.apply(&plan_config(plan)).unwrap();
            assert!(lease.is_noop(), "step {step}");
            self.model.lease = Some(LeaseM::Noop);
            self.model.journal = Some(Rec {
                before: self.model.current.clone(),
                desired: plan_state(plan),
                applied: Some(plan_state(plan)),
            });
            self.live = Some(lease);
        } else {
            let before = self.model.current.clone();
            let lease = self.fixture.manager.apply(&plan_config(plan)).unwrap();
            assert!(!lease.is_noop(), "step {step}");
            self.model.lease = Some(LeaseM::Owned {
                before: before.clone(),
                applied: plan_state(plan),
            });
            self.model.journal = Some(Rec {
                before,
                desired: plan_state(plan),
                applied: Some(plan_state(plan)),
            });
            self.model.current = plan_state(plan);
            self.live = Some(lease);
        }
    }

    fn run(&mut self, op: Op, step: usize) {
        match op {
            Op::Apply(plan) => {
                assert!(
                    self.model.lease.is_none() && self.live.is_none(),
                    "step {step}"
                );
                self.apply_recovering(plan, step);
            }
            Op::ApplyWhileLeased(plan) => {
                assert!(
                    self.model.lease.is_some() && self.live.is_some(),
                    "step {step}"
                );
                let error = self.fixture.manager.apply(&plan_config(plan)).unwrap_err();
                assert!(
                    matches!(error, Error::Conflict { .. }),
                    "step {step}: expected conflict, got {error:?}"
                );
            }
            Op::Update(plan) => match self.model.lease.clone().expect("lease") {
                LeaseM::Noop => {
                    // A no-op lease owns applied == before == original
                    // state. An external change since apply breaks the
                    // update exactly like an owned lease.
                    let rec = self.model.journal.clone().expect("journal");
                    if self.model.current != rec.before {
                        let error = self
                            .live
                            .as_ref()
                            .unwrap()
                            .update(&plan_config(plan))
                            .unwrap_err();
                        assert!(
                            error.is_external_modification(),
                            "step {step}: expected external modification, got {error:?}"
                        );
                    } else if self.model.current == plan_state(plan) {
                        self.live
                            .as_ref()
                            .unwrap()
                            .update(&plan_config(plan))
                            .unwrap();
                    } else {
                        let before = self.model.current.clone();
                        self.live
                            .as_ref()
                            .unwrap()
                            .update(&plan_config(plan))
                            .unwrap();
                        self.model.lease = Some(LeaseM::Owned {
                            before: before.clone(),
                            applied: plan_state(plan),
                        });
                        self.model.journal = Some(Rec {
                            before,
                            desired: plan_state(plan),
                            applied: Some(plan_state(plan)),
                        });
                        self.model.current = plan_state(plan);
                    }
                }
                LeaseM::Owned { before, applied } => {
                    if self.model.current != applied {
                        let error = self
                            .live
                            .as_ref()
                            .unwrap()
                            .update(&plan_config(plan))
                            .unwrap_err();
                        assert!(
                            error.is_external_modification(),
                            "step {step}: expected external modification, got {error:?}"
                        );
                    } else if self.model.current == plan_state(plan) {
                        self.live
                            .as_ref()
                            .unwrap()
                            .update(&plan_config(plan))
                            .unwrap();
                    } else {
                        self.live
                            .as_ref()
                            .unwrap()
                            .update(&plan_config(plan))
                            .unwrap();
                        self.model.lease = Some(LeaseM::Owned {
                            before: before.clone(),
                            applied: plan_state(plan),
                        });
                        self.model.journal = Some(Rec {
                            before,
                            desired: plan_state(plan),
                            applied: Some(plan_state(plan)),
                        });
                        self.model.current = plan_state(plan);
                    }
                }
            },
            Op::External(i) => {
                self.fixture
                    .fake
                    .external_change(IFACE1, external_state(i))
                    .unwrap();
                self.model.current = external_state(i);
            }
            Op::Restore => match self.model.lease.clone().expect("lease") {
                LeaseM::Noop => {
                    // No-op leases own Applied records with applied ==
                    // before: restore clears the journal without mutation
                    // unless an external change arrived meanwhile.
                    if self.model.journal.is_none() {
                        self.live.take().unwrap().restore().unwrap();
                        self.model.lease = None;
                        return;
                    }
                    let rec = self.model.journal.clone().expect("journal");
                    if self.model.current == rec.before {
                        self.live.take().unwrap().restore().unwrap();
                        self.model.journal = None;
                        self.model.lease = None;
                    } else {
                        let lease = self.live.take().unwrap();
                        let failure = lease.restore().unwrap_err();
                        assert!(
                            failure.error.is_external_modification(),
                            "step {step}: {failure:?}"
                        );
                        failure.lease.abandon().unwrap();
                        self.model.journal = None;
                        self.model.lease = None;
                    }
                }
                LeaseM::Owned { before, applied } => {
                    if self.model.current == applied {
                        let lease = self.live.take().unwrap();
                        lease.restore().unwrap();
                        self.model.current = before;
                        self.model.journal = None;
                        self.model.lease = None;
                    } else if self.model.current == before {
                        let lease = self.live.take().unwrap();
                        lease.restore().unwrap();
                        self.model.journal = None;
                        self.model.lease = None;
                    } else {
                        let lease = self.live.take().unwrap();
                        let failure = lease.restore().unwrap_err();
                        assert!(
                            failure.error.is_external_modification(),
                            "step {step}: {failure:?}"
                        );
                        let lease = failure.lease;
                        lease.abandon().unwrap();
                        self.model.journal = None;
                        self.model.lease = None;
                    }
                }
            },
            Op::Abandon => {
                let lease = self.live.take().expect("lease");
                lease.abandon().unwrap();
                // Every lease (including no-op leases) owns a journal.
                self.model.journal = None;
                self.model.lease = None;
            }
            Op::DropLease => {
                let lease = self.live.take().expect("lease");
                drop(lease);
                match self.model.lease.take().expect("lease") {
                    LeaseM::Noop => {
                        // Best-effort drop restore clears the no-op journal
                        // when the state is still ours; otherwise it is
                        // kept for recovery. The model journals the
                        // outcome the same way production does.
                        let rec = self.model.journal.clone().expect("journal");
                        if self.model.current == rec.before {
                            self.model.journal = None;
                        }
                    }
                    LeaseM::Owned { before, applied } => {
                        if self.model.current == applied {
                            self.model.current = before;
                            self.model.journal = None;
                        } else if self.model.current == before {
                            self.model.journal = None;
                        }
                    }
                }
            }
            Op::CrashApply(plan, phase) => {
                assert!(
                    self.model.lease.is_none()
                        && self.live.is_none()
                        && self.model.journal.is_none(),
                    "step {step}"
                );
                if self.model.current == plan_state(plan) {
                    let lease = self.fixture.manager.apply(&plan_config(plan)).unwrap();
                    assert!(lease.is_noop(), "step {step}");
                    self.model.lease = Some(LeaseM::Noop);
                    self.model.journal = Some(Rec {
                        before: self.model.current.clone(),
                        desired: plan_state(plan),
                        applied: Some(plan_state(plan)),
                    });
                    self.live = Some(lease);
                    self.assert_invariants(step);
                    return;
                }
                let injector = FaultInjector::new();
                injector.crash_at(match phase {
                    CrashPhase::Prepared => TxPoint::AfterPrepared,
                    CrashPhase::Applied => TxPoint::AfterApplied,
                    _ => unreachable!("apply crash phase"),
                });
                self.fixture
                    .manager
                    .install_fault_injector(injector.clone());
                let outcome =
                    osdns::testing::catch_crash(|| self.fixture.manager.apply(&plan_config(plan)));
                injector.clear();
                assert!(matches!(outcome, CrashOutcome::Crashed), "step {step}");
                let before = self.model.current.clone();
                match phase {
                    CrashPhase::Prepared => {
                        self.model.journal = Some(Rec {
                            before: before.clone(),
                            desired: plan_state(plan),
                            applied: None,
                        });
                    }
                    CrashPhase::Applied => {
                        self.model.journal = Some(Rec {
                            before: before.clone(),
                            desired: plan_state(plan),
                            applied: Some(plan_state(plan)),
                        });
                        self.model.current = plan_state(plan);
                    }
                    _ => unreachable!(),
                }
            }
            Op::CrashUpdate(plan, phase) => {
                let LeaseM::Owned { before, applied } = self.model.lease.clone().expect("lease")
                else {
                    panic!("step {step}: crash update requires an owned lease");
                };
                if self.model.current == plan_state(plan) {
                    self.live
                        .as_ref()
                        .unwrap()
                        .update(&plan_config(plan))
                        .unwrap();
                    self.assert_invariants(step);
                    return;
                }
                let injector = FaultInjector::new();
                injector.crash_at(match phase {
                    CrashPhase::UpdatePrepared => TxPoint::AfterUpdatePrepared,
                    CrashPhase::UpdateApplied => TxPoint::AfterUpdateApplied,
                    _ => unreachable!("update crash phase"),
                });
                self.fixture
                    .manager
                    .install_fault_injector(injector.clone());
                let outcome = osdns::testing::catch_crash(|| {
                    self.live.as_ref().unwrap().update(&plan_config(plan))
                });
                injector.clear();
                assert!(matches!(outcome, CrashOutcome::Crashed), "step {step}");
                self.live = None;
                self.model.lease = None;
                match phase {
                    CrashPhase::UpdatePrepared => {
                        self.model.journal = Some(Rec {
                            before,
                            desired: plan_state(plan),
                            applied: Some(applied),
                        });
                    }
                    CrashPhase::UpdateApplied => {
                        self.model.journal = Some(Rec {
                            before,
                            desired: plan_state(plan),
                            applied: Some(plan_state(plan)),
                        });
                        self.model.current = plan_state(plan);
                    }
                    _ => unreachable!(),
                }
            }
            Op::Recover => {
                let outcomes = self.fixture.manager.recover_stale().unwrap();
                match (&self.model.lease, &self.model.journal) {
                    // Any live lease holds its locks: recovery skips.
                    // No-op leases own journals too, so they are Busy
                    // like every other live lease.
                    (Some(_), Some(_)) => {
                        assert!(
                            outcomes
                                .iter()
                                .all(|o| matches!(o, RecoveryOutcome::Busy { .. })),
                            "step {step}: {outcomes:?}"
                        );
                    }
                    (Some(_), None) => {
                        assert!(outcomes.is_empty(), "step {step}: {outcomes:?}");
                    }
                    (None, None) => {
                        assert!(outcomes.is_empty(), "step {step}: {outcomes:?}");
                    }
                    (None, Some(rec)) => {
                        assert_eq!(outcomes.len(), 1, "step {step}: {outcomes:?}");
                        match self.recover_decision(rec) {
                            RecDecision::Cleared => {
                                assert!(
                                    matches!(&outcomes[0], RecoveryOutcome::JournalCleared { .. }),
                                    "step {step}: {outcomes:?}"
                                );
                                self.model.journal = None;
                            }
                            RecDecision::Restored => {
                                assert!(
                                    matches!(&outcomes[0], RecoveryOutcome::Restored { .. }),
                                    "step {step}: {outcomes:?}"
                                );
                                self.model.current = rec.before.clone();
                                self.model.journal = None;
                            }
                            RecDecision::Conflict => {
                                assert!(
                                    matches!(
                                        &outcomes[0],
                                        RecoveryOutcome::ExternalConflict { .. }
                                    ),
                                    "step {step}: {outcomes:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
        self.assert_invariants(step);
    }

    fn assert_invariants(&self, step: usize) {
        assert_eq!(
            self.live.is_some(),
            self.model.lease.is_some(),
            "step {step}: lease handle presence diverged from model"
        );
        let files = journal_files(&self.fixture.dir);
        assert_eq!(
            files.len(),
            usize::from(self.model.journal.is_some()),
            "step {step}: journal records {files:?} diverged from model"
        );
        let actual = self.fixture.fake.current_state(IFACE1).unwrap();
        assert_eq!(
            Some(&self.model.current),
            actual.as_ref(),
            "step {step}: fake OS state diverged from model"
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalM {
    None,
    Recoverable,
    Conflict,
}

#[derive(Clone, Debug)]
struct RefState {
    leased: bool,
    lease_owned: bool,
    lease_before_plan: Option<Plan>,
    current_owned: bool,
    journal: JournalM,
    allow_crash_apply: bool,
    current_plan: Option<Plan>,
    recovery_plan: Option<Plan>,
}

struct Lifecycle;

impl proptest_state_machine::ReferenceStateMachine for Lifecycle {
    type State = RefState;
    type Transition = Op;

    fn init_state() -> proptest::strategy::BoxedStrategy<Self::State> {
        use proptest::strategy::{Just, Strategy};
        Just(RefState {
            leased: false,
            lease_owned: false,
            lease_before_plan: None,
            current_owned: false,
            journal: JournalM::None,
            allow_crash_apply: true,
            current_plan: None,
            recovery_plan: None,
        })
        .boxed()
    }

    fn transitions(state: &Self::State) -> proptest::strategy::BoxedStrategy<Self::Transition> {
        use proptest::prop_oneof;
        use proptest::strategy::{Just, Strategy};

        let plans = proptest::sample::select(PLANS.to_vec());
        if state.leased {
            let mut transitions = vec![
                Just(Op::Restore).boxed(),
                Just(Op::Abandon).boxed(),
                Just(Op::DropLease).boxed(),
                Just(Op::Recover).boxed(),
                (0usize..EXTERNALS.len()).prop_map(Op::External).boxed(),
                plans.clone().prop_map(Op::Update).boxed(),
                plans.clone().prop_map(Op::ApplyWhileLeased).boxed(),
            ];
            if state.current_owned {
                transitions.push(
                    (plans, proptest::bool::ANY)
                        .prop_map(|(plan, applied)| {
                            Op::CrashUpdate(
                                plan,
                                if applied {
                                    CrashPhase::UpdateApplied
                                } else {
                                    CrashPhase::UpdatePrepared
                                },
                            )
                        })
                        .boxed(),
                );
            }
            proptest::strategy::Union::new(transitions).boxed()
        } else if state.journal == JournalM::None {
            prop_oneof![
                plans.clone().prop_map(Op::Apply),
                (0usize..EXTERNALS.len()).prop_map(Op::External),
                (plans, proptest::bool::ANY).prop_map(|(plan, applied)| Op::CrashApply(
                    plan,
                    if applied {
                        CrashPhase::Applied
                    } else {
                        CrashPhase::Prepared
                    }
                )),
                Just(Op::Recover),
            ]
            .boxed()
        } else {
            prop_oneof![
                Just(Op::Recover),
                (0usize..EXTERNALS.len()).prop_map(Op::External),
            ]
            .boxed()
        }
    }

    fn preconditions(state: &Self::State, transition: &Self::Transition) -> bool {
        match transition {
            Op::Apply(_) => !state.leased && state.journal == JournalM::None,
            Op::CrashApply(plan, _) => {
                !state.leased
                    && state.journal == JournalM::None
                    && state.allow_crash_apply
                    && state.current_plan != Some(*plan)
            }
            Op::ApplyWhileLeased(_) | Op::Update(_) | Op::Restore | Op::Abandon | Op::DropLease => {
                state.leased
            }
            Op::CrashUpdate(plan, _) => {
                state.leased
                    && state.lease_owned
                    && state.current_owned
                    && state.current_plan != Some(*plan)
            }
            Op::External(_) | Op::Recover => true,
        }
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        match transition {
            Op::Apply(plan) => {
                state.lease_before_plan = state.current_plan;
                state.lease_owned = state.current_plan != Some(*plan);
                state.leased = true;
                state.current_owned = true;
                state.journal = JournalM::Recoverable;
                state.allow_crash_apply = false;
                state.current_plan = Some(*plan);
            }
            Op::ApplyWhileLeased(_) => {}
            Op::Update(plan) if state.current_owned => {
                if state.current_plan != Some(*plan) {
                    state.lease_owned = true;
                }
                state.current_plan = Some(*plan);
            }
            Op::Update(_) => {}
            Op::External(_) => {
                state.current_owned = false;
                state.allow_crash_apply = true;
                state.current_plan = None;
                if !state.leased && state.journal != JournalM::None {
                    state.journal = JournalM::Conflict;
                }
            }
            Op::Restore => {
                if state.current_owned && state.lease_owned {
                    state.current_plan = state.lease_before_plan;
                }
                state.leased = false;
                state.lease_owned = false;
                state.current_owned = false;
                state.journal = JournalM::None;
                state.lease_before_plan = None;
            }
            Op::Abandon => {
                state.leased = false;
                state.lease_owned = false;
                state.current_owned = false;
                state.journal = JournalM::None;
                state.lease_before_plan = None;
            }
            Op::DropLease => {
                if state.current_owned && state.lease_owned {
                    state.current_plan = state.lease_before_plan;
                }
                state.leased = false;
                state.lease_owned = false;
                state.journal = if state.current_owned {
                    JournalM::None
                } else {
                    JournalM::Conflict
                };
                state.current_owned = false;
                state.lease_before_plan = None;
            }
            Op::CrashApply(plan, phase) => {
                state.recovery_plan = state.current_plan;
                state.journal = JournalM::Recoverable;
                state.current_owned = *phase == CrashPhase::Applied;
                state.allow_crash_apply = false;
                if *phase == CrashPhase::Applied {
                    state.current_plan = Some(*plan);
                }
            }
            Op::CrashUpdate(plan, phase) => {
                state.recovery_plan = state.lease_before_plan;
                state.leased = false;
                state.lease_owned = false;
                state.journal = JournalM::Recoverable;
                state.current_owned = *phase == CrashPhase::UpdateApplied;
                if *phase == CrashPhase::UpdateApplied {
                    state.current_plan = Some(*plan);
                }
            }
            Op::Recover => {
                if !state.leased && state.journal == JournalM::Recoverable {
                    state.journal = JournalM::None;
                    state.current_owned = false;
                    state.current_plan = state.recovery_plan;
                    state.recovery_plan = None;
                }
            }
        }
        state
    }
}

struct LifecycleTest;

impl proptest_state_machine::StateMachineTest for LifecycleTest {
    type SystemUnderTest = Runner;
    type Reference = Lifecycle;

    fn init_test(_: &RefState) -> Self::SystemUnderTest {
        Runner {
            fixture: new_fixture("proptest-fsm"),
            live: None,
            model: Model {
                current: FakeState::Empty,
                lease: None,
                journal: None,
            },
        }
    }

    fn apply(
        mut state: Self::SystemUnderTest,
        _: &RefState,
        transition: Op,
    ) -> Self::SystemUnderTest {
        state.run(transition, 0);
        state
    }

    fn check_invariants(state: &Self::SystemUnderTest, _: &RefState) {
        state.assert_invariants(0);
    }
}

proptest_state_machine::prop_state_machine! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn lifecycle_state_machine(sequential 1..80 => LifecycleTest);
}
