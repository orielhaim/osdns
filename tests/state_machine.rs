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
    fn recover_decision(&self, rec: &Rec) -> RecDecision {
        if self.model.current == rec.before {
            RecDecision::Cleared
        } else if rec.applied.as_ref() == Some(&self.model.current)
            || self.model.current == rec.desired
        {
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
            let lease = self.fixture.manager.apply(&plan_config(plan)).unwrap();
            assert!(lease.is_noop(), "step {step}");
            self.model.lease = Some(LeaseM::Noop);
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
                    if self.model.current == plan_state(plan) {
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
                    self.live.take().unwrap().restore().unwrap();
                    self.model.lease = None;
                    assert!(self.model.journal.is_none(), "step {step}");
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
                if matches!(self.model.lease, Some(LeaseM::Owned { .. })) {
                    self.model.journal = None;
                }
                self.model.lease = None;
            }
            Op::DropLease => {
                let lease = self.live.take().expect("lease");
                drop(lease);
                match self.model.lease.take().expect("lease") {
                    LeaseM::Noop => {}
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
                    (Some(LeaseM::Owned { .. }), Some(_)) => {
                        assert!(
                            outcomes
                                .iter()
                                .all(|o| matches!(o, RecoveryOutcome::Busy { .. })),
                            "step {step}: {outcomes:?}"
                        );
                    }
                    (Some(LeaseM::Noop), None) => {
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
                    (lease, journal) => {
                        unreachable!("step {step}: impossible model state {lease:?} / {journal:?}")
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

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn pick_plan(&mut self) -> Plan {
        PLANS[self.below(PLANS.len() as u64) as usize]
    }
}

fn next_op(runner: &Runner, rng: &mut XorShift) -> Op {
    let leased = runner.model.lease.is_some();
    let journalled = runner.model.journal.is_some();
    let roll = rng.below(100);
    match (leased, journalled) {
        (false, false) => match roll {
            0..=39 => Op::Apply(rng.pick_plan()),
            40..=54 => Op::External(rng.below(2) as usize),
            55..=74 => Op::CrashApply(
                rng.pick_plan(),
                if rng.below(2) == 0 {
                    CrashPhase::Prepared
                } else {
                    CrashPhase::Applied
                },
            ),
            75..=84 => Op::Recover,
            _ => Op::External(rng.below(2) as usize),
        },
        (false, true) => match roll {
            0..=39 => Op::Apply(rng.pick_plan()),
            40..=59 => Op::Recover,
            60..=79 => Op::External(rng.below(2) as usize),
            _ => Op::Apply(rng.pick_plan()),
        },
        (true, _) => match roll {
            0..=24 => Op::Update(rng.pick_plan()),
            25..=44 => Op::Restore,
            45..=54 => Op::Abandon,
            55..=64 => Op::DropLease,
            65..=74 => Op::ApplyWhileLeased(rng.pick_plan()),
            75..=84 => Op::External(rng.below(2) as usize),
            85..=89 => Op::Recover,
            _ => {
                if let Some(LeaseM::Owned { applied, .. }) = &runner.model.lease
                    && runner.model.current == *applied
                {
                    return Op::CrashUpdate(
                        rng.pick_plan(),
                        if rng.below(2) == 0 {
                            CrashPhase::UpdatePrepared
                        } else {
                            CrashPhase::UpdateApplied
                        },
                    );
                }
                Op::Restore
            }
        },
    }
}

fn run_sequence(seed: u64, steps: usize) {
    let fixture = new_fixture(&format!("fsm-{seed}"));
    let mut runner = Runner {
        fixture,
        live: None,
        model: Model {
            current: FakeState::Empty,
            lease: None,
            journal: None,
        },
    };
    let mut rng = XorShift(seed | 1);
    for step in 0..steps {
        let op = next_op(&runner, &mut rng);
        runner.run(op, step);
    }
    let _ = runner.fixture.manager.recover_stale().unwrap();
}

#[test]
fn state_machine_survives_random_sequences() {
    for seed in [1, 2, 3, 7, 42, 1337, 90210] {
        run_sequence(seed, 150);
    }
}
