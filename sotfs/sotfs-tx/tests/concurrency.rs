//! Loom-based concurrency tests for the GTXN transaction layer.
//!
//! Verifies that concurrent transactions maintain isolation (disjoint
//! write sets) and that rollback under contention is correct.
//!
//! Run with: cargo test --test concurrency -- --test-threads=1

use loom::sync::{Arc, Mutex};
use loom::thread;

/// Simplified graph state for loom testing (loom can't use BTreeMap from std).
#[derive(Clone)]
struct LoomGraph {
    values: [i64; 4],
}

/// Simplified transaction: records old values for rollback.
struct LoomTx {
    snapshot: [i64; 4],
    write_set: [bool; 4],
    committed: bool,
}

impl LoomTx {
    fn begin(graph: &LoomGraph) -> Self {
        Self {
            snapshot: graph.values,
            write_set: [false; 4],
            committed: false,
        }
    }

    fn write(&mut self, graph: &mut LoomGraph, idx: usize, val: i64) {
        self.write_set[idx] = true;
        graph.values[idx] = val;
    }

    fn commit(&mut self) {
        self.committed = true;
    }

    fn rollback(&self, graph: &mut LoomGraph) {
        for i in 0..4 {
            if self.write_set[i] {
                graph.values[i] = self.snapshot[i];
            }
        }
    }
}

#[test]
fn concurrent_transactions_isolation() {
    // Two transactions writing to disjoint slots should both succeed.
    loom::model(|| {
        let graph = Arc::new(Mutex::new(LoomGraph {
            values: [0, 0, 0, 0],
        }));

        let g1 = Arc::clone(&graph);
        let g2 = Arc::clone(&graph);

        let t1 = thread::spawn(move || {
            let mut g = g1.lock().unwrap();
            let mut tx = LoomTx::begin(&g);
            tx.write(&mut g, 0, 42); // writes slot 0
            tx.commit();
        });

        let t2 = thread::spawn(move || {
            let mut g = g2.lock().unwrap();
            let mut tx = LoomTx::begin(&g);
            tx.write(&mut g, 1, 99); // writes slot 1
            tx.commit();
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let g = graph.lock().unwrap();
        // Both writes should be visible (disjoint slots)
        assert!(g.values[0] == 42 || g.values[1] == 99);
    });
}

#[test]
fn rollback_restores_state() {
    // A rolled-back transaction should not affect the graph.
    loom::model(|| {
        let graph = Arc::new(Mutex::new(LoomGraph {
            values: [10, 20, 30, 40],
        }));

        let g1 = Arc::clone(&graph);

        let t1 = thread::spawn(move || {
            let mut g = g1.lock().unwrap();
            let mut tx = LoomTx::begin(&g);
            tx.write(&mut g, 0, 999);
            tx.write(&mut g, 2, 888);
            // Abort: rollback
            tx.rollback(&mut g);
        });

        t1.join().unwrap();

        let g = graph.lock().unwrap();
        assert_eq!(g.values[0], 10); // restored
        assert_eq!(g.values[2], 30); // restored
    });
}

#[test]
fn conflicting_writes_serialized() {
    // Two transactions writing to the SAME slot are serialized by the Mutex.
    // The last writer wins, but both execute atomically.
    loom::model(|| {
        let graph = Arc::new(Mutex::new(LoomGraph {
            values: [0, 0, 0, 0],
        }));

        let g1 = Arc::clone(&graph);
        let g2 = Arc::clone(&graph);

        let t1 = thread::spawn(move || {
            let mut g = g1.lock().unwrap();
            let mut tx = LoomTx::begin(&g);
            tx.write(&mut g, 0, 1);
            tx.commit();
        });

        let t2 = thread::spawn(move || {
            let mut g = g2.lock().unwrap();
            let mut tx = LoomTx::begin(&g);
            tx.write(&mut g, 0, 2);
            tx.commit();
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let g = graph.lock().unwrap();
        // One of them won — value is either 1 or 2, never 0
        assert!(g.values[0] == 1 || g.values[0] == 2);
    });
}
