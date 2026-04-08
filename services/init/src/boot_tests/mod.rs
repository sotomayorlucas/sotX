//! Boot-time integration tests for sotos-init.
pub(crate) mod dynamic;
pub(crate) mod linux_abi;
pub(crate) mod dynamic_test;
pub(crate) mod busybox;
pub(crate) mod validation;
pub(crate) mod benchmarks;

pub(crate) use dynamic::test_dynamic_linking;
pub(crate) use linux_abi::{run_linux_test, run_musl_test};
pub(crate) use dynamic_test::run_dynamic_test;
pub(crate) use busybox::run_busybox_test;
pub(crate) use validation::run_phase_validation;
pub(crate) use benchmarks::{run_benchmarks, producer};
pub use benchmarks::test_wasm;
