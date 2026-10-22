//! paludarium: an x86-64 Linux user-mode emulator (public API).
//!
//! ```no_run
//! use std::sync::Arc;
//! use paludarium::{Config, NativeHost, Session};
//!
//! let program = std::fs::read("hello").unwrap();
//! let config = Config::new("/hello", vec![b"hello".to_vec()]).with_file("/hello", program);
//! let session = Session::new(config, Arc::new(NativeHost::new())).unwrap();
//! let status = session.run().unwrap();
//! ```
#![forbid(unsafe_code)]

pub mod cli;

pub use paludarium_host::{Host, NativeHost};
pub use paludarium_runtime::{Config, DEFAULT_BUDGET, Mount, Session, TerminalInfo};
pub use paludarium_types::{Error, ErrorKind, ExitReason, ExitStatus, GuestAddr};

/// Test helpers re-exported for the differential harness and integration
/// tests.
pub mod testing {
    pub use paludarium_host::testing::RecordingHost;
    pub use paludarium_loader::testing::{CODE_ADDR, DATA_ADDR, tiny_exec};
}
