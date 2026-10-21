//! Independently implemented acceptance probe; item contracts are in COMPARISON.md.
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::{fs::MetadataExt, net::UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

type Outcome = Result<(), Box<dyn std::error::Error>>;
type Check = fn() -> Outcome;
const ITEMS: &[(&str, Check)] = &[
    ("tokio-timer", timer),
    ("unix-stream-pair", stream),
    ("rayon", parallel),
    ("mutex-condvar", synchronization),
    ("fs-basic", basic),
    ("fs-hardlink", hardlink),
    ("fs-symlink", symlink),
    ("fs-flock", locking),
];

fn require(ok: bool, description: &str) -> Outcome {
    if ok { Ok(()) } else { Err(description.into()) }
}

fn main() {
    let selected: Vec<String> = std::env::args().skip(1).collect();
    if selected == ["environment"] {
        let result = std::process::Command::new("node").arg("--version").output();
        match result {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => println!("PASS node-absent ENOENT"),
            result => {
                eprintln!("node unexpectedly available: {result:?}");
                std::process::exit(1);
            }
        }
        return;
    }
    if selected
        .iter()
        .any(|s| !ITEMS.iter().any(|(name, _)| name == s))
    {
        eprintln!("unknown probe item");
        std::process::exit(2);
    }
    let mut failed = false;
    for &(name, check) in ITEMS {
        if !selected.is_empty() && !selected.iter().any(|s| s == name) {
            continue;
        }
        match std::panic::catch_unwind(check) {
            Ok(Ok(())) => println!("PASS {name}"),
            Ok(Err(e)) => {
                println!("FAIL {name}: {e}");
                failed = true;
            }
            Err(_) => {
                println!("FAIL {name}: panic");
                failed = true;
            }
        }
        std::io::stdout().flush().expect("stdout flush");
    }
    std::process::exit(i32::from(failed));
}

fn timer() -> Outcome {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_time()
        .build()?;
    let elapsed = rt.block_on(async {
        tokio::spawn(async {
            let now = Instant::now();
            tokio::time::sleep(Duration::from_millis(50)).await;
            now.elapsed()
        })
        .await
    })?;
    require(
        (Duration::from_millis(50)..=Duration::from_secs(2)).contains(&elapsed),
        "timer deadline",
    )?;
    rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut ticker = tokio::time::interval(Duration::from_millis(10));
            for _ in 0..5 {
                ticker.tick().await;
            }
        })
        .await
    })?;
    Ok(())
}

fn stream() -> Outcome {
    let (mut tx, mut rx) = UnixStream::pair()?;
    let bytes: Vec<u8> = (0..(1 << 20)).map(|n| ((n * 31) % 251) as u8).collect();
    let expected = bytes.clone();
    let sender = std::thread::spawn(move || tx.write_all(&bytes));
    let mut actual = Vec::new();
    rx.read_to_end(&mut actual)?;
    sender.join().map_err(|_| "writer panic")??;
    require(actual == expected, "stream data mismatch")?;
    require(rx.read(&mut [0; 1])? == 0, "missing EOF")
}

fn parallel() -> Outcome {
    use rayon::prelude::*;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(4).build()?;
    require(
        pool.install(|| (0..1_000_000u64).into_par_iter().sum::<u64>()) == 499_999_500_000,
        "parallel sum",
    )
}

fn synchronization() -> Outcome {
    let count = Arc::new(Mutex::new(0));
    let mut threads = Vec::new();
    for _ in 0..4 {
        let count = count.clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..10_000 {
                *count.lock().unwrap() += 1;
            }
        }));
    }
    for thread in threads {
        thread.join().map_err(|_| "counter panic")?;
    }
    require(*count.lock().unwrap() == 40_000, "counter total")?;
    let state = Arc::new((Mutex::new(0u32), Condvar::new()));
    let other = state.clone();
    let deadline = Instant::now() + Duration::from_secs(10);
    let pong =
        std::thread::spawn(move || -> Result<(), &'static str> { turns(&other, 1, deadline) });
    turns(&state, 0, deadline)?;
    pong.join().map_err(|_| "pong panic")??;
    Ok(())
}

fn turns(
    state: &(Mutex<u32>, Condvar),
    parity: u32,
    deadline: Instant,
) -> Result<(), &'static str> {
    let mut value = state.0.lock().unwrap();
    while *value < 2000 {
        if Instant::now() >= deadline {
            return Err("condvar deadline");
        }
        if *value % 2 == parity {
            *value += 1;
            state.1.notify_all();
        } else {
            value = state
                .1
                .wait_timeout(value, deadline.saturating_duration_since(Instant::now()))
                .unwrap()
                .0;
        }
    }
    state.1.notify_all();
    Ok(())
}

fn directory() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join("paludarium-u10-probe");
    fs::create_dir(&path)?;
    Ok(path)
}

fn basic() -> Outcome {
    let dir = directory()?;
    fs::write(dir.join("old"), b"paludarium")?;
    require(fs::read(dir.join("old"))? == b"paludarium", "readback")?;
    fs::rename(dir.join("old"), dir.join("new"))?;
    require(
        !dir.join("old").exists() && fs::read(dir.join("new"))? == b"paludarium",
        "rename",
    )?;
    fs::create_dir(dir.join("child"))?;
    let mut names = fs::read_dir(&dir)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    require(names == ["child", "new"], "directory entries")?;
    fs::remove_dir_all(dir)?;
    Ok(())
}

fn hardlink() -> Outcome {
    let dir = directory()?;
    fs::write(dir.join("source"), b"initial")?;
    fs::hard_link(dir.join("source"), dir.join("alias"))?;
    require(fs::metadata(dir.join("source"))?.nlink() == 2, "link count")?;
    fs::write(dir.join("alias"), b"changed")?;
    require(
        fs::read(dir.join("source"))? == b"changed",
        "hardlink sharing",
    )?;
    fs::remove_dir_all(dir)?;
    Ok(())
}

fn symlink() -> Outcome {
    let dir = directory()?;
    let target = dir.join("target");
    fs::write(&target, b"symlink data")?;
    std::os::unix::fs::symlink(&target, dir.join("alias"))?;
    require(
        fs::read_link(dir.join("alias"))? == target,
        "readlink target",
    )?;
    require(
        fs::read(dir.join("alias"))? == b"symlink data",
        "symlink read",
    )?;
    fs::remove_dir_all(dir)?;
    Ok(())
}

fn lock(file: &File, operation: i32) -> std::io::Result<()> {
    // SAFETY: flock receives a live file descriptor and value-only flags.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn locking() -> Outcome {
    let dir = directory()?;
    fs::write(dir.join("lock"), b"")?;
    let a = File::open(dir.join("lock"))?;
    let b = File::open(dir.join("lock"))?;
    lock(&a, libc::LOCK_EX)?;
    require(
        lock(&b, libc::LOCK_EX | libc::LOCK_NB)
            .is_err_and(|e| e.raw_os_error() == Some(libc::EWOULDBLOCK)),
        "flock conflict",
    )?;
    lock(&a, libc::LOCK_UN)?;
    lock(&b, libc::LOCK_EX | libc::LOCK_NB)?;
    drop((a, b));
    fs::remove_dir_all(dir)?;
    Ok(())
}
