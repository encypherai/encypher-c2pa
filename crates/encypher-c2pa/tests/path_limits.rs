use encypher_c2pa::{verify_file, Error, VerifyOptions};
#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const PATH_LIMIT: u64 = 128 * 1024 * 1024;

fn scratch_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "encypher-c2pa-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ))
}

#[test]
fn verify_file_rejects_sparse_asset_over_path_limit() {
    let path = scratch_path("oversized.jpg");
    let file = File::create(&path).expect("create sparse asset");
    file.set_len(PATH_LIMIT + 1).expect("size sparse asset");
    drop(file);

    let error = verify_file(&path, Some("image/jpeg"), &VerifyOptions::default())
        .expect_err("oversized path asset must fail");
    fs::remove_file(&path).expect("remove sparse asset");

    assert!(matches!(error, Error::Io(_)));
    assert!(error.to_string().contains("128 MiB path limit"));
}

#[cfg(unix)]
#[test]
fn verify_file_rejects_non_regular_source_without_reading_it() {
    let error = verify_file("/dev/zero", Some("image/jpeg"), &VerifyOptions::default())
        .expect_err("character device must fail");

    assert!(matches!(error, Error::Io(_)));
    assert!(error.to_string().contains("not a regular file"));
}

#[cfg(unix)]
#[test]
fn verify_file_rejects_fifo_promptly_without_opening_it_twice() {
    let path = scratch_path("fifo.jpg");
    let c_path = CString::new(path.as_os_str().as_bytes()).expect("FIFO path has no NUL");
    // SAFETY: c_path is a valid, NUL-terminated path and the mode is valid.
    let result = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(
        result,
        0,
        "create FIFO: {}",
        std::io::Error::last_os_error()
    );

    let worker_path = path.clone();
    let (sender, receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = verify_file(&worker_path, Some("image/jpeg"), &VerifyOptions::default());
        sender.send(result).expect("send verification result");
    });

    let verification = match receiver.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Unblock the regressed implementation before failing so the test
            // never leaves a blocked worker behind.
            let writer = OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open FIFO writer to unblock reader");
            let result = receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("FIFO reader remained blocked after writer opened");
            drop(writer);
            worker.join().expect("join FIFO verification worker");
            fs::remove_file(&path).expect("remove FIFO");
            panic!("verify_file blocked while opening FIFO; eventual result: {result:?}");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("FIFO verification worker disconnected")
        }
    };

    worker.join().expect("join FIFO verification worker");
    fs::remove_file(&path).expect("remove FIFO");
    let error = verification.expect_err("FIFO must be rejected");
    assert!(matches!(error, Error::Io(_)));
    assert!(error.to_string().contains("not a regular file"));
}
