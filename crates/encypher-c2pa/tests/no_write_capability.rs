//! Verification runs with the ability to write taken away by the kernel.
//!
//! The other controls in this repository reason about source text. The
//! public-surface gate locks the shape of the API from rustdoc's own output,
//! and `read_only_contract.rs` checks the observable behaviour of each entry
//! point. Neither can establish the general property that verification does
//! not write, and one attempt to get there with a pattern list over the source
//! was defeated twice in a sitting by `use std::fs as io_fs` and by
//! `File::options().create(true)`. A denylist over text cannot decide this.
//!
//! So stop asking the source and ask the kernel. This forks a child, installs
//! a seccomp filter that refuses every syscall capable of creating, truncating
//! or removing a file, and then runs the three public verification entry
//! points inside it. If they still succeed, they did not write - not because
//! no writer was spotted, but because no writer was possible. Aliases,
//! re-export paths, generic `io::Write` indirection, macro expansion,
//! `include!`, `unsafe`, and a dependency writing on the crate's behalf are all
//! equally powerless against it, which is the whole point of moving the check
//! down a layer.
//!
//! The filter is applied at `openat`/`open` by inspecting the flags argument,
//! so reads pass and writes do not. `write(2)` itself stays permitted: the
//! child needs stdout, and it cannot obtain a writable file descriptor anyway.
//!
//! A denied syscall KILLS the child rather than returning `EPERM`, and that
//! detail is the difference between a test and a decoration. The first version
//! returned an error, and both of the reviewer's writers sailed through it:
//! they were written `let _ = io_fs::write(..)`, so the write failed, the
//! result was discarded, verification finished normally and the test reported
//! success. Returning an error only proves verification does not DEPEND on
//! writing. Killing proves it does not ATTEMPT it.
//!
//! Two children run. The first tries to create a file and MUST die, because a
//! filter that is not actually engaged would make everything after it vacuous.
//! The second runs the entry points and must exit cleanly.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::{Path, PathBuf};

use encypher_c2pa::{verify, verify_file, verify_with_options, VerifyOptions};

// Exit codes. The child cannot panic usefully - the harness's machinery is not
// reachable once it is sandboxed - so it reports by status and the parent
// translates.
const OK: i32 = 0;
const NO_NEW_PRIVS_REFUSED: i32 = 10;
const SECCOMP_REFUSED: i32 = 11;
const SANDBOX_NOT_ENGAGED: i32 = 12;
const VERIFY_FAILED: i32 = 20;
const VERIFY_WITH_OPTIONS_FAILED: i32 = 21;
const VERIFY_FILE_FAILED: i32 = 22;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

/// Assemble the seccomp program.
///
/// Written out longhand rather than pulled from a crate: this repository has no
/// network during CI and the filter is short enough that a reader can check it
/// against the syscall table, which matters more here than brevity.
fn filter() -> Vec<libc::sock_filter> {
    // Classic BPF opcodes.
    const LD_W_ABS: u16 = 0x20;
    const ALU_AND_K: u16 = 0x54;
    const JMP_JEQ_K: u16 = 0x15;
    const JMP_JA: u16 = 0x05;
    const RET_K: u16 = 0x06;

    // `struct seccomp_data` offsets: nr, arch, instruction_pointer, args[6].
    const OFF_NR: u32 = 0;
    const OFF_ARCH: u32 = 4;
    const OFF_ARG1: u32 = 24;
    const OFF_ARG2: u32 = 32;

    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;

    // Any of these in the open flags means the caller wants to modify a file.
    const WRITE_FLAGS: u32 =
        (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u32;

    // x86_64 syscall numbers that mutate the filesystem without an open.
    // `openat2` is here because its flags live behind a pointer, which classic
    // BPF cannot follow - so it is refused outright rather than guessed at.
    const UNCONDITIONAL_DENY: &[u32] = &[
        437, // openat2
        85,  // creat
        87,  // unlink
        263, // unlinkat
        82,  // rename
        264, // renameat
        316, // renameat2
        76,  // truncate
        77,  // ftruncate
        83,  // mkdir
        258, // mkdirat
        84,  // rmdir
        86,  // link
        265, // linkat
        88,  // symlink
        266, // symlinkat
        90,  // chmod
        268, // fchmodat
        91,  // fchmod
        // A verifier does not start programs either. Without these, a writer
        // could shell out: the filter IS inherited across fork and exec, so the
        // child dies and no write lands, but the verifier survives to return a
        // clean report and the test would not notice the attempt.
        57,  // fork
        58,  // vfork
        56,  // clone
        435, // clone3
        59,  // execve
        322, // execveat
    ];

    let ins = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };

    // Refuse to run at all on an unexpected architecture. A filter written
    // against the wrong syscall table is worse than none, because it would
    // silently permit everything it thinks it is denying.
    let mut p = vec![
        ins(LD_W_ABS, 0, 0, OFF_ARCH),
        ins(JMP_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        ins(RET_K, 0, 0, RET_KILL_PROCESS),
    ];

    // openat(dirfd, path, flags, mode): allow when no write flag is set.
    p.push(ins(LD_W_ABS, 0, 0, OFF_NR));
    p.push(ins(JMP_JEQ_K, 0, 5, 257));
    p.push(ins(LD_W_ABS, 0, 0, OFF_ARG2));
    p.push(ins(ALU_AND_K, 0, 0, WRITE_FLAGS));
    p.push(ins(JMP_JEQ_K, 1, 0, 0));
    p.push(ins(RET_K, 0, 0, RET_KILL_PROCESS));
    p.push(ins(RET_K, 0, 0, RET_ALLOW));

    // open(path, flags, mode): same test, flags one argument earlier.
    p.push(ins(LD_W_ABS, 0, 0, OFF_NR));
    p.push(ins(JMP_JEQ_K, 0, 5, 2));
    p.push(ins(LD_W_ABS, 0, 0, OFF_ARG1));
    p.push(ins(ALU_AND_K, 0, 0, WRITE_FLAGS));
    p.push(ins(JMP_JEQ_K, 1, 0, 0));
    p.push(ins(RET_K, 0, 0, RET_KILL_PROCESS));
    p.push(ins(RET_K, 0, 0, RET_ALLOW));

    // Everything else that mutates. Each comparison jumps forward to the single
    // shared deny return, so no offset exceeds the 255-instruction jump limit.
    p.push(ins(LD_W_ABS, 0, 0, OFF_NR));
    let chain_start = p.len();
    let deny_at = chain_start + UNCONDITIONAL_DENY.len() + 1;
    for (i, nr) in UNCONDITIONAL_DENY.iter().enumerate() {
        let jt = (deny_at - (chain_start + i) - 1) as u8;
        p.push(ins(JMP_JEQ_K, jt, 0, *nr));
    }
    p.push(ins(JMP_JA, 0, 0, 1));
    p.push(ins(RET_K, 0, 0, RET_KILL_PROCESS));
    p.push(ins(RET_K, 0, 0, RET_ALLOW));

    p
}

/// Drop the ability to create or modify any file, irreversibly, for this
/// process and everything it goes on to call.
fn engage_sandbox() -> Result<(), i32> {
    // Required before an unprivileged process may install a filter.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(NO_NEW_PRIVS_REFUSED);
    }
    let prog = filter();
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &fprog as *const libc::sock_fprog,
        )
    };
    if rc != 0 {
        return Err(SECCOMP_REFUSED);
    }
    Ok(())
}

/// Attempt a write under the filter. Must not survive.
fn canary_child() -> ! {
    if let Err(code) = engage_sandbox() {
        unsafe { libc::_exit(code) }
    }
    let _ = std::fs::write("/tmp/encypher-seccomp-canary", b"x");
    // Reaching this line means the filter permitted a file creation.
    unsafe { libc::_exit(SANDBOX_NOT_ENGAGED) }
}

/// Run the three public entry points under the filter. Must exit cleanly.
fn verify_child(signed_jpg: Vec<u8>, signed_mp4: Vec<u8>, mp4_path: PathBuf) -> ! {
    let code = (|| {
        engage_sandbox()?;

        // Any write attempt beneath these calls - by any route, including one
        // whose error is discarded - terminates this process, and the parent
        // reports the signal.
        verify(&signed_jpg, "image/jpeg").map_err(|_| VERIFY_FAILED)?;

        verify_with_options(&signed_mp4, "video/mp4", &VerifyOptions::default())
            .map_err(|_| VERIFY_WITH_OPTIONS_FAILED)?;

        verify_file(&mp4_path, None, &VerifyOptions::default()).map_err(|_| VERIFY_FILE_FAILED)?;

        Ok(())
    })()
    .err()
    .unwrap_or(OK);

    // `_exit`, not `exit`: destructors and buffered-output flushing belong to
    // the parent's test harness and must not run twice.
    unsafe { libc::_exit(code) }
}

/// Fork, run `f` in the child, and return the child's wait status.
fn in_child(f: impl FnOnce()) -> i32 {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        f();
        // Both children end in `_exit`, so this is unreachable. It exists
        // because a diverging closure cannot be named on stable Rust.
        unsafe { libc::_exit(70) }
    }
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "waitpid failed");
    status
}

/// The filter must actually bite. Without this the next test would pass just as
/// happily with no filter at all.
#[test]
fn the_sandbox_kills_a_writer() {
    let status = in_child(|| canary_child());

    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        let why = match code {
            NO_NEW_PRIVS_REFUSED => "PR_SET_NO_NEW_PRIVS was refused",
            SECCOMP_REFUSED => "PR_SET_SECCOMP was refused; seccomp may be unavailable here",
            SANDBOX_NOT_ENGAGED => "a file was created with the filter installed",
            _ => "unexpected exit",
        };
        panic!("{why} (exit {code}) - the write-capability test cannot mean anything");
    }

    assert!(
        libc::WIFSIGNALED(status),
        "child neither exited nor signalled"
    );
    assert_eq!(
        libc::WTERMSIG(status),
        libc::SIGSYS,
        "expected the write attempt to be killed by SIGSYS",
    );
}

/// The property itself: with writing impossible, verification still works.
#[test]
fn verification_completes_with_the_write_capability_removed() {
    let dir = fixture_dir();
    let signed_jpg = std::fs::read(dir.join("signed_test.jpg")).expect("jpg fixture");
    let signed_mp4 = std::fs::read(dir.join("signed_test.mp4")).expect("mp4 fixture");
    let mp4_path = dir.join("signed_test.mp4");

    // Read the fixtures BEFORE forking, so the child's job is exactly the calls
    // under test.
    let status = in_child(move || verify_child(signed_jpg, signed_mp4, mp4_path));

    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        if sig == libc::SIGSYS {
            panic!(
                "verification attempted a filesystem mutation. The syscall was \
                 refused and the process killed, so this is not a flaky test: \
                 something beneath verify/verify_with_options/verify_file tried \
                 to create, truncate or remove a file.",
            );
        }
        panic!("sandboxed child was killed by signal {sig}");
    }
    assert!(
        libc::WIFEXITED(status),
        "child neither exited nor signalled"
    );

    let code = libc::WEXITSTATUS(status);
    let explain = match code {
        OK => return,
        NO_NEW_PRIVS_REFUSED => "PR_SET_NO_NEW_PRIVS was refused, so no filter could be installed",
        SECCOMP_REFUSED => "PR_SET_SECCOMP was refused; seccomp may be unavailable here",
        VERIFY_FAILED => "verify() failed with writes denied",
        VERIFY_WITH_OPTIONS_FAILED => "verify_with_options() failed with writes denied",
        VERIFY_FILE_FAILED => "verify_file() failed with writes denied",
        _ => "child exited with an unexpected status",
    };
    panic!("{explain} (exit {code})");
}
