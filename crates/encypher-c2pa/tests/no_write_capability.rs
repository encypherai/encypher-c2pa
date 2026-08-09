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
const SIGNED_INPUT_NOT_PARSED: i32 = 23;

/// Everything the sandboxed child needs, gathered before the fork so its own
/// work is exactly the calls under test.
struct Cases {
    signed_jpg: Vec<u8>,
    signed_mp4: Vec<u8>,
    jpg_path: PathBuf,
    mp4_path: PathBuf,
    mimes: Vec<String>,
    extensions: Vec<String>,
}

impl Cases {
    fn collect() -> Self {
        let dir = fixture_dir();
        Self {
            signed_jpg: std::fs::read(dir.join("signed_test.jpg")).expect("jpg fixture"),
            signed_mp4: std::fs::read(dir.join("signed_test.mp4")).expect("mp4 fixture"),
            jpg_path: dir.join("signed_test.jpg"),
            mp4_path: dir.join("signed_test.mp4"),
            mimes: encypher_c2pa::supported_mime_types()
                .into_iter()
                .map(str::to_string)
                .collect(),
            extensions: encypher_c2pa::SUPPORTED_EXTENSIONS
                .iter()
                .map(|(ext, _)| (*ext).to_string())
                .collect(),
        }
    }
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

/// Assemble the seccomp program: allow a fixed set, kill everything else.
///
/// The first version of this was a denylist of mutating syscalls, and it had
/// exactly the weakness the source scan had. A reviewer asked what it did about
/// io_uring, and the answer was nothing: `io_uring_setup` succeeds on this
/// kernel, and a ring can perform `openat` and `write` as submission entries
/// without ever issuing the syscalls the list refused. `setxattr`, `utimensat`
/// and `fallocate` were missing too. Enumerating ways to write is the same
/// losing game one layer down.
///
/// So this is inverted. Verification needs a small, boring set of syscalls -
/// read, map memory, look at the clock - and anything outside it kills the
/// process. Soundness no longer depends on my imagination: it depends on the
/// much easier claim that nothing in the list below can modify a file.
///
/// The two that could, given the wrong argument, are constrained by argument
/// rather than excluded: `openat`/`open` must carry no write flag, and
/// `write`/`writev` must target stdout or stderr. Everything else is either
/// read-only or does not touch the filesystem at all.
///
/// It is deliberately not minimal. Trimming it further would buy nothing and
/// would make the test brittle against an allocator change. What matters is
/// that it is an allowlist, so a new way to write is denied by default instead
/// of denied only if I thought of it.
/// Syscalls the sandboxed scenario actually makes. Removing any one of these
/// kills the run, which `every_allowed_syscall_is_needed` proves on every CI
/// run - so this tier cannot quietly accumulate.
const EXERCISED: &[u32] = &[
    0,   // read
    3,   // close
    332, // statx
    10,  // mprotect
    28,  // madvise
    16,  // ioctl - on a read-only descriptor
    318, // getrandom
    231, // exit_group
];

/// Permitted but not exercised here, and deliberately kept.
///
/// A reviewer asked how the allowlist could be shown minimal rather than merely
/// sufficient. Measuring it was the easy part: the child is forked from a warm
/// process, so it inherits its mappings and its allocator arena and ends up
/// needing only the eight above. Trimming to exactly those would make this
/// suite fail on a machine with a different libc, allocator or kernel, and a
/// test that fails on a contributor's laptop teaches people to delete the test.
///
/// So the surplus is declared instead of hidden. Every entry here is a read,
/// a memory operation, a thread or signal operation, or a clock - none can
/// create or modify a file, which is the only property soundness rests on. The
/// point of splitting the list is that a NEW permission cannot arrive
/// unnoticed: it either proves itself necessary, or it is written down here
/// where a reviewer sees it.
const HEADROOM: &[u32] = &[
    17,  // pread64
    19,  // readv
    295, // preadv
    4,   // stat
    5,   // fstat
    6,   // lstat
    262, // newfstatat
    8,   // lseek
    217, // getdents64
    79,  // getcwd
    89,  // readlink
    267, // readlinkat
    9,   // mmap
    11,  // munmap
    12,  // brk
    25,  // mremap
    13,  // rt_sigaction
    14,  // rt_sigprocmask
    15,  // rt_sigreturn
    131, // sigaltstack
    202, // futex
    24,  // sched_yield
    204, // sched_getaffinity
    39,  // getpid
    186, // gettid
    102, // getuid
    107, // geteuid
    104, // getgid
    108, // getegid
    60,  // exit
    96,  // gettimeofday
    228, // clock_gettime
    229, // clock_getres
    35,  // nanosleep
    230, // clock_nanosleep
    157, // prctl
    158, // arch_prctl
    218, // set_tid_address
    273, // set_robust_list
    334, // rseq
    324, // membarrier
    99,  // sysinfo
    63,  // uname
    7,   // poll
    271, // ppoll
    281, // epoll_pwait
    291, // epoll_create1
    233, // epoll_ctl
    302, // prlimit64
];

/// The filter's allowlist: both tiers.
fn allowed() -> Vec<u32> {
    EXERCISED.iter().chain(HEADROOM).copied().collect()
}

fn filter(exclude: Option<u32>) -> Vec<libc::sock_filter> {
    // Classic BPF opcodes.
    const LD_W_ABS: u16 = 0x20;
    const ALU_AND_K: u16 = 0x54;
    const JMP_JEQ_K: u16 = 0x15;
    const JMP_JGT_K: u16 = 0x25;
    const RET_K: u16 = 0x06;

    // `struct seccomp_data` offsets: nr, arch, instruction_pointer, args[6].
    const OFF_NR: u32 = 0;
    const OFF_ARCH: u32 = 4;
    const OFF_ARG0: u32 = 16;
    const OFF_ARG1: u32 = 24;
    const OFF_ARG2: u32 = 32;

    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;

    // Any of these in the open flags means the caller wants to modify a file.
    // `O_TMPFILE` includes `O_DIRECTORY` and is caught by `O_WRONLY`/`O_RDWR`,
    // which it must be combined with to be useful.
    const WRITE_FLAGS: u32 =
        (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u32;

    // x86_64 numbers for what verification legitimately does: read files and
    // directories, manage its own memory and threads, ask the time, get
    // randomness, and exit. None of these can create or modify a file.

    let ins = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };

    // Refuse to run at all on an unexpected architecture. A filter written
    // against the wrong syscall table is worse than none, because it would
    // silently permit everything it thinks it is denying.
    let mut p = vec![
        ins(LD_W_ABS, 0, 0, OFF_ARCH),
        ins(JMP_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        ins(RET_K, 0, 0, RET_KILL_PROCESS),
        ins(LD_W_ABS, 0, 0, OFF_NR),
    ];

    // A syscall whose verdict depends on an argument: `nr` selects the block,
    // the argument decides. Each block is self-contained so no jump is long.
    let arg_gated = |p: &mut Vec<libc::sock_filter>, nr: u32, off: u32, write_flags: bool| {
        p.push(ins(JMP_JEQ_K, 0, if write_flags { 5 } else { 4 }, nr));
        p.push(ins(LD_W_ABS, 0, 0, off));
        if write_flags {
            // openat/open: allowed only with no write flag set.
            p.push(ins(ALU_AND_K, 0, 0, WRITE_FLAGS));
            p.push(ins(JMP_JEQ_K, 1, 0, 0));
            p.push(ins(RET_K, 0, 0, RET_KILL_PROCESS));
            p.push(ins(RET_K, 0, 0, RET_ALLOW));
        } else {
            // write/writev: allowed only to stdout and stderr.
            p.push(ins(JMP_JGT_K, 1, 0, 2));
            p.push(ins(RET_K, 0, 0, RET_ALLOW));
            p.push(ins(RET_K, 0, 0, RET_KILL_PROCESS));
        }
        p.push(ins(LD_W_ABS, 0, 0, OFF_NR));
    };
    arg_gated(&mut p, 257, OFF_ARG2, true); // openat(dirfd, path, flags, ..)
    arg_gated(&mut p, 2, OFF_ARG1, true); // open(path, flags, ..)
    arg_gated(&mut p, 1, OFF_ARG0, false); // write(fd, ..)
    arg_gated(&mut p, 20, OFF_ARG0, false); // writev(fd, ..)

    // The allowlist proper. Each comparison jumps forward to the single ALLOW,
    // and falling off the end reaches KILL - so an unlisted syscall dies.
    // Minimality testing removes one entry and requires the scenario to die.
    let allowed: Vec<u32> = allowed()
        .into_iter()
        .filter(|nr| Some(*nr) != exclude)
        .collect();

    let start = p.len();
    let allow_at = start + allowed.len() + 1;
    for (i, nr) in allowed.iter().enumerate() {
        let jt = (allow_at - (start + i) - 1) as u8;
        p.push(ins(JMP_JEQ_K, jt, 0, *nr));
    }
    p.push(ins(RET_K, 0, 0, RET_KILL_PROCESS));
    p.push(ins(RET_K, 0, 0, RET_ALLOW));

    p
}

/// Drop the ability to create or modify any file, irreversibly, for this
/// process and everything it goes on to call.
fn engage_sandbox(exclude: Option<u32>) -> Result<(), i32> {
    // Required before an unprivileged process may install a filter.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(NO_NEW_PRIVS_REFUSED);
    }
    let prog = filter(exclude);
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
    if let Err(code) = engage_sandbox(None) {
        unsafe { libc::_exit(code) }
    }
    let _ = std::fs::write("/tmp/encypher-seccomp-canary", b"x");
    // Reaching this line means the filter permitted a file creation.
    unsafe { libc::_exit(SANDBOX_NOT_ENGAGED) }
}

/// Call a syscall that is simply not on the list. Must not survive.
///
/// `io_uring_setup` specifically, because it is what showed the previous
/// denylist to be unsound: a ring performs `openat` and `write` as submission
/// entries, so refusing those syscall numbers refuses nothing. It succeeds on
/// this kernel outside the sandbox. Inside, it is not on the allowlist, and
/// that is the whole difference between the two designs.
fn unlisted_syscall_child() -> ! {
    if let Err(code) = engage_sandbox(None) {
        unsafe { libc::_exit(code) }
    }
    let mut params = [0u8; 120];
    unsafe { libc::syscall(425, 8, params.as_mut_ptr()) };
    unsafe { libc::_exit(SANDBOX_NOT_ENGAGED) }
}

/// Run the public entry points under the filter, across the whole supported
/// surface. Must exit cleanly.
///
/// An earlier version verified one JPEG and one MP4 and asserted only that the
/// call returned `Ok`. A reviewer pointed out that this proves very little: a
/// mutation on a format or an error path never executed is a mutation the
/// sandbox never sees, and `Ok` does not show the manifest was actually parsed.
///
/// So this drives every MIME in `supported_mime_types()` and every extension in
/// `SUPPORTED_EXTENSIONS`, on signed input, on unsigned input, and on truncated
/// input - the error paths being the easiest place for a side effect to hide -
/// and it asserts what the signed cases must actually conclude.
fn verify_child(cases: Cases, exclude: Option<u32>) -> ! {
    let Cases {
        signed_jpg,
        signed_mp4,
        jpg_path,
        mp4_path,
        mimes,
        extensions,
    } = cases;

    let code = (|| {
        engage_sandbox(exclude)?;

        // The signed fixtures must reach a real conclusion, not merely return.
        // If verification silently degraded to "no provenance" the sandbox would
        // look clean while proving nothing about the parsing path.
        for (bytes, mime) in [(&signed_jpg, "image/jpeg"), (&signed_mp4, "video/mp4")] {
            let report = verify(bytes, mime).map_err(|_| VERIFY_FAILED)?;
            if !report.present || report.integrity != "valid" {
                return Err(SIGNED_INPUT_NOT_PARSED);
            }
        }

        let report = verify_with_options(&signed_mp4, "video/mp4", &VerifyOptions::default())
            .map_err(|_| VERIFY_WITH_OPTIONS_FAILED)?;
        if !report.present || report.hard_binding != "match" {
            return Err(SIGNED_INPUT_NOT_PARSED);
        }

        for path in [&jpg_path, &mp4_path] {
            let report = verify_file(path, None, &VerifyOptions::default())
                .map_err(|_| VERIFY_FILE_FAILED)?;
            if !report.present {
                return Err(SIGNED_INPUT_NOT_PARSED);
            }
        }

        // Every declared MIME, on content that does not match it. These are the
        // error paths: a format sniffer, a truncated parse, an unsupported
        // branch. Success or failure is equally fine here - what matters is that
        // the code ran with writing impossible.
        for mime in &mimes {
            let _ = verify(b"", mime);
            let _ = verify(b"not a media file at all", mime);
            let _ = verify(&signed_jpg[..signed_jpg.len() / 2], mime);
            let _ = verify_with_options(&signed_mp4, mime, &VerifyOptions::default());
        }

        // Every declared extension, so MIME inference runs on each one. The file
        // does not exist, which exercises the error path that a careless
        // implementation might use to create it.
        for ext in &extensions {
            let missing = jpg_path.with_extension(ext);
            let _ = verify_file(&missing, None, &VerifyOptions::default());
        }

        // And the real fixtures under an explicitly overridden MIME.
        for mime in &mimes {
            let _ = verify_file(&jpg_path, Some(mime), &VerifyOptions::default());
        }

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

/// The allowlist is default-deny, and this is what makes that claim testable.
#[test]
fn the_sandbox_kills_an_unlisted_syscall() {
    let status = in_child(|| unlisted_syscall_child());

    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        let why = match code {
            NO_NEW_PRIVS_REFUSED => "PR_SET_NO_NEW_PRIVS was refused",
            SECCOMP_REFUSED => "PR_SET_SECCOMP was refused; seccomp may be unavailable here",
            SANDBOX_NOT_ENGAGED => {
                "io_uring_setup returned instead of being killed - the filter is \
                 not default-deny, so every syscall absent from the allowlist is \
                 permitted and this whole test file proves nothing"
            }
            _ => "unexpected exit",
        };
        panic!("{why} (exit {code})");
    }

    assert!(
        libc::WIFSIGNALED(status),
        "child neither exited nor signalled"
    );
    assert_eq!(
        libc::WTERMSIG(status),
        libc::SIGSYS,
        "expected an unlisted syscall to be killed by SIGSYS",
    );
}

/// Every entry in the exercised tier is load-bearing, and the two tiers agree.
///
/// An allowlist answers "is this sound?" far better than a denylist, but it
/// invites a different rot: entries drift in, nobody can say why, and the list
/// slowly becomes permissive. A reviewer asked how it could be shown minimal
/// rather than merely sufficient. This is the answer, and it is honest about
/// which half is proved.
///
/// For each syscall in `EXERCISED`, build the filter without it and run the
/// whole scenario: it must die. Anything that survives was not needed and
/// belongs in `HEADROOM` or nowhere. Nothing may appear in both tiers, so a
/// permission cannot be justified twice over.
#[test]
fn every_allowed_syscall_is_needed() {
    let overlap: Vec<u32> = EXERCISED
        .iter()
        .copied()
        .filter(|nr| HEADROOM.contains(nr))
        .collect();
    assert!(
        overlap.is_empty(),
        "listed in both EXERCISED and HEADROOM: {overlap:?}",
    );

    let mut unnecessary = Vec::new();
    for nr in EXERCISED {
        let cases = Cases::collect();
        let status = in_child(move || verify_child(cases, Some(*nr)));
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == OK {
            unnecessary.push(*nr);
        }
    }

    assert!(
        unnecessary.is_empty(),
        "these are in EXERCISED but the scenario runs without them: \
         {unnecessary:?}. Either move them to HEADROOM, where unexercised \
         permissions are declared and justified, or delete them.",
    );
}

/// The property itself: with writing impossible, verification still works.
#[test]
fn verification_completes_with_the_write_capability_removed() {
    // Read the fixtures and the format tables BEFORE forking, so the child's
    // job is exactly the calls under test.
    let cases = Cases::collect();
    let status = in_child(move || verify_child(cases, None));

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
        SIGNED_INPUT_NOT_PARSED => {
            "a signed fixture did not verify as present and valid inside the \
             sandbox, so the scenario proved nothing about the parsing path"
        }
        _ => "child exited with an unexpected status",
    };
    panic!("{explain} (exit {code})");
}
