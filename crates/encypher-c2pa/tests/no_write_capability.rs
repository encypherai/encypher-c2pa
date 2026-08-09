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

use std::collections::HashSet;
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
const INHERITED_MAPPING_SURVIVED: i32 = 24;

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

// How the permission lists below are meant to be read.
//
// The first version was a denylist of mutating syscalls, and it had exactly the
// weakness the source scan had. A reviewer asked what it did about io_uring,
// and the answer was nothing: `io_uring_setup` succeeds on this kernel, and a
// ring performs `openat` and `write` as submission entries without ever issuing
// the syscalls the list refused. `setxattr`, `utimensat` and `fallocate` were
// missing too. Enumerating ways to write is the same losing game one layer
// down.
//
// So it is inverted. Verification needs a small, boring set of syscalls - read,
// map memory, look at the clock - and anything outside it kills the process.
// Soundness no longer depends on my imagination: it depends on the much easier
// claim that nothing in the lists below can modify a file.
//
// Three are constrained by argument rather than excluded: `openat` and `open`
// must carry no write flag, and `ioctl` must be the one terminal query the
// runtime makes on startup. Everything else is a read, a memory operation, a
// thread or signal operation, or a clock.
//
// `write` and `writev` are not here at all. They were briefly permitted to
// stdout so the child could print, until it became clear that a harness which
// redirects stdout into a file hands a writer a live descriptor. The child
// reports by exit status.
//
// The lists are deliberately not minimal. Trimming further would buy nothing
// and would make the suite brittle against an allocator change. What matters is
// that they are an allowlist, so a new way to write is denied by default rather
// than denied only if someone thought of it.

/// Syscalls the sandboxed scenario actually makes. Removing any one of these
/// kills the run, which `every_allowed_syscall_is_needed` proves on every CI
/// run - so this tier cannot quietly accumulate.
const EXERCISED: &[u32] = &[
    0,   // read
    3,   // close
    332, // statx
    10,  // mprotect
    28,  // madvise
    318, // getrandom
];

/// Permitted but not exercised here, and deliberately kept.
///
/// A reviewer asked how the allowlist could be shown minimal rather than merely
/// sufficient. Measuring it was the easy part: the child is forked from a warm
/// process, so it inherits its mappings and its allocator arena and ends up
/// needing only the six above. Trimming to exactly those would make this
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
    // Harness, not verification. The child ends in `_exit`, so removing this
    // always kills the run and it would pass the necessity test without that
    // proving anything about the code under test. Declared here instead of
    // taking undeserved credit there.
    231, // exit_group
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

/// The terminal-attribute query behind `isatty`, which the Rust runtime makes
/// on startup. The only `ioctl` request permitted.
const TCGETS: u32 = 0x5401;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

// Byte offsets into `struct seccomp_data`: nr, arch, instruction_pointer, then
// args[6]. The argument offsets are named here because the gate table below
// refers to them, and a wrong offset would silently inspect the wrong value.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG1: u32 = 24;
const OFF_ARG2: u32 = 32;

/// How a permitted syscall's arguments are constrained.
enum Gate {
    /// `openat`/`open`: the flags argument may carry no write flag.
    NoWriteFlags { arg: u32 },
    /// `ioctl`: the request argument must be exactly this value.
    ArgEquals { arg: u32, value: u32 },
}

/// Permitted only for specific argument values, so these sit in neither tier
/// above: the syscall number alone does not decide the verdict.
///
/// The filter is generated from this table, so a permission cannot exist in the
/// program without appearing here.
const ARGUMENT_GATED: &[(u32, Gate)] = &[
    // openat(dirfd, path, flags, mode) - flags is args[2], at offset 32.
    (257, Gate::NoWriteFlags { arg: OFF_ARG2 }),
    // open(path, flags, mode) - flags is args[1], at offset 24.
    (2, Gate::NoWriteFlags { arg: OFF_ARG1 }),
    // ioctl(fd, request, ..) - request is args[1]. Only TCGETS, the terminal
    // query the Rust runtime makes on startup.
    (
        16,
        Gate::ArgEquals {
            arg: OFF_ARG1,
            value: TCGETS,
        },
    ),
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
    const RET_K: u16 = 0x06;

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

    // The argument-gated syscalls, built FROM the table rather than alongside
    // it. A reviewer asked whether a syscall could be permitted by the filter
    // while appearing in none of the three lists - the direction the earlier
    // check could not see. Generating every permission from the lists makes
    // that unrepresentable rather than merely tested: there is nowhere else
    // for a permission to come from.
    //
    // `write` and `writev` appear in no list, and so in no filter. An earlier
    // version permitted them to fd 1-2 so the child could print, which handed a
    // writer a live descriptor whenever the harness redirected stdout into a
    // file. The child reports by exit status, so it does not need them.
    for (nr, gate) in ARGUMENT_GATED {
        match gate {
            // openat/open: no write flag may be set.
            Gate::NoWriteFlags { arg } => {
                p.push(ins(JMP_JEQ_K, 0, 5, *nr));
                p.push(ins(LD_W_ABS, 0, 0, *arg));
                p.push(ins(ALU_AND_K, 0, 0, WRITE_FLAGS));
                p.push(ins(JMP_JEQ_K, 1, 0, 0));
                p.push(ins(RET_K, 0, 0, RET_KILL_PROCESS));
                p.push(ins(RET_K, 0, 0, RET_ALLOW));
            }
            // ioctl: one permitted request. `FS_IOC_SETFLAGS` on a READ-ONLY
            // descriptor toggled `FS_NODUMP_FL`, so the descriptor's mode is
            // not the safety property it appears to be - the request is.
            Gate::ArgEquals { arg, value } => {
                p.push(ins(JMP_JEQ_K, 0, 4, *nr));
                p.push(ins(LD_W_ABS, 0, 0, *arg));
                p.push(ins(JMP_JEQ_K, 1, 0, *value));
                p.push(ins(RET_K, 0, 0, RET_KILL_PROCESS));
                p.push(ins(RET_K, 0, 0, RET_ALLOW));
            }
        }
        p.push(ins(LD_W_ABS, 0, 0, OFF_NR));
    }

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

/// Unmap every shared file-backed mapping inherited from the parent.
///
/// A shared mapping of a file is a write capability regardless of its current
/// protection, because `mprotect` can restore `PROT_WRITE` and a store then
/// reaches the file with no syscall at all. Closing the descriptor it was made
/// through does not remove it.
///
/// `/proc/self/maps` lines are
/// `start-end perms offset dev inode pathname`. The rule applied is:
///
///   unmap it when the fourth character of `perms` is `s` and `inode` is not 0.
///
/// That is deliberately conservative rather than exact, and the difference is
/// worth stating because an earlier version of this comment claimed the exact
/// version and was wrong. Inode 0 does mean anonymous, but the converse fails:
/// a reviewer showed that `MAP_SHARED | MAP_ANONYMOUS` is reported as
/// `/dev/zero` with a real inode, so the rule sweeps up some anonymous shared
/// mappings too. That costs a little memory the child was not going to use and
/// removes a class of mapping this code would otherwise have to reason about,
/// so it is left as is - but it is not the rule "unmap file-backed mappings",
/// and a maintainer should not be told that it is.
///
/// The decision uses the inode rather than the pathname on purpose. A pathname
/// may contain spaces, so splitting on whitespace cannot delimit it, and the
/// first version got the field arithmetic wrong anyway: it read field 4 while
/// believing that was the path. Field 4 is the inode. It behaved only because
/// nothing here maps a file shared.
fn unmap_inherited_shared_mappings() -> Result<(), ()> {
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(|_| ())?;

    for line in maps.lines() {
        let fields: Vec<&str> = line.split_whitespace().take(5).collect();
        let [range, perms, _offset, _dev, inode] = fields[..] else {
            continue;
        };
        if perms.as_bytes().get(3) != Some(&b's') || inode == "0" {
            continue;
        }

        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start, 16),
            usize::from_str_radix(end, 16),
        ) else {
            continue;
        };

        let rc = unsafe { libc::munmap(start as *mut libc::c_void, end - start) };
        if rc != 0 {
            return Err(());
        }
    }

    Ok(())
}

/// Drop the ability to create or modify any file, irreversibly, for this
/// process and everything it goes on to call.
fn engage_sandbox(exclude: Option<u32>) -> Result<(), i32> {
    // Two kinds of inherited capability have to go before the filter does
    // anything, because a filter over syscall numbers cannot see either.
    //
    // First, descriptors. A reviewer took an inherited `O_RDWR` descriptor and
    // used it; the same inheritance let `ioctl` flip `FS_NODUMP_FL` on a
    // read-only one. The child starts with nothing open: it never prints, and
    // it opens its fixtures by path afterwards, read-only.
    unsafe { libc::close_range(0, u32::MAX, 0) };

    // Second, and less obvious: shared file-backed MAPPINGS. Closing a
    // descriptor does not remove the mapping made through it. The same
    // reviewer mapped a file `MAP_SHARED` before the fork, let the child close
    // every descriptor and install the filter, then used the permitted
    // `mprotect` to restore `PROT_WRITE` on the surviving VMA and changed the
    // file with an ordinary memory store - no syscall for the filter to refuse.
    //
    // So unmap them. `/proc/self/maps` names every mapping; anything shared and
    // file-backed is a write capability that predates the sandbox. This runs
    // before the filter, while reading `/proc` and unmapping are permitted, and
    // a mapping that cannot be unmapped is a hard failure rather than a
    // warning - the point of the exercise is that none survives.
    if unmap_inherited_shared_mappings().is_err() {
        return Err(INHERITED_MAPPING_SURVIVED);
    }

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
        // One predicate for all three entry points: an earlier version checked
        // a different pair of fields at each call, so a report could satisfy
        // the suite while failing the property the README describes.
        let signed_ok = |r: &encypher_c2pa::VerificationReport| {
            r.present && r.integrity == "valid" && r.hard_binding == "match"
        };

        for (bytes, mime) in [(&signed_jpg, "image/jpeg"), (&signed_mp4, "video/mp4")] {
            let report = verify(bytes, mime).map_err(|_| VERIFY_FAILED)?;
            if !signed_ok(&report) {
                return Err(SIGNED_INPUT_NOT_PARSED);
            }
        }

        let report = verify_with_options(&signed_mp4, "video/mp4", &VerifyOptions::default())
            .map_err(|_| VERIFY_WITH_OPTIONS_FAILED)?;
        if !signed_ok(&report) {
            return Err(SIGNED_INPUT_NOT_PARSED);
        }

        for path in [&jpg_path, &mp4_path] {
            let report = verify_file(path, None, &VerifyOptions::default())
                .map_err(|_| VERIFY_FILE_FAILED)?;
            if !signed_ok(&report) {
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

/// Each capability a reviewer actually used, pinned so it cannot come back.
///
/// These are not hypothetical. Every one was demonstrated end to end against an
/// earlier version of this filter, on a real file, while the whole suite
/// reported success. They are listed by the route rather than the syscall
/// because that is how they were found.
#[test]
fn no_writable_descriptor_reaches_the_sandbox() {
    // The mmap route is closed by descriptor hygiene rather than by the filter,
    // so it needs its own assertion. A reviewer took an inherited `O_RDWR`
    // descriptor, mapped it `MAP_SHARED`, and rewrote a file's bytes without
    // issuing one denied syscall. No filter over syscall numbers can see that;
    // the only defence is that no such descriptor exists.
    //
    // Checked before the filter goes on, because `fcntl` is not permitted after.
    const A_DESCRIPTOR_IS_WRITABLE: i32 = 30;
    const MMAP_SHARED_SUCCEEDED: i32 = 31;

    let status = in_child(|| {
        unsafe { libc::close_range(0, u32::MAX, 0) };

        for fd in 0..256 {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                continue; // not open, which is the expected case
            }
            let access = flags & libc::O_ACCMODE;
            if access == libc::O_WRONLY || access == libc::O_RDWR {
                unsafe { libc::_exit(A_DESCRIPTOR_IS_WRITABLE) }
            }
        }

        // And with nothing writable open, the mapping the reviewer used cannot
        // be built at all.
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                3,
                0,
            )
        };
        if mapped != libc::MAP_FAILED {
            unsafe { libc::_exit(MMAP_SHARED_SUCCEEDED) }
        }

        unsafe { libc::_exit(OK) }
    });

    assert!(
        libc::WIFEXITED(status),
        "descriptor check did not exit cleanly"
    );
    match libc::WEXITSTATUS(status) {
        OK => {}
        A_DESCRIPTOR_IS_WRITABLE => panic!(
            "a writable descriptor survived into the sandbox - mmap MAP_SHARED \
             over it rewrites a file without any denied syscall",
        ),
        MMAP_SHARED_SUCCEEDED => panic!("a writable shared mapping was still obtainable"),
        code => panic!("unexpected exit {code}"),
    }
}

#[test]
fn an_inherited_shared_mapping_cannot_outlive_the_sandbox() {
    // The reviewer's exact attack, kept as a test because it is the subtlest
    // route found here and the only one that needed no syscall at all.
    //
    // Map a file MAP_SHARED before forking, with PROT_READ so it looks
    // harmless. The child closes every descriptor and installs the filter -
    // neither of which touches the mapping. Then `mprotect`, which is
    // permitted, restores PROT_WRITE on the surviving VMA and a plain store
    // changes the file. Nothing was denied because nothing was asked.
    //
    // The fix is that the mapping is gone by the time the filter goes on, so
    // the mprotect has nothing to upgrade.
    const MPROTECT_SUCCEEDED: i32 = 40;

    let dir = std::env::temp_dir().join(format!("encypher-vma-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("target");
    std::fs::write(&path, b"A").expect("seed");

    let raw = std::ffi::CString::new(path.to_str().expect("path")).expect("cstring");
    let fd = unsafe { libc::open(raw.as_ptr(), libc::O_RDWR) };
    assert!(fd >= 0, "open target");
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert!(mapped != libc::MAP_FAILED, "map target");

    let status = in_child(move || {
        if let Err(code) = engage_sandbox(None) {
            unsafe { libc::_exit(code) }
        }
        // If the mapping survived, this upgrade succeeds and the store lands.
        if unsafe { libc::mprotect(mapped, 4096, libc::PROT_READ | libc::PROT_WRITE) } == 0 {
            unsafe { std::ptr::write_volatile(mapped as *mut u8, b'Z') };
            unsafe { libc::_exit(MPROTECT_SUCCEEDED) }
        }
        unsafe { libc::_exit(OK) }
    });

    unsafe { libc::munmap(mapped, 4096) };
    unsafe { libc::close(fd) };
    let after = std::fs::read(&path).expect("read back");
    let _ = std::fs::remove_dir_all(&dir);

    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == MPROTECT_SUCCEEDED {
        panic!(
            "an inherited MAP_SHARED mapping survived into the sandbox: \
             mprotect restored write access and the file now reads {after:?}. \
             Closing descriptors does not remove mappings made through them.",
        );
    }
    assert_eq!(after, b"A", "the sandboxed child changed the backing file");
}

#[test]
fn the_demonstrated_bypasses_all_die() {
    let probes: &[(&str, fn())] = &[
        // Writing to stdout when the harness has redirected it into a file.
        // The fix was to drop write/writev rather than permit them to fd 1-2.
        ("write to fd 1", || unsafe {
            libc::write(1, [120u8].as_ptr() as *const _, 1);
        }),
        // Opening anything for writing at all - the precondition for the
        // MAP_SHARED mapping trick below.
        ("open O_RDWR", || unsafe {
            libc::open(c"/tmp".as_ptr(), libc::O_RDWR);
        }),
        // FS_IOC_SETFLAGS on a READ-ONLY descriptor toggled FS_NODUMP_FL, so
        // read-only is not the safety property it appears to be. ioctl is now
        // gated by request, not by descriptor.
        ("ioctl FS_IOC_SETFLAGS", || unsafe {
            let flags: libc::c_long = 0;
            libc::ioctl(0, 0x4008_6602, &flags);
        }),
        // io_uring performs openat and write as ring operations, which is what
        // made the original denylist unsound.
        ("io_uring_setup", || unsafe {
            let mut params = [0u8; 120];
            libc::syscall(425, 8, params.as_mut_ptr());
        }),
    ];

    for (name, probe) in probes {
        let status = in_child(|| {
            if let Err(code) = engage_sandbox(None) {
                unsafe { libc::_exit(code) }
            }
            probe();
            unsafe { libc::_exit(SANDBOX_NOT_ENGAGED) }
        });

        assert!(
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS,
            "{name}: expected SIGSYS, but the capability survived the filter. \
             This route was demonstrated against an earlier version and must \
             stay closed.",
        );
    }
}

/// A value the interpreter is tracking: a concrete number, or anything at all.
///
/// Syscall arguments are `Unknown`, because the point is to say something true
/// for every argument a caller might pass, rather than for three that happened
/// to be tried.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Val {
    Known(u32),
    Unknown,
}

/// Every verdict the filter can reach for a given syscall, over all arguments.
///
/// The first version of this took three concrete argument profiles and ran
/// them. It looked exhaustive and was not: a reviewer added a permission for
/// `renameat2` guarded by `args[0] == 3`, which none of the three profiles hit,
/// so the check stayed green while the sandboxed child opened directories until
/// it held fd 3 and renamed a real file.
///
/// So arguments are not sampled here, they are unknown. Where a comparison
/// tests an unknown value both outcomes are explored, and what comes back is
/// the set of verdicts reachable by ANY argument. A conditional ALLOW is then
/// simply an ALLOW.
///
/// Only the four opcodes this program uses are modelled; anything else panics.
/// A separate check requires EVERY instruction to be modelled, reachable or
/// not, because an opcode encountered only on a path this walk considers dead
/// would otherwise pass in silence - and "dead according to the model" is
/// exactly the thing being taken on trust.
///
/// The program has no backward jumps and each state is visited once, so the
/// walk terminates.
fn reachable_verdicts(program: &[libc::sock_filter], nr: u32) -> HashSet<u32> {
    walk(program, nr).into_iter().map(|(v, _)| v).collect()
}

/// One thing the filter learned on the way to a verdict:
/// `data[offset] & mask == value`.
///
/// Every test this program makes has that shape - load a word, optionally mask
/// it, compare for equality - so a path condition is just a list of these.
type Constraint = (u32, u32, u32);

/// Walk the filter, returning every verdict it can reach together with what had
/// to be true of the arguments to reach it.
///
/// Verdicts alone were not enough. The reverse check asked only WHICH syscalls
/// could be allowed, then skipped the listed ones as permitted by definition -
/// so the argument gates were never checked at all. A reviewer planted a plain
/// `RET_ALLOW` for `openat` when `dirfd == 3`, which is listed, so nothing
/// looked at it; the child opened four directories to get fd 3 and created a
/// real file with `O_CREAT`.
///
/// Being listed is permission to be reached, not permission to be reached on
/// any terms. Carrying the conditions along lets the terms be checked too.
fn walk(program: &[libc::sock_filter], nr: u32) -> Vec<(u32, Vec<Constraint>)> {
    // `seccomp_data` is addressed by byte offset. `nr` and `arch` are
    // determined for a given syscall; every argument word is not.
    let load = |k: u32| match k {
        OFF_NR => Val::Known(nr),
        OFF_ARCH => Val::Known(AUDIT_ARCH_X86_64),
        _ => Val::Unknown,
    };

    // The accumulator, plus where it came from. The origin is what turns a
    // comparison into a statement about an argument: after `A = data[off] & m`,
    // learning `A == k` is learning `data[off] & m == k`.
    #[derive(Clone, PartialEq, Eq, Hash)]
    struct State {
        pc: usize,
        val: Val,
        origin: Option<(u32, u32)>,
        conditions: Vec<Constraint>,
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();

    // The accumulator starts `Unknown` rather than `Known(0)`. The kernel zeroes
    // it and this program loads before it compares, so the two agree here - but
    // they fail differently if that stops being true. Over-approximating finds
    // ALLOWs that are not really reachable, a loud false alarm;
    // under-approximating misses one that is, the failure this exists to catch.
    let mut work = vec![State {
        pc: 0,
        val: Val::Unknown,
        origin: None,
        conditions: Vec::new(),
    }];

    while let Some(s) = work.pop() {
        if !seen.insert(s.clone()) {
            continue;
        }
        let i = program[s.pc];
        match i.code {
            // LD_W_ABS
            0x20 => work.push(State {
                pc: s.pc + 1,
                val: load(i.k),
                origin: Some((i.k, u32::MAX)),
                ..s
            }),
            // ALU_AND_K
            0x54 => work.push(State {
                pc: s.pc + 1,
                val: match s.val {
                    Val::Known(v) => Val::Known(v & i.k),
                    Val::Unknown => Val::Unknown,
                },
                origin: s.origin.map(|(off, mask)| (off, mask & i.k)),
                ..s
            }),
            // JMP_JEQ_K
            0x15 => {
                let taken = s.pc + 1 + usize::from(i.jt);
                let missed = s.pc + 1 + usize::from(i.jf);
                match s.val {
                    // A determined comparison goes one way, as the kernel would.
                    Val::Known(v) => work.push(State {
                        pc: if v == i.k { taken } else { missed },
                        ..s
                    }),
                    // An undetermined one goes both, because some caller can
                    // arrange either. Taking the equal branch is where a fact
                    // about an argument is learned.
                    Val::Unknown => {
                        let mut learned = s.conditions.clone();
                        if let Some((off, mask)) = s.origin {
                            learned.push((off, mask, i.k));
                        }
                        work.push(State {
                            pc: taken,
                            val: Val::Known(i.k),
                            origin: s.origin,
                            conditions: learned,
                        });
                        work.push(State { pc: missed, ..s });
                    }
                }
            }
            // RET_K
            0x06 => out.push((i.k, s.conditions)),
            other => panic!("filter uses opcode {other:#x}, which this interpreter does not model"),
        }
    }

    out
}

/// No syscall is permitted that is not written down, for any argument.
///
/// This invariant has been wrong twice, each time in a way that looked right.
///
/// First it ran one direction only - every listed number must appear somewhere
/// in the program - which catches a list entry that was never wired up and
/// misses a permission wired up and never listed. A reviewer added a bare
/// `renameat2` permission and renamed a real file with every test green.
///
/// Then it asked the filter directly, but with three concrete argument
/// profiles. The same reviewer guarded the same permission on `args[0] == 3`,
/// which no profile happened to hit, opened directories in the sandboxed child
/// until it held fd 3, and renamed a real file with every test green again.
///
/// Sampling arguments cannot establish a statement about all arguments. So the
/// arguments are unknown and both sides of an undetermined comparison are
/// explored: for an unlisted syscall, EVERY reachable path must end in KILL.
#[test]
fn the_interpreter_models_every_instruction() {
    // The walk panics on an opcode it does not model, which is the right
    // behaviour but only fires on a path it decides is reachable. That is
    // circular: the reachability decision is what the model is for. So check
    // the whole program regardless of reachability.
    //
    // Classic BPF has more than these four - notably the X register, indexed
    // loads and BPF_MISC. None appear here, and if one ever does, the honest
    // outcome is a failure that says so rather than a walk quietly reasoning
    // about an instruction set that is not the one being run.
    const MODELLED: &[u16] = &[
        0x20, // LD_W_ABS
        0x54, // ALU_AND_K
        0x15, // JMP_JEQ_K
        0x06, // RET_K
    ];

    let unmodelled: Vec<(usize, u16)> = filter(None)
        .iter()
        .enumerate()
        .filter(|(_, i)| !MODELLED.contains(&i.code))
        .map(|(pc, i)| (pc, i.code))
        .collect();

    assert!(
        unmodelled.is_empty(),
        "the filter contains instructions the interpreter does not model, at \
         (index, opcode): {unmodelled:?}. Either model them or stop claiming \
         the reverse invariant, because the walk cannot reason about them.",
    );
}

#[test]
fn every_argument_gate_is_actually_enforced() {
    // Being on a list is permission to be reached, not permission to be reached
    // on any terms.
    //
    // The reverse check skipped listed syscalls as permitted by definition, so
    // nothing ever looked at the argument gates. A reviewer planted a plain
    // RET_ALLOW for openat conditional on dirfd == 3 - openat is listed, so the
    // check passed it - then opened four directories in the sandboxed child to
    // obtain fd 3 and created a real file with O_CREAT. Eight tests green.
    //
    // So for each gated syscall, every path that reaches ALLOW must have learned
    // the fact the gate exists to establish. A path that arrives by some other
    // route has not been through the gate, whatever else it checked.
    const ACTION: u32 = 0xffff_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const WRITE_FLAGS: u32 =
        (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u32;

    let program = filter(None);

    for (nr, gate) in ARGUMENT_GATED {
        // The constraint the gate is supposed to impose, taken from the same
        // table the filter is generated from.
        let required: Constraint = match gate {
            Gate::NoWriteFlags { arg } => (*arg, WRITE_FLAGS, 0),
            Gate::ArgEquals { arg, value } => (*arg, u32::MAX, *value),
        };

        for (verdict, conditions) in walk(&program, *nr) {
            if verdict & ACTION != RET_ALLOW {
                continue;
            }
            assert!(
                conditions.contains(&required),
                "syscall {nr} can reach ALLOW without its gate: the path \
                 established {conditions:x?}, which does not include \
                 {required:x?}. A gated syscall that can be allowed by another \
                 route is not gated.",
            );
        }
    }
}

#[test]
fn the_filter_permits_nothing_unlisted() {
    // A seccomp return value is an ACTION in the high 16 bits and DATA in the
    // low 16. The kernel masks before deciding, so 0x7fff_0001 is every bit as
    // permissive as 0x7fff_0000.
    //
    // The first version of this compared for equality with `RET_ALLOW`, and a
    // reviewer walked past it twice over: `RET_ALLOW | 1` passed the test while
    // the kernel renamed a real file, and so did `SECCOMP_RET_LOG`, which logs
    // a syscall and then runs it.
    //
    // Enumerating the permissive actions would repeat the mistake this file has
    // now made three times - allowlists are what it concluded, twice, and then
    // it wrote a denylist over return codes anyway. So the test is inverted:
    // for an unlisted syscall, every reachable verdict must be EXACTLY the kill
    // this filter issues. Not "not allow" - exactly kill. Any other value,
    // whatever a future kernel decides it means, is a failure.
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const ACTION: u32 = 0xffff_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;

    let program = filter(None);
    let listed: Vec<u32> = allowed()
        .into_iter()
        .chain(ARGUMENT_GATED.iter().map(|(nr, _)| *nr))
        .collect();

    let permitted: Vec<(u32, Vec<u32>)> = (0..600u32)
        .filter(|nr| !listed.contains(nr))
        .filter_map(|nr| {
            let stray: Vec<u32> = reachable_verdicts(&program, nr)
                .into_iter()
                .filter(|v| *v != RET_KILL_PROCESS)
                .collect();
            (!stray.is_empty()).then_some((nr, stray))
        })
        .collect();

    assert!(
        permitted.is_empty(),
        "unlisted syscalls can reach a verdict other than kill: {permitted:x?}. \
         Every permission must be written down, or the lists stop describing \
         the program.",
    );

    // The walk is only worth anything if it reaches the ALLOW returns at all.
    // A filter it could not traverse would report an empty set for everything
    // and pass in silence. Matched on the action, for the same reason as above.
    for nr in listed {
        assert!(
            reachable_verdicts(&program, nr)
                .iter()
                .any(|v| v & ACTION == RET_ALLOW),
            "syscall {nr} is listed as permitted, but no path through the \
             filter reaches ALLOW for it",
        );
    }
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
    // Every permitted syscall appears in exactly one list. Without this the
    // argument-gated three sat outside both tiers, invisible to these checks.
    let gated_numbers: Vec<u32> = ARGUMENT_GATED.iter().map(|(nr, _)| *nr).collect();
    let lists = [
        ("EXERCISED", EXERCISED),
        ("HEADROOM", HEADROOM),
        ("ARGUMENT_GATED", gated_numbers.as_slice()),
    ];
    for (i, (name_a, a)) in lists.iter().enumerate() {
        for (name_b, b) in lists.iter().skip(i + 1) {
            let overlap: Vec<u32> = a.iter().copied().filter(|nr| b.contains(nr)).collect();
            assert!(
                overlap.is_empty(),
                "listed in both {name_a} and {name_b}: {overlap:?}",
            );
        }
    }

    // And the lists describe the filter that is actually built, rather than a
    // parallel document that can drift away from it.
    let program = filter(None);
    for nr in EXERCISED.iter().chain(HEADROOM).chain(&gated_numbers) {
        assert!(
            program.iter().any(|i| i.k == *nr),
            "syscall {nr} is listed as permitted but appears nowhere in the \
             assembled filter",
        );
    }

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
