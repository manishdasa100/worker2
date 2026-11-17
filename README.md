# CodingLemons worker2

Executes untrusted user submissions for a LeetCode-style judge and returns
verdicts. A clean rebuild of `../worker` that keeps the proven execution core
and closes its security gaps. Same Redis streams, payloads and heartbeat key as
before, apart from the additive fields and the `worker_type` rename below.

## Contract (the backend depends on it)

- **Submissions**: consumed from `stream:pending-submissions` (group `workers`).
  Entry field `body` = JSON `{jobId, language, userCode(b64), driverCode(b64),
  task, timeLimit(CPU-ms), memoryLimit(MB), testCases:[{input,expectedOutput}],
  slowCode?, hogCode?}`.
- **Results**: XADD'd to `stream:execution-results`. Entry field `body` = JSON
  `{job_id, status: COMPLETED|FAILED, worker_type: "GVISOR_WORKER",
  execution_report: <JSON string, COMPLETED only>, error?: <string, FAILED only>}`.
  `worker_type` was `NSJAIL_WORKER`; the backend must accept the new value
  before this worker publishes to production.
- **Liveness**: key `executor:nsjail:heartbeat` (SET+EX, existence-gated). The
  backend only enqueues while it exists. Shared by all workers; never deleted.
  Refreshed only while at least one slot's executor reports ready.
- **Retries**: a job delivered a third time (its executor died twice) is
  published `FAILED` with error `retries exhausted` instead of being run again.
- **Tasks**: `RUN_CODE` (run all, report each), `SUBMIT_CODE` (stop at first
  fail), `CALIBRATE` (measure a reference solution to derive a problem's limits).

## Architecture

```
Consumer, on the host (holds the Redis credentials, no judging code):
main.py        startup: config, validation, logging
consumer.py    async loop: readiness, free-slot reads, run_job to executors, liveness, keep-alive, draining
redis_io.py    ALL Redis: consume / ack / touch / beat / publish (at-least-once, 3-delivery limit)

Executor, one per slot in a runsc container (Dockerfile; no secrets, no network):
executor.py    answers run_job on its unix socket, one job at a time
judge.py       verdict pipeline: compile (sandboxed) -> run tests -> classify
calibrate.py   CALIBRATE: measure reference + slow/hog gap verification
sandbox.py     nsjail wrapper; run + compile profiles; CPU-ms TLE, cgroup metrics
cgroups.py     per-jail cgroups on runsc's v1 cgroupfs
languages/     declarative handlers (write_files / compile_commands / run_command)
sandbox/       run.cfg + compile.cfg (jail profiles), run.kafel + compile.kafel (seccomp), the jails' passwd + group
tools/         profile_syscalls.py: strace the toolchains to re-check the seccomp policies
```

Separation of concerns is the structural change from worker1: transport,
judging, and sandboxing no longer bleed into each other.

## Security model (defense in depth)

Every execution — **including compilation** — runs inside nsjail, inside an
executor container under gVisor (`runsc`, `--network=none`). The executor is
root in its container (with gVisor's `CAP_SYS_ADMIN`, to mount workspaces); each
jail runs as one unprivileged user mapped to the slot's own host uid
(`JAIL_UID`, ≥ 61000: 61001 for slot 1, 61002 for slot 2), which owns nothing.
Each slot's executor is pinned to its own core; core 0 stays with the consumer.

| Boundary | Enforced by |
|---|---|
| No host filesystem | tmpfs `/`, the language's toolchain paths read-only (none for a static binary) + the code dir; no `/proc` or `/sys`; fake `/etc/passwd` and `/etc/group`; `/dev` holds null, zero and urandom |
| Workspace | a fresh tmpfs per job, 64 MB and 1024 inodes, unmounted afterwards: compiles can't fill the disk and nothing reaches the next job |
| No network | empty net namespace |
| No privileges | user namespace, `no_new_privs`, all caps dropped |
| CPU / TLE | executor watchdog polls the jail cgroup every 10 ms and kills past the CPU limit or a wall limit of 2 × CPU + 1 s; nsjail rlimits a second above as backstop |
| Memory / MLE | executor polls the jail cgroup's usage and kills past the limit (gVisor accounts memory but does not enforce it) |
| Processes / fork bombs | cgroup `pids.max` + `rlimit_nproc` |
| Output / disk | output cap + `rlimit_fsize`; a jail's `/tmp` counts against its memory |
| rlimits | every one set per phase; run-phase stack = memory limit, so deep recursion works |
| Syscalls (user code) | seccomp allowlist `sandbox/run.kafel`: unlisted → `ENOSYS`, dangerous (ptrace, mount, unshare, bpf, ...) → killed, threads only (`fork` → `EAGAIN`), no sockets, `ioctl` allowlist on all 64 bits |
| Syscalls (compiler) | `sandbox/compile.kafel`: the same, plus process creation (never new namespaces) for `cc1`/`as`/`ld` |

**Biggest fix over worker1:** worker1 compiled on the host, so a submission's
`#include "/host/path"` leaked file contents through compiler diagnostics.
worker2 compiles inside `compile.cfg` — the host FS simply isn't present, so
`#include "/etc/shadow"` fails with "No such file or directory". Compile bombs
are bounded by the compile jail's cgroup too.

`clone3` returns `ENOSYS`, so glibc falls back to `clone`, whose flags seccomp
can check: namespace flags are refused in both phases. After a base-image,
toolchain or gVisor upgrade, re-run `tools/profile_syscalls.py` and review the
syscalls it lists as not named by a policy.

### Redis credentials

Assume a jail escape eventually happens: whatever Redis login sits on the
worker host is then the attacker's. In prod, give the worker a dedicated ACL
user limited to its 3 keys and the commands it uses (Redis 7+; on Redis 6 use
plain `~` for all three keys), and set `REDIS_USERNAME=worker`:

```
ACL SETUSER worker on >LONG_RANDOM_PASSWORD resetkeys resetchannels \
  %RW~stream:pending-submissions %W~stream:execution-results %W~executor:nsjail:heartbeat \
  -@all +ping +xgroup|create +xreadgroup +xautoclaim +xclaim +xack +xdel +xadd +set
```

A stolen worker login can then only touch the job queue, write results and
the heartbeat. It cannot read results, touch other keys, `FLUSHALL`,
`CONFIG SET` or `EVAL`. Give the backend its own user and
`ACL SETUSER default off`. `tests/test_consumer.py` plays the backend and
uses suffixed keys, so run it with full-access credentials.

## Running

Jails run only in the executor, as root inside a `runsc` container; it refuses
to start anywhere else. The host needs Docker and gVisor with a runtime that
lets the executor create its socket in the mounted directory:

```bash
sudo runsc install --runtime=runsc-executor -- --platform=systrap --host-uds=create
sudo systemctl reload docker

docker build -t codinglemons-executor .
for i in 1 2; do     # slot i: core i, its own jail uid and socket directory
  docker run -d --name executor-slot$i --restart=unless-stopped --runtime=runsc-executor \
    --network=none --cap-add=SYS_ADMIN --cpuset-cpus=$i -e JAIL_UID=6100$i \
    -v /run/codinglemons/slot$i:/run/executor codinglemons-executor
done
# -> sockets at /run/codinglemons/slot{1,2}/executor.sock
```

The consumer runs on the host from the venv, with `EXECUTOR_SOCKETS` listing
one executor socket per slot. It sends work only to slots whose executor
reports ready (each takes 1–2 minutes to self-test after starting) and keeps
the heartbeat alive only while at least one does:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env.dev    # Redis + EXECUTOR_SOCKETS
.venv/bin/python main.py --env dev
```

## Tests

```bash
# fast, no Redis, no containers
.venv/bin/python -m unittest tests.test_contract tests.test_read_loop

# Seam B: the consumer against real Redis (.env.dev) and stub executors
.venv/bin/python -m unittest tests.test_consumer

# Seam A: builds the image, starts an executor under runsc-executor, talks to its socket
.venv/bin/python -m unittest tests.test_executor tests.test_adversarial tests.test_selftest

# Seam A, two slots pinned to cores 1 and 2 (needs 3 cores): concurrency and timing fairness
.venv/bin/python -m unittest tests.test_slots
```

Every executor runs its containment self-test (`selftest.py`, with the probe in
`probe/probe.go`) before it takes work, so each Seam A container takes 1–2 minutes
to become ready. `tests/test_selftest.py` reads the report back through `ready`,
on a healthy executor and on ones with a weakened policy or a missing toolchain.

`tests/verdict_matrix.py` drives the judge in-process and is parked.
`tests/test_adversarial.py` covers containment through Seam A: seccomp in both
phases, what each jail can see (host files, `/proc`, `/usr`, devices, the
environment), writes outside `/tmp`, the network, setuid, disk fill, fork bombs,
the compile-time file-read hole, the workspace cap, and leftovers between jobs.
