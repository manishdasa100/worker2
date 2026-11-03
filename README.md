# CodingLemons worker2

Executes untrusted user submissions for a LeetCode-style judge and returns
verdicts. A clean rebuild of `../worker` that keeps the proven execution core
and closes its security gaps. Drop-in on the backend: same Redis streams, same
payloads, same heartbeat key.

## Contract (unchanged — the backend depends on it)

- **Submissions**: consumed from `stream:pending-submissions` (group `workers`).
  Entry field `body` = JSON `{jobId, language, userCode(b64), driverCode(b64),
  task, timeLimit(CPU-ms), memoryLimit(MB), testCases:[{input,expectedOutput}],
  slowCode?, hogCode?}`.
- **Results**: XADD'd to `stream:execution-results`. Entry field `body` = JSON
  `{job_id, status: COMPLETED|FAILED, worker_type: "NSJAIL_WORKER",
  execution_report: <JSON string, COMPLETED only>}`.
- **Liveness**: key `executor:nsjail:heartbeat` (SET+EX, existence-gated). The
  backend only enqueues while it exists. Shared by all workers; never deleted.
- **Tasks**: `RUN_CODE` (run all, report each), `SUBMIT_CODE` (stop at first
  fail), `CALIBRATE` (measure a reference solution to derive a problem's limits).

## Architecture

```
main.py        startup: config, validation, cgroup delegation, logging
dispatcher.py  async loop: concurrency, liveness, in-flight keep-alive, draining
redis_io.py    ALL Redis: consume / ack / touch / beat / publish (at-least-once)
judge.py       verdict pipeline: compile (sandboxed) -> run tests -> classify
calibrate.py   CALIBRATE: measure reference + slow/hog gap verification
sandbox.py     nsjail wrapper; run + compile profiles; CPU-ms TLE, cgroup metrics
cgroups.py     rootless cgroup v2 delegation + per-run accounting cgroup
languages/     declarative handlers (write_files / compile_command / run_command)
sandbox/       run.cfg (default-deny seccomp) + compile.cfg (sandboxed compiler)
```

Separation of concerns is the structural change from worker1: transport,
judging, and sandboxing no longer bleed into each other.

## Security model (defense in depth)

Every execution — **including compilation** — runs inside nsjail, rootless
(the worker's own uid, no sudo), in a delegated cgroup v2 subtree.

| Boundary | Enforced by |
|---|---|
| No host filesystem | tmpfs `/`, only `/usr` (toolchain) read-only + the code dir |
| No network | empty net namespace |
| No privileges | user namespace, `no_new_privs`, all caps dropped |
| CPU / TLE | cgroup CPU-time counter (ms-granular) + wall-clock backstop |
| Memory / MLE | cgroup `memory.max` (+ `memory.peak`/`events` read back) |
| Processes / fork bombs | cgroup `pids.max` + `rlimit_nproc` |
| Output / disk | output cap + `rlimit_fsize` |
| Syscalls (user code) | **default-deny** seccomp allow-list (`KILL_PROCESS`) |
| Syscalls (compiler) | denylist (`EPERM`) — it legitimately forks `cc1`/`as`/`ld` |

**Biggest fix over worker1:** worker1 compiled on the host, so a submission's
`#include "/host/path"` leaked file contents through compiler diagnostics.
worker2 compiles inside `compile.cfg` — the host FS simply isn't present, so
`#include "/etc/passwd"` fails with "No such file or directory". Compile bombs
are bounded by the compile jail's cgroup too.

**Known ceiling:** `clone3` (JVM threads) can't be flag-filtered by seccomp, so
creating a *nested* user namespace isn't blocked. It grants no host privileges,
and `unshare`/`setns` are killed. Prod hardening: set `user.max_user_namespaces=0`
on the host.

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
`ACL SETUSER default off`. `tests/integration_live.py` plays the backend and
uses suffixed keys, so run it with full-access credentials.

## Running

Requires a delegated cgroup v2 subtree (rootless sandbox). Dev:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env.dev    # edit Redis + paths
./run.sh dev                # wraps: systemd-run --user --scope -p Delegate=yes ...
```

Prod: a systemd unit with `User=<worker>` and `Delegate=memory pids`.

## Tests

```bash
# fast, no sandbox
.venv/bin/python -m unittest tests.test_contract

# require a delegated scope:
systemd-run --user --scope -p Delegate=yes .venv/bin/python tests/smoke.py            # 3 langs, compile+run
systemd-run --user --scope -p Delegate=yes .venv/bin/python tests/verdict_matrix.py   # TLE/MLE/RE + fairness
systemd-run --user --scope -p Delegate=yes .venv/bin/python tests/security.py         # adversarial containment
systemd-run --user --scope -p Delegate=yes .venv/bin/python tests/integration_live.py # full loop over real Redis
```

`tests/security.py` asserts containment of: host-file reads, filesystem escapes,
worker-secret/`/proc` leakage, outbound network, privilege escalation, disk fill,
fork bombs, default-deny seccomp, and the compile-time file-read hole.
