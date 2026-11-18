"""
Containment self-test: the executor attacks its own jails and reports whether
they held. Ported from judgebox's internal/judge/selftest.go.

    report = await self_test(judge)
    report["ready"]    # True only if every check passed or is not applicable

Four parts, all through the same NsjailSandbox that judges jobs:
  1. overhead   an empty jail's CPU and memory (an idle probe jailed, less the
                same probe bare), set on the sandbox so every later reading
                excludes it
  2. resources  memory, CPU (and how fast the kill lands), wall, pids, output
  3. surface    the run and compile phases' seccomp policies, filesystem and
                identity. A probe that passes by exiting 0 first runs
                unsandboxed as a control: if it exits 0 there too, the kernel
                lacks the interface and the check is not applicable rather than
                a vacuous pass.
  4. smoke      a trivial job in every language, judged end to end

The probe is probe/probe.go, a static binary at PROBE. Exit 0 = contained,
1 = breached; some probes must instead be killed (see each check).
"""
import asyncio
import logging
import time
from datetime import datetime, timezone

from languages import LANGUAGES
from languages.base import Toolchain
from models import ExecutionRequest, StatusCode
from cgroups import JailCgroup
from sandbox import COMPILE_PIDS_MAX, RUN_PIDS_MAX, WATCHDOG_POLL_S, workspace

logger = logging.getLogger(__name__)

PROBE = "/usr/local/bin/probe"
PROBE_TOOLCHAIN = Toolchain(mounts=(PROBE,), env=("GOMAXPROCS=1",))
SIGSYS = 31
CONTROL_TIMEOUT_S = 10

# Probe limits, as judgebox's: room for the probe, far below what a probe asks for.
TIME_LIMIT_MS = 2000
MEMORY_LIMIT_MB = 64
CPU_PROBE_LIMIT_MS = 300
CPU_KILL_LATENCY_MS = 600     # the spin must be dead by twice its limit
NOOP_IDLE_MS = 100            # long enough for the 10 ms memory poll to see an empty jail

# Probes the policy must kill (SIGSYS), in both phases: judgebox's two, then a
# raw call for the rest of the kill set as test_adversarial tries it.
KILLED = [
    ("seccomp_kills_ptrace", ("ptrace",)),
    ("seccomp_kills_unshare", ("unshare",)),
    ("seccomp_kills_mount", ("syscall", "165")),
    ("seccomp_kills_chroot", ("syscall", "161")),
    ("seccomp_kills_bpf", ("syscall", "321")),
    ("seccomp_kills_keyctl", ("syscall", "250")),
]

# Kernel-surface probes that pass by exiting 0, in both phases.
CONTAINED = [
    ("no_sockets", "socket"),
    ("x32_abi_blocked", "x32"),
    ("io_uring_blocked", "io_uring"),
    ("ioctl_high_bits_blocked", "ioctl_highbits"),
    ("no_capabilities", "caps"),
    ("default_action_denies_unlisted", "default_deny"),
]

# A trivial solution and driver per language, printing 42.
SMOKE_PROGRAMS = {
    "python": ("def f():\n    return 42\n",
               "from solution import f\nprint(f())\n"),
    "cpp": ("int f() { return 42; }\n",
            '#include <iostream>\n#include "solution.cpp"\nint main(){ std::cout << f() << std::endl; }\n'),
    "java": ("public class Solution { static int f() { return 42; } }\n",
             "public class Main { public static void main(String[] a) { System.out.println(Solution.f()); } }\n"),
    "c": ("int f(void) { return 42; }\n",
          '#include <stdio.h>\n#include "solution.c"\nint main(void) { printf("%d\\n", f()); return 0; }\n'),
    "go": ("package main\n\nfunc f() int { return 42 }\n",
           'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println(f()) }\n'),
    "javascript": ("function f() { return 42; }\nmodule.exports = { f };\n",
                   "const { f } = require('./solution');\nconsole.log(f());\n"),
    "rust": ("pub fn f() -> i32 { 42 }\n",
             'mod solution;\nfn main() { println!("{}", solution::f()); }\n'),
}


def not_ready(error: str) -> dict:
    """The report before the first self-test, or when one couldn't run."""
    return {"ready": False, "ran_at": None, "overhead": None,
            "checks": [{"name": "self_test", "ok": False, "detail": error}]}


async def self_test(judge) -> dict:
    started = time.monotonic()
    checks = []
    try:
        overhead = await _checks(judge, checks)
    except Exception as e:      # a check that can't even run fails the self-test
        logger.exception("Self-test aborted")
        checks.append({"name": "self_test", "ok": False, "detail": f"aborted: {e}"})
        overhead = None
    report = {"ready": all(c["ok"] for c in checks), "ran_at": datetime.now(timezone.utc).isoformat(),
              "overhead": overhead, "checks": checks}
    seconds = time.monotonic() - started
    if report["ready"]:
        logger.info("Self-test passed in %.1fs (overhead %s)", seconds, overhead)
    for c in checks:
        if not c["ok"]:
            logger.error("Self-test check %s failed: %s", c["name"], c.get("detail"))
    return report


async def _checks(judge, checks) -> dict:
    sandbox = judge.sandbox
    controls = {}

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    async def applicable(probe):
        """The unsandboxed control: False if the probe is contained even there."""
        if probe not in controls:
            process = await asyncio.create_subprocess_exec(
                PROBE, probe, cwd="/tmp", env={"GOMAXPROCS": "1"},
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            try:
                controls[probe] = await asyncio.wait_for(process.wait(), CONTROL_TIMEOUT_S) != 0
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                controls[probe] = True
        return controls[probe]

    async def unjailed(*args):
        """The probe outside any jail, in a cgroup of its own: (cpu_ms, peak memory bytes)."""
        cgroup = JailCgroup.create(pids_max=RUN_PIDS_MAX)
        try:
            process = await asyncio.create_subprocess_exec(
                PROBE, *args, cwd="/tmp", env={"GOMAXPROCS": "1"}, preexec_fn=cgroup.join,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            peak = 0
            while process.returncode is None:
                peak = max(peak, cgroup.memory_bytes())
                await asyncio.sleep(WATCHDOG_POLL_S)
            return cgroup.cpu_time_ms(), peak
        finally:
            cgroup.remove()

    with workspace() as code_dir:
        async def run(*args, time_limit_ms=TIME_LIMIT_MS):
            return await sandbox.run([PROBE, *args], code_dir, PROBE_TOOLCHAIN,
                                     time_limit_ms=time_limit_ms, memory_limit=MEMORY_LIMIT_MB)

        async def compile_phase(*args, time_limit_ms=TIME_LIMIT_MS, memory_limit=MEMORY_LIMIT_MB):
            return await sandbox.compile([PROBE, *args], code_dir, PROBE_TOOLCHAIN,
                                         time_limit_ms=time_limit_ms, memory_limit=memory_limit)

        # 1. Overhead: the best of five idle probes in a jail, less the best of five
        # bare in a cgroup of their own. (judgebox subtracts the probe's own rusage,
        # but under gVisor rusage and the cgroup don't count alike.)
        sandbox.overhead_cpu_ms = sandbox.overhead_memory_bytes = 0
        jailed, bare = [], []
        for _ in range(5):
            r = await run("noop", str(NOOP_IDLE_MS))
            if r.exit_code != 0 or r.setup_failed:
                add("overhead", False, f"noop probe failed: {describe(r)}")
                return None
            jailed.append((r.cpu_ms, r.peak_memory_bytes))
            bare.append(await unjailed("noop", str(NOOP_IDLE_MS)))
        cpu_ms = max(0, min(c for c, _ in jailed) - min(c for c, _ in bare))
        used = max(0, min(m for _, m in jailed) - min(m for _, m in bare))
        sandbox.overhead_cpu_ms, sandbox.overhead_memory_bytes = cpu_ms, used
        overhead = {"cpu_ms": cpu_ms, "memory_kb": used // 1024}
        add("overhead", True, f"empty jail: {cpu_ms} ms CPU, {used // 1024} KiB")

        # 2. Resources (run phase).
        r = await run("alloc", "256")
        add("memory_limit", r.oom_killed, describe(r))
        r = await run("spin", time_limit_ms=CPU_PROBE_LIMIT_MS)
        add("cpu_time_limit", r.time_limit_hit == "cpu", describe(r))
        add("cpu_kill_latency", r.cpu_ms <= CPU_KILL_LATENCY_MS,
            f"killed after {r.cpu_ms} ms CPU (limit {CPU_PROBE_LIMIT_MS} ms)")
        r = await run("sleep", time_limit_ms=CPU_PROBE_LIMIT_MS)
        add("wall_time_limit", r.time_limit_hit == "wall", describe(r))
        # Exit 1 only if every thread was created; stopped by the limit, Go exits 2.
        r = await run("threads", "128")
        add("pids_limit", not r.setup_failed and r.exit_code not in (0, 1), describe(r))
        r = await run("flood", "8")
        add("output_limit", r.output_exceeded, describe(r))

        # 3. Kernel surface, run phase then compile phase.
        for phase, invoke, prefix in (("run", run, ""), ("compile", compile_phase, "compile_")):
            for name, probe in KILLED:
                r = await invoke(*probe)
                add(prefix + name, r.signal == SIGSYS, describe(r))
            contained = [*CONTAINED, ("filesystem_isolation", "fs")]
            if phase == "run":
                contained.insert(0, ("no_fork_in_run_phase", "fork"))
            for name, probe in contained:
                # Writing where the jail mustn't is never a kernel gap; and its
                # control would write into the executor's own filesystem.
                if probe != "fs" and not await applicable(probe):
                    checks.append({"name": prefix + name, "ok": True, "not_applicable": True,
                                   "detail": "contained even unsandboxed: the kernel lacks this interface"})
                    continue
                r = await invoke(probe, phase)
                add(prefix + name, held(r), describe(r))
        # Under the compile phase's real limits: under gVisor each fork costs ~10 ms
        # of CPU, and the forks outgrow 64 MB, long before pids.max stops them.
        limits = judge.config.execution
        r = await compile_phase("forkbomb", "1000", time_limit_ms=limits.compile_timeout * 1000,
                                memory_limit=limits.compile_memory_limit)
        created = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
        add("compile_fork_bounded", r.exit_code == 0 and 0 < created <= COMPILE_PIDS_MAX,
            f"{created} processes created (limit {COMPILE_PIDS_MAX}); {describe(r)}")

    # 4. Smoke: every language judges a trivial program Accepted. A language
    # without a smoke program aborts the self-test.
    for language in LANGUAGES:
        user_code, driver_code = SMOKE_PROGRAMS[language]
        report = await judge.judge(ExecutionRequest(
            job_id=f"self-test-{language}", language=language, user_code=user_code,
            driver_code=driver_code, task="SUBMIT_CODE", time_limit=5000, memory_limit=64,
            test_cases=[{"input": "", "expectedOutput": "42"}]))
        add(f"smoke_{language}", report.status_code == StatusCode.ACCEPTED,
            " ".join(str(v) for v in (report.status_msg, report.compile_error, report.runtime_error,
                                      report.internal_error) if v)[:500])
    return overhead


def held(r) -> bool:
    """The probe reported containment (exit 0), or the policy killed it."""
    if r.setup_failed or r.time_limit_hit or r.oom_killed or r.output_exceeded:
        return False
    return r.signal == SIGSYS or (r.signal is None and r.exit_code == 0)


def describe(r) -> str:
    facts = [f"exit={r.exit_code}"]
    if r.signal:
        facts.append(f"signal={r.signal}")
    for flag in ("setup_failed", "oom_killed", "output_exceeded"):
        if getattr(r, flag):
            facts.append(flag)
    if r.time_limit_hit:
        facts.append(f"{r.time_limit_hit} time limit")
    facts.append(f"cpu={r.cpu_ms}ms")
    out = "".join(ch for ch in (r.stdout.strip() or r.stderr.strip())[-200:] if ch.isprintable())
    return " ".join(facts) + (f": {out}" if out else "")
