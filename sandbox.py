"""
nsjail sandbox wrapper.

Runs one command inside an nsjail jail and reports what happened. Knows
nothing about languages, test cases, or verdicts — it takes a command,
isolates it, and returns timing/memory/exit facts.

Two profiles share one invocation path:
  * run     — user code. Code dir read-only, GNU-time wrapped, default-deny
              seccomp (sandbox/run.cfg). This is the TLE/MLE-judged path.
  * compile — the compiler. Code dir READ-WRITE (it emits the binary/classes),
              not wrapped, looser seccomp (sandbox/compile.cfg). Crucially the
              compiler sees only the toolchain + code dir and no network, so a
              malicious source cannot read host files (`#include "/etc/..."`)
              or exhaust host RAM at compile time — the jail's cgroup bounds it.

Runs as root inside the executor's runsc container (ADR-0003). nsjail joins a
fresh per-jail cgroup before exec; while it runs, the executor polls the
cgroup's memory, tracking the peak and killing the jail past the limit, since
gVisor accounts memory but does not enforce it. CPU time is read at the end.
The jail runs as JAIL_UID, which owns nothing.
"""
import asyncio
import logging
import math
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass
from typing import List, Optional

from cgroups import JailCgroup
from config import SandboxConfig

logger = logging.getLogger(__name__)

# GNU time, run inside the jail around user code: %e is the user process's own
# fork->exit elapsed, so reported runtime excludes sandbox setup/teardown.
TIME_BINARY = "/usr/bin/time"
STATS_MOUNT = "/stats"
STATS_FILENAME = "stats.txt"

JAIL_UID = 65534        # outside id the jail's user maps to (sandbox/*.cfg uidmap)
MEMORY_POLL_S = 0.01     # ticket 10 folds this into the CPU/wall/memory watchdog
RUN_PIDS_MAX = 64
COMPILE_PIDS_MAX = 128   # compiler drivers fork

# stderr is debug output and never judged, so it may run far past the output
# cap; only a flood this many times the cap kills the jail.
STDERR_FLOOD_FACTOR = 32

SIGKILL = 9
SIGXCPU = 24

# nsjail's reap line for the jail's direct child (the program, or GNU time
# around it). Absent, or with a launch failure logged, means nsjail itself
# never got the command running: a setup failure, not the program's doing.
_NSJAIL_EXIT = re.compile(r"\) (?:exited with status: \d+|terminated with signal: \S+ \((\d+)\))")
_NSJAIL_LAUNCH_FAILED = "Launching child process failed"
_TIME_CANNOT_RUN = f"{TIME_BINARY}: cannot run "


@dataclass
class SandboxResult:
    """What came out of the jail."""
    stdout: str
    stderr: str
    nsjail_log: str
    exit_code: int
    timed_out: bool              # exceeded the CPU-ms budget (clean overrun, CPU kill, or wall backstop)
    oom_killed: bool             # memory passed the limit; the jail was killed for it
    runtime_ms: int              # resolved: driver > wrapper > wall
    signal: Optional[int]
    peak_memory_mb: int = 0
    setup_failed: bool = False   # nsjail couldn't start the command: a worker failure, not a verdict
    output_exceeded: bool = False  # stdout passed the output cap (or stderr flooded); the jail was killed for it
    # Raw components (CALIBRATE reports all of them)
    wall_ms: int = 0
    wrapper_ms: Optional[int] = None
    driver_ms: Optional[int] = None
    cpu_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.oom_killed


class NsjailSandbox:
    def __init__(self, config: SandboxConfig, output_limit_bytes: int):
        self.config = config
        self.output_limit_bytes = output_limit_bytes
        self._time_wrapper = os.path.isfile(TIME_BINARY)
        if not self._time_wrapper:
            logger.warning("%s not found — runtimes will include sandbox overhead "
                           "(install the 'time' package)", TIME_BINARY)

    # ---- public API ---------------------------------------------------------

    async def run(
        self,
        command: List[str],
        code_dir: str,
        stdin_data: str = "",
        time_limit_ms: int = 5000,
        memory_limit: int = 50,
    ) -> SandboxResult:
        """Run user code in the read-only, GNU-time-wrapped, run profile (TLE-judged)."""
        return await self._invoke(
            command, code_dir,
            config_path=self.config.run_config_path,
            stdin_data=stdin_data,
            time_limit_ms=time_limit_ms,
            memory_limit=memory_limit,
            writable=False,
            measure=True,
        )

    async def compile(
        self,
        command: List[str],
        code_dir: str,
        time_limit_ms: int,
        memory_limit: int,
    ) -> SandboxResult:
        """
        Run the compiler in the writable compile profile. No network, only the
        toolchain + code dir visible, cgroup-bounded. Output lands in code_dir
        (a host bind mount) for the run profile to use read-only afterwards.
        """
        return await self._invoke(
            command, code_dir,
            config_path=self.config.compile_config_path,
            stdin_data="",
            time_limit_ms=time_limit_ms,
            memory_limit=memory_limit,
            writable=True,
            measure=False,
        )

    # ---- shared invocation --------------------------------------------------

    @staticmethod
    def _rlimit_seconds(time_limit_ms: int) -> int:
        """
        Coarse whole-second RLIMIT_CPU cap. The kernel's RLIMIT_CPU is second-
        granular so it can't be the fine TLE; it only stops a runaway burning
        forever. The ms-granular verdict is the cpu_ms compare in _invoke. Ceil
        keeps the cap >= the ms threshold so a solution AT the threshold isn't
        SIGKILLed before cpu_ms can judge it.
        """
        return max(1, math.ceil(time_limit_ms / 1000))

    def _build_command(self, command, code_dir, *, config_path, rlimit_cpu_s,
                       wall_limit_s, writable, log_file, stats_dir) -> List[str]:
        mount_flag = "--bindmount" if writable else "--bindmount_ro"
        cmd = [
            self.config.nsjail_path,
            "--config", config_path,
            "--log", log_file,
            "--rlimit_cpu", str(rlimit_cpu_s),
            "--time_limit", str(wall_limit_s),
            mount_flag, f"{code_dir}:/code",
        ]
        if stats_dir:
            cmd += ["--bindmount", f"{stats_dir}:{STATS_MOUNT}"]
        cmd.append("--")
        cmd += command
        return cmd

    async def _invoke(self, command, code_dir, *, config_path, stdin_data,
                      time_limit_ms, memory_limit, writable, measure) -> SandboxResult:
        log_file = tempfile.NamedTemporaryFile(prefix="nsjail_log_", suffix=".txt", delete=False)
        log_path = log_file.name
        log_file.close()

        if writable:
            os.chown(code_dir, JAIL_UID, JAIL_UID)   # the compiler writes its output there
        # +1: nsjail itself sits in the cgroup with the jail
        run_cgroup = JailCgroup.create(pids_max=(COMPILE_PIDS_MAX if writable else RUN_PIDS_MAX) + 1)

        stats_dir = ""
        stats_path = ""
        if measure and self._time_wrapper:
            stats_dir = tempfile.mkdtemp(prefix="nsjail_stats_")
            os.chown(stats_dir, JAIL_UID, JAIL_UID)
            stats_path = os.path.join(stats_dir, STATS_FILENAME)
            # -a appends after the child exits, preserving any driver_ns line.
            command = [TIME_BINARY, "-a", "-f", "%e",
                       "-o", f"{STATS_MOUNT}/{STATS_FILENAME}"] + command

        rlimit_cpu_s = self._rlimit_seconds(time_limit_ms)
        wall_limit_s = rlimit_cpu_s + self.config.wall_clock_grace

        nsjail_cmd = self._build_command(
            command, code_dir, config_path=config_path, rlimit_cpu_s=rlimit_cpu_s,
            wall_limit_s=wall_limit_s, writable=writable,
            log_file=log_path, stats_dir=stats_dir,
        )
        logger.debug("nsjail: %s", " ".join(nsjail_cmd))

        output_exceeded = memory_exceeded = False
        peak_bytes = 0
        memory_bytes = memory_limit * 1024 * 1024
        watcher = None

        def kill_jail():
            try:
                run_cgroup.kill(spare=process.pid)   # nsjail survives to log the reap
            except OSError:
                process.kill()   # can't list the cgroup: take nsjail down, the jail with it

        def kill_for_output():
            nonlocal output_exceeded
            output_exceeded = True
            kill_jail()

        async def watch_memory():
            nonlocal peak_bytes, memory_exceeded
            while True:
                used = run_cgroup.memory_bytes()
                peak_bytes = max(peak_bytes, used)
                if used > memory_bytes and not memory_exceeded:
                    memory_exceeded = True
                    kill_jail()
                await asyncio.sleep(MEMORY_POLL_S)

        start = time.monotonic()
        try:
            process = await asyncio.create_subprocess_exec(
                *nsjail_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=run_cgroup.join,
            )
            watcher = asyncio.create_task(watch_memory())
            # Outer timeout sits above the enforced wall backstop; if it fires
            # nsjail itself hung.
            outer = wall_limit_s + 10
            # Never buffer more than the cap. In the run phase stdout past the cap,
            # or a stderr flood, kills the jail (Output Limit Exceeded); stderr keeps
            # its tail, where tracebacks and memory markers are. Compiler output keeps
            # its head (the first error) and is never fatal. Both pipes are read to
            # EOF so the program can't block on a full pipe.
            cap = self.output_limit_bytes
            kill = kill_for_output if measure else None
            stdout_b, stderr_b, _, _ = await asyncio.wait_for(asyncio.gather(
                self._drain(process.stdout, cap, kill_past=cap, kill=kill),
                self._drain(process.stderr, cap, tail=measure,
                            kill_past=cap * STDERR_FLOOD_FACTOR, kill=kill),
                self._feed(process.stdin, stdin_data.encode("utf-8")),
                process.wait()), timeout=outer)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            watcher.cancel()

            with open(log_path, "r", errors="replace") as f:
                nsjail_log = f.read()

            stdout = stdout_b.decode("utf-8", errors="replace")
            stderr = stderr_b.decode("utf-8", errors="replace")
            exit_code = process.returncode or 0
            driver_ms, wrapper_ms, wrapped_signal = self._read_stats(stats_path)
            exits = list(_NSJAIL_EXIT.finditer(nsjail_log))
            # ponytail: user code can forge GNU time's lines — print the "cannot run"
            # stderr line and exit 127 (its own job becomes a worker failure), or write
            # a "Command terminated by signal" line to /stats (its own RE reason
            # changes). Self-only; both go with the GNU time wrapper.
            setup_failed = (not exits or _NSJAIL_LAUNCH_FAILED in nsjail_log
                            or (bool(stats_path) and exit_code == 127
                                and stderr.startswith(_TIME_CANNOT_RUN)))
            # Signal never comes from exit_code (a program may exit 139 itself):
            # the jail child's signal per nsjail, else the program's per GNU time.
            jail_signal = exits[-1].group(1) if exits else None
            signal = int(jail_signal) if jail_signal else wrapped_signal

            oom_killed = memory_exceeded
            peak_memory_mb = math.ceil(peak_bytes / (1024 * 1024))
            cpu_ms = run_cgroup.cpu_time_ms()

            # TLE verdict (ms-granular, off the cgroup CPU counter):
            #  1. clean overrun: exit 0 but cpu over budget (sub-second discrimination
            #     the coarse rlimit can't do; exit 0 keeps crashes classed as RE)
            #  2. CPU kill: SIGXCPU/SIGKILL after burning budget, excluding OOM
            #  3. wall backstop: nsjail "time limit" log line (sleepers, no CPU burn)
            #  4. fallback for (3): SIGKILL past the wall cap can only be the nsjail kill
            cpu_exceeded = cpu_ms >= time_limit_ms
            overran_clean = exit_code == 0 and cpu_exceeded
            killed_for_time = signal in (SIGKILL, SIGXCPU) and cpu_exceeded and not oom_killed
            timed_out = (
                overran_clean
                or killed_for_time
                or ("time limit" in nsjail_log.lower())
                or (signal == SIGKILL and elapsed_ms >= wall_limit_s * 1000)
            )

            if driver_ms is not None and 0 <= driver_ms <= elapsed_ms:
                runtime_ms = driver_ms
            elif wrapper_ms is not None:
                runtime_ms = wrapper_ms
            else:
                runtime_ms = elapsed_ms

            return SandboxResult(
                stdout=stdout, stderr=stderr, nsjail_log=nsjail_log, exit_code=exit_code,
                timed_out=timed_out, oom_killed=oom_killed, runtime_ms=runtime_ms,
                signal=signal, peak_memory_mb=peak_memory_mb, wall_ms=elapsed_ms,
                wrapper_ms=wrapper_ms, driver_ms=driver_ms, cpu_ms=cpu_ms,
                setup_failed=setup_failed, output_exceeded=output_exceeded,
            )

        except asyncio.TimeoutError:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.error("nsjail hung (outer timeout after %dms)", elapsed_ms)
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass
            return SandboxResult("", "Sandbox process timed out (nsjail hung)", "", -1,
                                 False, False, elapsed_ms, None, setup_failed=True)
        except (FileNotFoundError, PermissionError, OSError) as e:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.error("Failed to launch nsjail: %s", e)
            return SandboxResult("", f"Failed to launch sandbox: {e}", "", -1,
                                 False, False, elapsed_ms, None, setup_failed=True)
        finally:
            if watcher is not None:
                watcher.cancel()
            try:
                os.unlink(log_path)
            except FileNotFoundError:
                pass
            if stats_dir:
                shutil.rmtree(stats_dir, ignore_errors=True)
            run_cgroup.remove()

    @staticmethod
    async def _drain(stream, cap: int, *, tail=False, kill_past=0, kill=None) -> bytes:
        """
        Read a pipe to EOF, keeping only its first (or, with tail, last) `cap`
        bytes. Calls kill() once, as soon as more than kill_past bytes arrive.
        """
        kept = bytearray()
        total = 0
        while chunk := await stream.read(65536):
            total += len(chunk)
            if kill and total > kill_past:
                kill()
                kill = None
            if tail:
                kept += chunk
                if len(kept) > 2 * cap:      # trim in batches, not per chunk
                    del kept[:-cap]
            else:
                kept += chunk[:cap - len(kept)]
        return bytes(kept[-cap:] if tail else kept)

    @staticmethod
    async def _feed(stdin, data: bytes) -> None:
        try:
            stdin.write(data)
            await stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass   # the program exited without reading all its input
        stdin.close()

    @staticmethod
    def _read_stats(stats_path: str):
        """
        Parse the shared stats file. Lines in write order:
            driver_ns <int>   optional, appended by driver: solution call ns
            Command terminated by signal <n>   GNU time, if the program was signalled
            <%e seconds>      GNU time, always last (unless the wrapper was killed)
        Returns (driver_ms, wrapper_ms, signal), each None if missing/unparseable.
        """
        driver_ms = wrapper_ms = signal = None
        if not stats_path:
            return driver_ms, wrapper_ms, signal
        try:
            with open(stats_path, "r") as f:
                content = f.read()
        except OSError:
            return driver_ms, wrapper_ms, signal
        for line in content.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "driver_ns" and parts[1].isdigit():
                driver_ms = (int(parts[1]) + 500_000) // 1_000_000   # last wins
            elif line.startswith("Command terminated by signal ") and parts[-1].isdigit():
                signal = int(parts[-1])
            elif len(parts) == 1:
                try:
                    wrapper_ms = int(float(parts[0]) * 1000)
                except ValueError:
                    continue
        return driver_ms, wrapper_ms, signal
