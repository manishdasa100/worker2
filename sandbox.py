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

Rootless: nsjail runs as the worker's own user inside a delegated cgroup v2
subtree. Each run gets a fresh per-run parent cgroup; after nsjail exits the
worker reads memory.peak / memory.events / cpu.stat from it — kernel-accurate
and valid even when the whole PID namespace was SIGKILLed on a TLE.
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

from cgroups import CgroupDelegation
from config import SandboxConfig

logger = logging.getLogger(__name__)

# GNU time, run inside the jail around user code: %e is the user process's own
# fork->exit elapsed, so reported runtime excludes sandbox setup/teardown.
TIME_BINARY = "/usr/bin/time"
STATS_MOUNT = "/stats"
STATS_FILENAME = "stats.txt"

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
    oom_killed: bool             # kernel OOM-killed the run's cgroup
    runtime_ms: int              # resolved: driver > wrapper > wall
    signal: Optional[int]
    peak_memory_mb: int = 0
    setup_failed: bool = False   # nsjail couldn't start the command: a worker failure, not a verdict
    output_exceeded: bool = False  # stdout passed the output cap; the jail was killed for it
    # Raw components (CALIBRATE reports all of them)
    wall_ms: int = 0
    wrapper_ms: Optional[int] = None
    driver_ms: Optional[int] = None
    cpu_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.oom_killed


class NsjailSandbox:
    def __init__(self, config: SandboxConfig, delegation: CgroupDelegation, output_limit_bytes: int):
        if delegation is None:
            raise ValueError(
                "NsjailSandbox requires a delegated cgroup subtree — run under "
                "systemd with Delegate=memory pids, or ./run.sh for dev."
            )
        self.config = config
        self.delegation = delegation
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
                       wall_limit_s, memory_limit, writable, log_file, stats_dir,
                       run_cgroup_dir) -> List[str]:
        memory_bytes = memory_limit * 1024 * 1024
        mount_flag = "--bindmount" if writable else "--bindmount_ro"
        cmd = [
            self.config.nsjail_path,
            "--config", config_path,
            "--log", log_file,
            "--rlimit_cpu", str(rlimit_cpu_s),
            "--time_limit", str(wall_limit_s),
            "--cgroup_mem_max", str(memory_bytes),
            "--cgroup_mem_swap_max", "0",   # else over-limit swaps out instead of OOM-killing
            mount_flag, f"{code_dir}:/code",
        ]
        if run_cgroup_dir:
            cmd += ["--cgroupv2_mount", run_cgroup_dir]
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

        run_cgroup = self.delegation.create_run_cgroup()

        stats_dir = ""
        stats_path = ""
        if measure and self._time_wrapper:
            stats_dir = tempfile.mkdtemp(prefix="nsjail_stats_")
            stats_path = os.path.join(stats_dir, STATS_FILENAME)
            # -a appends after the child exits, preserving any driver_ns line.
            command = [TIME_BINARY, "-a", "-f", "%e",
                       "-o", f"{STATS_MOUNT}/{STATS_FILENAME}"] + command

        rlimit_cpu_s = self._rlimit_seconds(time_limit_ms)
        wall_limit_s = rlimit_cpu_s + self.config.wall_clock_grace

        nsjail_cmd = self._build_command(
            command, code_dir, config_path=config_path, rlimit_cpu_s=rlimit_cpu_s,
            wall_limit_s=wall_limit_s, memory_limit=memory_limit, writable=writable,
            log_file=log_path, stats_dir=stats_dir,
            run_cgroup_dir=run_cgroup.path if run_cgroup else "",
        )
        logger.debug("nsjail: %s", " ".join(nsjail_cmd))

        output_exceeded = False

        def kill_for_output():
            nonlocal output_exceeded
            output_exceeded = True
            try:
                run_cgroup.kill()
            except OSError:
                process.kill()   # no cgroup.kill: take nsjail down, the jail with it

        start = time.monotonic()
        try:
            process = await asyncio.create_subprocess_exec(
                *nsjail_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Outer timeout sits above the enforced wall backstop; if it fires
            # nsjail itself hung.
            outer = wall_limit_s + 10
            # Never buffer more than the cap: in the run phase stdout past it kills
            # the jail (Output Limit Exceeded); stderr, and compiler output, are
            # truncated but never fatal. Both pipes are read to EOF so the program
            # can't block on a full pipe.
            cap = self.output_limit_bytes
            stdout_b, stderr_b, _, _ = await asyncio.wait_for(asyncio.gather(
                self._drain(process.stdout, cap, kill_for_output if measure else None),
                self._drain(process.stderr, cap),
                self._feed(process.stdin, stdin_data.encode("utf-8")),
                process.wait()), timeout=outer)
            elapsed_ms = int((time.monotonic() - start) * 1000)

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

            # Kernel counters — definitive, survive a SIGKILLed PID namespace.
            oom_killed = run_cgroup.oom_killed()
            peak_memory_mb = run_cgroup.peak_memory_mb()
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
            try:
                os.unlink(log_path)
            except FileNotFoundError:
                pass
            if stats_dir:
                shutil.rmtree(stats_dir, ignore_errors=True)
            if run_cgroup is not None:
                run_cgroup.remove()

    @staticmethod
    async def _drain(stream, cap: int, on_overflow=None) -> bytes:
        """Read a pipe to EOF, keeping only its first `cap` bytes."""
        kept = bytearray()
        while chunk := await stream.read(65536):
            if on_overflow and len(kept) + len(chunk) > cap:
                on_overflow()
                on_overflow = None
            kept += chunk[:cap - len(kept)]
        return bytes(kept)

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
