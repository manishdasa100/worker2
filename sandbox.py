"""
nsjail sandbox wrapper.

Runs one command inside an nsjail jail and reports what happened. Knows
nothing about languages, test cases, or verdicts — it takes a command,
isolates it, and returns timing/memory/exit facts.

Two profiles share one invocation path:
  * run     — user code. Code dir read-only, seccomp allowlist with threads
              only (sandbox/run.cfg, run.kafel), stack limit = memory limit.
              This is the TLE/MLE-judged path.
  * compile — the compiler. Code dir READ-WRITE (it emits the binary/classes),
              not wrapped, the allowlist plus process creation
              (sandbox/compile.cfg, compile.kafel). Crucially the
              compiler sees only the toolchain + code dir and no network, so a
              malicious source cannot read host files (`#include "/etc/..."`)
              or exhaust host RAM at compile time — the jail's cgroup bounds it.

Besides the code dir, a jail sees only the toolchain its caller names: read-only
paths and extra environment variables (nothing for a static binary). The code dir lives in a
job's workspace(): a fresh tmpfs, size- and inode-capped, so a compile can't
fill the disk and nothing a job writes reaches the next one.

Runs as root inside the executor's runsc container (ADR-0003). nsjail joins a
fresh per-jail cgroup before exec; while it runs, a watchdog polls the cgroup
and kills the jail past its CPU limit, its wall limit (2 x CPU + 1 s) or its
memory limit (gVisor accounts memory but does not enforce it), tracking the
memory peak. nsjail's rlimit_cpu and time_limit sit a second above the watchdog
as backstops. Every reading has an empty jail's own cost (overhead_*, measured
by the containment self-test) taken off first. The jail runs as JAIL_USER, mapped to the slot's host uid
(SandboxConfig.jail_uid), which owns nothing.
"""
import asyncio
import logging
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, List, Optional

from cgroups import JailCgroup
from config import SandboxConfig

logger = logging.getLogger(__name__)

# Where a driver may append "driver_ns <int>", its own timing of the solution call.
STATS_MOUNT = "/stats"
STATS_FILENAME = "stats.txt"

JAIL_USER = 1000        # uid and gid inside every jail: "jail" in sandbox/passwd
# ponytail: one cap for every language; per-language caps if a toolchain needs more.
WORKSPACE_OPTIONS = "size=64m,nr_inodes=1024,mode=0755"
WATCHDOG_POLL_S = 0.01
RUN_PIDS_MAX = 64
COMPILE_PIDS_MAX = 128   # compiler drivers fork

# stderr is debug output and never judged, so it may run far past the output
# cap; only a flood this many times the cap kills the jail.
STDERR_FLOOD_FACTOR = 32

SIGXCPU = 24

# nsjail's reap line for the jail's direct child, the program. Absent, or with a
# launch failure logged, means nsjail itself never got the command running: a
# setup failure, not the program's doing.
_NSJAIL_EXIT = re.compile(r"\) (?:exited with status: \d+|terminated with signal: \S+ \((\d+)\))")
_NSJAIL_LAUNCH_FAILED = "Launching child process failed"


@contextmanager
def workspace() -> Iterator[str]:
    """
    Mount a fresh tmpfs for one job and yield the code dir inside it; stats dirs
    and calibration's adversaries go beside it, under the same cap. Mounting
    needs CAP_SYS_ADMIN in the executor's runsc container (gVisor's, not the host's).
    """
    root = tempfile.mkdtemp(prefix="workspace_")
    mounted = subprocess.run(["mount", "-t", "tmpfs", "-o", WORKSPACE_OPTIONS, "tmpfs", root],
                             capture_output=True, text=True)
    if mounted.returncode != 0:
        os.rmdir(root)
        raise RuntimeError(f"Cannot mount a job workspace (the executor needs CAP_SYS_ADMIN): "
                           f"{mounted.stderr.strip()}")
    try:
        code_dir = os.path.join(root, "code")
        os.mkdir(code_dir)
        yield code_dir
    finally:
        # Every jail has exited by now, so nothing holds the mount.
        unmounted = subprocess.run(["umount", root], capture_output=True, text=True)
        if unmounted.returncode == 0:
            os.rmdir(root)
        else:
            logger.error("Could not unmount workspace %s: %s", root, unmounted.stderr.strip())


@dataclass
class SandboxResult:
    """What came out of the jail."""
    stdout: str
    stderr: str
    nsjail_log: str
    exit_code: int
    time_limit_hit: Optional[str]  # "cpu" or "wall" when the time limit was hit, else None
    oom_killed: bool             # memory passed the limit; the jail was killed for it
    runtime_ms: int              # the driver's own timing if it emitted one, else cpu_ms
    signal: Optional[int]
    peak_memory_mb: int = 0
    peak_memory_bytes: int = 0
    setup_failed: bool = False   # nsjail couldn't start the command: a worker failure, not a verdict
    output_exceeded: bool = False  # stdout passed the output cap (or stderr flooded); the jail was killed for it
    # Raw components (CALIBRATE reports all of them)
    wall_ms: int = 0
    driver_ms: Optional[int] = None
    cpu_ms: int = 0


class NsjailSandbox:
    def __init__(self, config: SandboxConfig, output_limit_bytes: int):
        self.config = config
        self.output_limit_bytes = output_limit_bytes
        # What an empty jail costs (nsjail and jail setup), measured by the self-test.
        # Subtracted from every reading, so limits and reports are the program's own.
        self.overhead_cpu_ms = 0
        self.overhead_memory_bytes = 0

    # ---- public API ---------------------------------------------------------

    async def run(
        self,
        command: List[str],
        code_dir: str,
        toolchain,
        stdin_data: str = "",
        time_limit_ms: int = 5000,
        memory_limit: int = 50,
    ) -> SandboxResult:
        """Run user code in the read-only run profile (TLE-judged) with `toolchain`."""
        return await self._invoke(
            command, code_dir, toolchain,
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
        toolchain,
        time_limit_ms: int,
        memory_limit: int,
    ) -> SandboxResult:
        """
        Run the compiler in the writable compile profile. No network, only the
        toolchain + code dir visible, cgroup-bounded. Output lands in code_dir
        for the run profile to use read-only afterwards.
        """
        return await self._invoke(
            command, code_dir, toolchain,
            config_path=self.config.compile_config_path,
            stdin_data="",
            time_limit_ms=time_limit_ms,
            memory_limit=memory_limit,
            writable=True,
            measure=False,
        )

    # ---- shared invocation --------------------------------------------------

    def _build_command(self, command, code_dir, toolchain, *, config_path, rlimit_cpu_s,
                       wall_limit_s, writable, log_file, stats_dir, stack_mb) -> List[str]:
        mount_flag = "--bindmount" if writable else "--bindmount_ro"
        identity = f"{JAIL_USER}:{self.config.jail_uid}:1"
        cmd = [
            self.config.nsjail_path,
            "--config", config_path,
            "--log", log_file,
            "--user", identity, "--group", identity,
            "--rlimit_cpu", str(rlimit_cpu_s),
            "--time_limit", str(wall_limit_s),
        ]
        if stack_mb:
            cmd += ["--rlimit_stack", str(stack_mb)]
        for path in toolchain.mounts:
            cmd += ["--bindmount_ro", path]
        for var in toolchain.env:
            cmd += ["--env", var]
        cmd += [mount_flag, f"{code_dir}:/code"]
        if stats_dir:
            cmd += ["--bindmount", f"{stats_dir}:{STATS_MOUNT}"]
        cmd.append("--")
        cmd += command
        return cmd

    async def _invoke(self, command, code_dir, toolchain, *, config_path, stdin_data,
                      time_limit_ms, memory_limit, writable, measure) -> SandboxResult:
        log_file = tempfile.NamedTemporaryFile(prefix="nsjail_log_", suffix=".txt", delete=False)
        log_path = log_file.name
        log_file.close()

        jail_uid = self.config.jail_uid
        if writable:
            os.chown(code_dir, jail_uid, jail_uid)   # the compiler writes its output there
        # +1: nsjail itself sits in the cgroup with the jail
        run_cgroup = JailCgroup.create(pids_max=(COMPILE_PIDS_MAX if writable else RUN_PIDS_MAX) + 1)

        stats_dir = ""
        stats_path = ""
        if measure:
            # Beside the code dir, so the workspace's cap bounds what the program writes here.
            stats_dir = tempfile.mkdtemp(prefix="stats_", dir=os.path.dirname(code_dir))
            os.chown(stats_dir, jail_uid, jail_uid)
            stats_path = os.path.join(stats_dir, STATS_FILENAME)

        wall_limit_ms = 2 * time_limit_ms + 1000
        # The watchdog enforces both limits to the ms; nsjail's whole-second
        # rlimit_cpu and time_limit are backstops a second above it.
        rlimit_cpu_s = math.ceil(time_limit_ms / 1000) + 1
        wall_limit_s = math.ceil(wall_limit_ms / 1000) + 1

        nsjail_cmd = self._build_command(
            command, code_dir, toolchain, config_path=config_path, rlimit_cpu_s=rlimit_cpu_s,
            wall_limit_s=wall_limit_s, writable=writable,
            log_file=log_path, stats_dir=stats_dir,
            stack_mb=memory_limit if measure else None,   # the compile stack is compile.cfg's
        )
        logger.debug("nsjail: %s", " ".join(nsjail_cmd))

        kill_reason = None   # first limit that killed the jail: output, memory, cpu or wall
        peak_bytes = 0
        memory_bytes = memory_limit * 1024 * 1024
        base_cpu_ms, base_bytes = self.overhead_cpu_ms, self.overhead_memory_bytes
        watcher = None

        def kill_jail(reason):
            nonlocal kill_reason
            kill_reason = kill_reason or reason
            try:
                run_cgroup.kill(spare=process.pid)   # nsjail survives to log the reap
            except OSError:
                process.kill()   # can't list the cgroup: take nsjail down, the jail with it

        async def watchdog():
            # Keeps killing while a limit stays exceeded, so nothing forked mid-kill survives.
            nonlocal peak_bytes
            while True:
                used = run_cgroup.memory_bytes() - base_bytes
                peak_bytes = max(peak_bytes, used)
                if used > memory_bytes:
                    kill_jail("memory")
                elif run_cgroup.cpu_time_ms() - base_cpu_ms > time_limit_ms:
                    kill_jail("cpu")
                elif (time.monotonic() - start) * 1000 > wall_limit_ms:
                    kill_jail("wall")
                await asyncio.sleep(WATCHDOG_POLL_S)

        start = time.monotonic()
        try:
            process = await asyncio.create_subprocess_exec(
                *nsjail_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=run_cgroup.join,
            )
            watcher = asyncio.create_task(watchdog())
            # Outer timeout sits above nsjail's wall backstop; if it fires
            # nsjail itself hung.
            outer = wall_limit_s + 10
            # Never buffer more than the cap. In the run phase stdout past the cap,
            # or a stderr flood, kills the jail (Output Limit Exceeded); stderr keeps
            # its tail, where tracebacks and memory markers are. Compiler output keeps
            # its head (the first error) and is never fatal. Both pipes are read to
            # EOF so the program can't block on a full pipe.
            cap = self.output_limit_bytes
            kill = (lambda: kill_jail("output")) if measure else None
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
            driver_ms = self._read_driver_ms(stats_path)
            exits = list(_NSJAIL_EXIT.finditer(nsjail_log))
            setup_failed = not exits or _NSJAIL_LAUNCH_FAILED in nsjail_log
            # Signal never comes from exit_code (a program may exit 139 itself).
            jail_signal = exits[-1].group(1) if exits else None
            signal = int(jail_signal) if jail_signal else None
            cpu_ms = max(0, run_cgroup.cpu_time_ms() - base_cpu_ms)

            # A watchdog kill decides alone. Otherwise, in the spec's order: nsjail's
            # wall backstop, the rlimit's SIGXCPU, then a program that exited on its
            # own after slipping past the CPU limit between two polls.
            if kill_reason in ("cpu", "wall"):
                time_limit_hit = kill_reason
            elif kill_reason or setup_failed:
                time_limit_hit = None
            elif "time limit" in nsjail_log.lower():
                time_limit_hit = "wall"
            elif signal == SIGXCPU or (signal is None and cpu_ms > time_limit_ms):
                time_limit_hit = "cpu"
            else:
                time_limit_hit = None

            if driver_ms is not None and 0 <= driver_ms <= elapsed_ms:
                runtime_ms = driver_ms
            else:
                runtime_ms = cpu_ms

            return SandboxResult(
                stdout=stdout, stderr=stderr, nsjail_log=nsjail_log, exit_code=exit_code,
                time_limit_hit=time_limit_hit, oom_killed=kill_reason == "memory",
                runtime_ms=runtime_ms, signal=signal,
                peak_memory_mb=math.ceil(peak_bytes / (1024 * 1024)), peak_memory_bytes=peak_bytes,
                wall_ms=elapsed_ms,
                driver_ms=driver_ms, cpu_ms=cpu_ms,
                setup_failed=setup_failed, output_exceeded=kill_reason == "output",
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
                                 None, False, elapsed_ms, None, setup_failed=True)
        except (FileNotFoundError, PermissionError, OSError) as e:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.error("Failed to launch nsjail: %s", e)
            return SandboxResult("", f"Failed to launch sandbox: {e}", "", -1,
                                 None, False, elapsed_ms, None, setup_failed=True)
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
    def _read_driver_ms(stats_path: str) -> Optional[int]:
        """The driver's last "driver_ns <int>" line in the stats file, in ms; None if absent."""
        driver_ms = None
        try:
            with open(stats_path, "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) == 2 and parts[0] == "driver_ns" and parts[1].isdigit():
                        driver_ms = (int(parts[1]) + 500_000) // 1_000_000
        except OSError:
            pass
        return driver_ms
