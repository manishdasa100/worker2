"""
Language handler interface.

A handler is declarative — it does NOT run subprocesses. It says:
  1. how to lay source files out in the code dir   (write_files)
  2. the command that compiles them, if any         (compile_command)
  3. the command that runs them                      (run_command)
  4. how to probe its runtime version                (version_command, for CALIBRATE)

Both compile_command and run_command execute INSIDE the jail (cwd=/code, the
code dir bind-mounted there) — so paths are sandbox-internal (/code/..., or
relative to /code). The judge orchestrates: sandbox.compile(compile_command())
then sandbox.run(run_command()). This is the worker2 change that closes the
host-side compile hole: the compiler never runs on the host.

Per-language fairness knobs (applied by the judge):
  time_multiplier     — the request's time budget is calibrated for compiled
                        speed; slower runtimes get budget x this so the same
                        algorithm passes in every language (standard judge convention).
  memory_baseline_mb  — added to the request's memory limit so "128 MB" means
                        128 MB usable by the solution, not minus runtime overhead.
  oom_error_markers   — stderr substrings meaning the RUNTIME itself reported
                        memory exhaustion (e.g. JVM OutOfMemoryError exits 1
                        before the cgroup OOM killer). Lets the judge class it MLE.
"""
from abc import ABC, abstractmethod
from typing import List, Optional


class BaseLanguage(ABC):
    time_multiplier: float = 1.0
    memory_baseline_mb: int = 0
    oom_error_markers: tuple = ()

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def write_files(self, code_dir: str, user_code: str, driver_code: str) -> None:
        ...

    @abstractmethod
    def compile_command(self) -> Optional[List[str]]:
        """Command to compile inside the jail, or None for interpreted languages."""
        ...

    @abstractmethod
    def run_command(self, memory_limit_mb: int) -> List[str]:
        """
        Command to run inside the jail. memory_limit_mb is the enforced cgroup
        limit — languages that must size their own heap derive it from this
        (Java sets -Xmx to it so heap death lands as a cgroup OOM => MLE).
        """
        ...

    @abstractmethod
    def version_command(self) -> List[str]:
        """Host-side command printing the runtime/compiler version (CALIBRATE metadata)."""
        ...
