"""
Cgroup v2 delegation — lets nsjail run WITHOUT sudo.

nsjail only needs root to create cgroups under /sys/fs/cgroup and write the
limit files. If systemd delegates a cgroup subtree to the worker's user
(Delegate= in the unit, or `systemd-run --user --scope -p Delegate=yes`),
the worker owns that subtree and can hand nsjail a directory it is allowed
to write to. Everything else nsjail does (namespaces, mounts, seccomp,
rlimits) already works unprivileged via user namespaces.

Layout inside the delegated subtree:

    <delegated root>/            owned by the worker's user
    ├── supervisor/              leaf holding the worker process itself
    └── run-<id>/                one per sandbox run (created/removed per run)
        └── NSJAIL.<pid>/        created by nsjail, holds the jailed process

The worker must move itself into the `supervisor` leaf because of the
cgroup v2 "no internal processes" rule: a cgroup cannot both contain
processes and enable controllers for its children.

The per-run parent cgroup is what makes result classification reliable:
after nsjail exits (and removes its own NSJAIL.* child), the parent still
holds the aggregated counters, so the worker reads:
    memory.events  oom_kill > 0  → definitive memory-limit kill
    memory.peak                  → peak usage as the kernel accounted it
This works even when the whole PID namespace was SIGKILLed on a time-limit
kill, which no in-sandbox wrapper can report.
"""
import logging
import os
import uuid

from typing import Optional, Set

logger = logging.getLogger(__name__)

CGROUP_FS_ROOT = "/sys/fs/cgroup"
SUPERVISOR_LEAF = "supervisor"
RUN_PREFIX = "run-"


def _remove_cgroup_tree(path: str) -> bool:
    """rmdir a cgroup and its descendants bottom-up. True if fully removed."""
    for dirpath, _, _ in os.walk(path, topdown=False):
        try:
            os.rmdir(dirpath)
        except OSError:
            pass
    return not os.path.isdir(path)

# Controllers the sandbox needs. cpu is optional (used only for the
# cgroup_cpu_ms_per_sec throttle; rlimit_cpu + max_cpus still apply without it).
REQUIRED_CONTROLLERS = {"memory", "pids"}
OPTIONAL_CONTROLLERS = {"cpu"}


class RunCgroup:
    """A per-execution parent cgroup. nsjail creates its jail cgroup inside it."""

    def __init__(self, path: str):
        self.path = path

    def peak_memory_mb(self) -> int:
        """Peak memory of the run as the kernel accounted it, in MB (rounded up).

        Read from the parent cgroup, so it survives nsjail removing its own
        child cgroup, and reflects exactly what the memory limit enforces
        (RSS + page cache + kernel memory). 0 if unavailable.
        """
        value = self._read("memory.peak")
        if value is None or not value.isdigit():
            return 0
        return (int(value) + (1024 * 1024) - 1) // (1024 * 1024)

    def cpu_time_ms(self) -> int:
        """
        CPU time consumed by the run's subtree, in ms, from cpu.stat
        (usage_usec). Available even without the cpu controller enabled.
        Wall-vs-CPU separation shows whether a run was compute-bound or
        waiting. 0 if unavailable.
        """
        stat = self._read("cpu.stat")
        if stat is None:
            return 0
        for line in stat.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "usage_usec" and parts[1].isdigit():
                return int(parts[1]) // 1000
        return 0

    def oom_killed(self) -> bool:
        """True if the kernel OOM-killed a process in this run's subtree."""
        events = self._read("memory.events")
        if events is None:
            return False
        for line in events.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "oom_kill":
                return parts[1] != "0"
        return False

    def remove(self) -> None:
        """
        Remove the run cgroup, including any nested NSJAIL.* child left
        behind if nsjail was killed before its own cleanup ran. Cgroup dirs
        can only be rmdir'd, bottom-up, and only when empty of processes.
        """
        if not _remove_cgroup_tree(self.path):
            # Not fatal — a stale dir is swept on the next worker startup
            logger.warning("Could not remove run cgroup %s", self.path)

    def _read(self, filename: str) -> Optional[str]:
        try:
            with open(os.path.join(self.path, filename), "r") as f:
                return f.read().strip()
        except OSError:
            return None


class CgroupDelegation:
    """
    The worker's delegated cgroup v2 subtree.

    Use try_setup() to create one — it returns None (with a logged reason)
    when the worker is not running inside a delegated subtree, in which
    case the worker refuses to start (see main.py).
    """

    def __init__(self, root: str, controllers: Set[str]):
        self.root = root
        self.controllers = controllers

    @classmethod
    def try_setup(cls) -> Optional["CgroupDelegation"]:
        """
        Detect a delegated subtree and prepare it for sandbox runs.

        Steps:
          1. Find our own cgroup and check we own it (that's what systemd
             delegation means at the filesystem level).
          2. Check the memory and pids controllers are available.
          3. Move ourselves into the `supervisor` leaf and enable controllers
             for future sibling (run-*) cgroups.

        Any failure returns None; the caller decides how to fail.
        """
        root = cls._own_cgroup_dir()
        if root is None:
            return None

        # A restarted worker begins life inside the supervisor leaf created
        # by the previous run (children inherit the parent's cgroup). Climb
        # back to the delegated root instead of nesting supervisor/supervisor
        # one level deeper on every restart.
        while os.path.basename(root) == SUPERVISOR_LEAF:
            root = os.path.dirname(root)

        if not os.access(os.path.join(root, "cgroup.procs"), os.W_OK):
            logger.info(
                "Cgroup %s is not writable — not a delegated subtree", root)
            return None

        try:
            with open(os.path.join(root, "cgroup.controllers")) as f:
                available = set(f.read().split())
        except OSError as e:
            logger.info("Cannot read cgroup.controllers in %s: %s", root, e)
            return None

        missing = REQUIRED_CONTROLLERS - available
        if missing:
            logger.info(
                "Delegated cgroup %s lacks required controller(s) %s "
                "(available: %s)", root, sorted(missing), sorted(available))
            return None

        controllers = REQUIRED_CONTROLLERS | (OPTIONAL_CONTROLLERS & available)

        try:
            cls._move_procs_to_supervisor(root)
            cls._enable_subtree_controllers(root, controllers)
        except OSError as e:
            logger.info("Could not prepare delegated cgroup %s: %s", root, e)
            return None

        cls._sweep_stale_run_cgroups(root)

        logger.info(
            "Rootless sandbox enabled: delegated cgroup %s (controllers: %s)",
            root, " ".join(sorted(controllers)))
        return cls(root, controllers)

    def create_run_cgroup(self) -> RunCgroup:
        """Create a fresh parent cgroup for one sandbox run."""
        path = os.path.join(self.root, f"{RUN_PREFIX}{uuid.uuid4().hex[:12]}")
        os.mkdir(path)
        # Enable controllers so nsjail's child cgroup gets memory.max/pids.max
        with open(os.path.join(path, "cgroup.subtree_control"), "w") as f:
            f.write(" ".join(f"+{c}" for c in sorted(self.controllers)))
        return RunCgroup(path)

    # ---- setup helpers ------------------------------------------------------

    @staticmethod
    def _own_cgroup_dir() -> Optional[str]:
        """Resolve this process's cgroup v2 directory, or None."""
        try:
            with open("/proc/self/cgroup") as f:
                for line in f:
                    # cgroup v2 unified hierarchy line: "0::/path"
                    if line.startswith("0::"):
                        rel = line.split("::", 1)[1].strip()
                        return CGROUP_FS_ROOT + rel
        except OSError as e:
            logger.info("Cannot read /proc/self/cgroup: %s", e)
        return None

    @staticmethod
    def _move_procs_to_supervisor(root: str) -> None:
        """
        Move every process in the subtree root (normally just this worker)
        into the supervisor leaf, freeing the root of the "no internal
        processes" rule so controllers can be enabled for children.
        """
        leaf = os.path.join(root, SUPERVISOR_LEAF)
        os.makedirs(leaf, exist_ok=True)
        with open(os.path.join(root, "cgroup.procs")) as f:
            pids = f.read().split()
        for pid in pids:
            try:
                with open(os.path.join(leaf, "cgroup.procs"), "w") as f:
                    f.write(pid)
            except OSError:
                # Process may have exited between read and write
                pass

    @staticmethod
    def _enable_subtree_controllers(root: str, controllers: Set[str]) -> None:
        with open(os.path.join(root, "cgroup.subtree_control"), "w") as f:
            f.write(" ".join(f"+{c}" for c in sorted(controllers)))

    @staticmethod
    def _sweep_stale_run_cgroups(root: str) -> None:
        """Remove empty run-* cgroups left behind by a previous crash."""
        try:
            entries = os.listdir(root)
        except OSError:
            return
        for entry in entries:
            if not entry.startswith(RUN_PREFIX):
                continue
            path = os.path.join(root, entry)
            # Bottom-up rmdir; a cgroup with live processes stays (EBUSY)
            if _remove_cgroup_tree(path):
                logger.info("Removed stale run cgroup: %s", path)
