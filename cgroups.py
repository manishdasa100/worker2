"""
Per-jail cgroups on the cgroupfs runsc exposes inside the executor container.

runsc mounts cgroup v1, one hierarchy per controller (ticket 04):
/sys/fs/cgroup/{cpu,cpuacct,cpuset,devices,job,memory,pids}. The executor
runs as root in its container, so it can make child cgroups there.

Each jail gets one cgroup named jail-<id> under memory, cpuacct and pids.
nsjail itself joins it before exec (preexec), so the jail and everything it
forks inherit it. nsjail's own cgroup support is not used. Readings therefore
include nsjail's own small footprint.

gVisor accounts memory per cgroup but does not enforce memory.limit_in_bytes,
and has no memory.max_usage_in_bytes, so the executor polls usage itself, for
both the peak and the limit.
"""
import logging
import os
import signal
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

CGROUP_FS_ROOT = "/sys/fs/cgroup"
CONTROLLERS = ("memory", "cpuacct", "pids")
JAIL_PREFIX = "jail-"


def require() -> None:
    """
    Refuse to start unless this process can make cgroups on runsc's v1
    cgroupfs, i.e. it is root inside an executor container. Clears jail
    cgroups left by a crashed predecessor.
    """
    # gVisor's own `job` controller: present under runsc, never on a Linux host or runc.
    if not os.path.isdir(os.path.join(CGROUP_FS_ROOT, "job")):
        raise RuntimeError(f"No gVisor cgroupfs at {CGROUP_FS_ROOT}: the executor runs only under runsc.")
    probe = JailCgroup.create(pids_max=1)
    probe.remove()
    for controller in CONTROLLERS:
        root = os.path.join(CGROUP_FS_ROOT, controller)
        for entry in os.listdir(root):
            if entry.startswith(JAIL_PREFIX):
                try:
                    os.rmdir(os.path.join(root, entry))
                except OSError as e:
                    logger.warning("Could not remove stale cgroup %s/%s: %s", controller, entry, e)


class JailCgroup:
    """One jail's cgroup, the same name under every controller."""

    def __init__(self, name: str):
        self.dirs = {c: os.path.join(CGROUP_FS_ROOT, c, name) for c in CONTROLLERS}

    @classmethod
    def create(cls, pids_max: int) -> "JailCgroup":
        cg = cls(f"{JAIL_PREFIX}{uuid.uuid4().hex[:12]}")
        try:
            for d in cg.dirs.values():
                os.mkdir(d)
            cg._write("pids", "pids.max", str(pids_max))
        except OSError as e:
            cg.remove()
            raise RuntimeError(
                f"Cannot create a jail cgroup ({e}). The executor must run as root "
                f"inside a runsc container exposing cgroup v1 at {CGROUP_FS_ROOT}.") from e
        return cg

    def join(self) -> None:
        """Move the calling process into the cgroup. Runs in the child before exec."""
        for d in self.dirs.values():
            with open(os.path.join(d, "cgroup.procs"), "w") as f:
                f.write(str(os.getpid()))

    def memory_bytes(self) -> int:
        value = self._read("memory", "memory.usage_in_bytes")
        return int(value) if value and value.isdigit() else 0

    def cpu_time_ms(self) -> int:
        value = self._read("cpuacct", "cpuacct.usage")     # ns
        return int(value) // 1_000_000 if value and value.isdigit() else 0

    def kill(self, spare: Optional[int] = None) -> None:
        """
        SIGKILL every process in the cgroup but `spare` (nsjail, so it still
        logs the reap). Raises OSError if the cgroup can't be listed.
        """
        with open(os.path.join(self.dirs["memory"], "cgroup.procs")) as f:
            pids = f.read().split()
        for pid in pids:
            if int(pid) != spare:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def remove(self) -> None:
        for d in self.dirs.values():
            try:
                os.rmdir(d)
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.warning("Could not remove cgroup %s: %s", d, e)   # require() sweeps it next start

    def _read(self, controller: str, filename: str) -> Optional[str]:
        try:
            with open(os.path.join(self.dirs[controller], filename)) as f:
                return f.read().strip()
        except OSError:
            return None

    def _write(self, controller: str, filename: str, value: str) -> None:
        with open(os.path.join(self.dirs[controller], filename), "w") as f:
            f.write(value)
