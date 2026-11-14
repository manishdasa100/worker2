import os
from typing import List, Optional

from languages.base import BaseLanguage

JAVA_PATH = os.environ.get("JAVA_PATH", "/usr/lib/jvm/java-21-openjdk-amd64/bin/java")
JAVAC_PATH = os.path.join(os.path.dirname(JAVA_PATH), "javac")


class JavaLanguage(BaseLanguage):
    """
    Layout in code_dir:  Solution.java (user), Main.java (driver), *.class (compiled).
    Compiled inside the jail with javac; run with java -cp /code Main.
    """
    # JIT-compiled: ~2x the C++ budget absorbs JVM startup (~100-250ms) + warmup.
    # An empty main peaks at ~180 MB under gVisor (measured, ticket 07; flags
    # barely move it), so start from judgebox's 192. Confirmed by CALIBRATE (ticket 16).
    time_multiplier = 2.0
    memory_baseline_mb = 192
    oom_error_markers = ("java.lang.OutOfMemoryError",)   # heap death below cgroup limit, exit 1

    @property
    def name(self) -> str:
        return "Java"

    def write_files(self, code_dir: str, user_code: str, driver_code: str) -> None:
        with open(os.path.join(code_dir, "Solution.java"), "w") as f:
            f.write(user_code)
        with open(os.path.join(code_dir, "Main.java"), "w") as f:
            f.write(driver_code)

    def compile_command(self) -> Optional[List[str]]:
        # cwd=/code inside the jail; writes *.class there for the run jail.
        return [JAVAC_PATH, "Main.java", "Solution.java"]

    def run_command(self, memory_limit_mb: int) -> List[str]:
        # -Xmx = the cgroup limit, so heap+overhead crosses the cgroup ceiling and
        # memory-hungry solutions die by cgroup OOM (-> MLE) rather than an
        # artificially small heap aborting far below it. The JVM can't self-size
        # (/sys isn't mounted), so set it explicitly.
        # SerialGC + one processor: no GC/JIT thread pools sized to the host's
        # cores, so CPU time and startup memory belong to the solution.
        return [
            JAVA_PATH,
            "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1", "-XX:-UsePerfData",
            "-Xms8m", f"-Xmx{memory_limit_mb}m",
            "-XX:MaxMetaspaceSize=64m",
            "-cp", "/code", "Main",
        ]

    def version_command(self) -> List[str]:
        return [JAVA_PATH, "-version"]   # prints to stderr
