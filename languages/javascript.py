import os
from typing import List

from languages.base import BaseLanguage, SHARED_LIBS, Toolchain

NODE = "/opt/node/bin/node"
# No UV_USE_IO_URING=0 (judgebox sets it): libuv probes io_uring at startup either
# way (profiled, ticket 12), and seccomp answers ENOSYS.
TOOLCHAIN = Toolchain(mounts=(NODE, *SHARED_LIBS))


class JavaScriptLanguage(BaseLanguage):
    """
    Layout in code_dir:  solution.js (user, CommonJS: module.exports), main.js
    (driver, require('./solution')). The compile step is `node --check` on each
    file, so a syntax error is a Compile Error carrying Node's message.
    """
    compile_toolchain = TOOLCHAIN
    run_toolchain = TOOLCHAIN
    # JIT-compiled: judgebox's x2. An empty program peaks at ~117 MB under gVisor
    # (~108 MB above an empty jail; measured, ticket 12), which judgebox's 64 doesn't
    # cover. Confirmed by CALIBRATE (ticket 16).
    time_multiplier = 2.0
    memory_baseline_mb = 128
    # V8's own "FATAL ERROR: ... JavaScript heap out of memory". With the heap as large
    # as the limit, the memory watch usually kills a heap blow-up first (MLE either way).
    oom_error_markers = ("JavaScript heap out of memory",)

    @property
    def name(self) -> str:
        return "JavaScript"

    def write_files(self, code_dir: str, user_code: str, driver_code: str) -> None:
        with open(os.path.join(code_dir, "solution.js"), "w") as f:
            f.write(user_code)
        with open(os.path.join(code_dir, "main.js"), "w") as f:
            f.write(driver_code)

    def compile_commands(self) -> List[List[str]]:
        # --check parses one file without running it, so one command per file.
        return [[NODE, "--check", "solution.js"], [NODE, "--check", "main.js"]]

    def run_command(self, memory_limit_mb: int) -> List[str]:
        # Heap = the limit, as Java's -Xmx: V8 can't size it itself without /proc and /sys.
        # --stack-size: V8's own recursion limit in KB (its default is under 1 MB). About
        # 64 MB, judgebox's value; it must stay below the stack rlimit, which is the memory
        # limit and so at least the 128 MB baseline.
        # One V8 worker thread: glibc gives each thread a stack the size of that rlimit,
        # and from a 768 MB limit V8's default four overrun rlimit_as and Node hangs at
        # startup. It also keeps GC work on the solution's thread.
        return [NODE, f"--max-old-space-size={memory_limit_mb}", "--stack-size=65500",
                "--v8-pool-size=1", "/code/main.js"]

    def version_command(self) -> List[str]:
        return [NODE, "--version"]
