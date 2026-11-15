from typing import List

from languages.base import BaseLanguage, SHARED_LIBS, Toolchain

# The bind follows the symlink, so the jail's /usr/bin/python3 is the interpreter itself.
TOOLCHAIN = Toolchain(mounts=("/usr/bin/python3", "/usr/lib/python3.12", *SHARED_LIBS))


class PythonLanguage(BaseLanguage):
    """
    Layout in code_dir:  solution.py (user), main.py (driver). The compile step
    only checks syntax (byte-compiling, nothing runs), so a syntax error is a
    Compile Error carrying the interpreter's message.
    """
    compile_toolchain = TOOLCHAIN
    run_toolchain = TOOLCHAIN
    # CPython ~3x compiled C++ on typical judge work; interpreter ~10-15 MB baseline.
    time_multiplier = 3.0
    memory_baseline_mb = 16
    oom_error_markers = ("MemoryError",)   # malloc / rlimit_as exhaustion

    @property
    def name(self) -> str:
        return "Python"

    def write_files(self, code_dir: str, user_code: str, driver_code: str) -> None:
        import os
        with open(os.path.join(code_dir, "solution.py"), "w") as f:
            f.write(user_code)
        with open(os.path.join(code_dir, "main.py"), "w") as f:
            f.write(driver_code)

    def compile_commands(self) -> List[List[str]]:
        # Leaves the .pyc files in /code, where the run phase's import reuses them.
        return [["/usr/bin/python3", "-m", "py_compile", "main.py", "solution.py"]]

    def run_command(self, memory_limit_mb: int) -> List[str]:
        # -u: unbuffered, so debug prints survive a TLE/MLE SIGKILL and reach the report.
        return ["/usr/bin/python3", "-u", "/code/main.py"]

    def version_command(self) -> List[str]:
        return ["/usr/bin/python3", "--version"]
