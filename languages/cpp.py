from typing import List

from languages.base import BaseLanguage, LOADER, Toolchain


class CppLanguage(BaseLanguage):
    """
    Layout in code_dir:  solution.cpp (user), main.cpp (driver, #include "solution.cpp"),
    main (compiled binary). Compiled inside the jail: only main.cpp is passed to g++;
    it pulls in solution.cpp.
    """
    compile_toolchain = Toolchain(mounts=("/usr", LOADER))
    run_toolchain = Toolchain()   # static: the run jail holds nothing but the workspace
    # Reference language: limits are calibrated to compiled speed; no runtime baseline.
    time_multiplier = 1.0
    memory_baseline_mb = 0
    oom_error_markers = ("std::bad_alloc",)   # failed alloc -> uncaught bad_alloc (SIGABRT)

    @property
    def name(self) -> str:
        return "C++"

    def write_files(self, code_dir: str, user_code: str, driver_code: str) -> None:
        import os
        with open(os.path.join(code_dir, "solution.cpp"), "w") as f:
            f.write(user_code)
        with open(os.path.join(code_dir, "main.cpp"), "w") as f:
            f.write(driver_code)

    def compile_commands(self) -> List[List[str]]:
        # Runs inside the compile jail with cwd=/code (relative paths resolve there).
        # Writes /code/main, which the run jail then executes read-only.
        return [["/usr/bin/g++-13", "-std=gnu++20", "-O2", "-static", "-o", "main", "main.cpp"]]

    def run_command(self, memory_limit_mb: int) -> List[str]:
        return ["/code/main"]

    def version_command(self) -> List[str]:
        return ["/usr/bin/g++-13", "--version"]
