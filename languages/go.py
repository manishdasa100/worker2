import os
from typing import List

from languages.base import BaseLanguage, Toolchain

GOROOT = "/usr/local/go"
GO_TOOL_DIR = f"{GOROOT}/pkg/tool/linux_amd64"
# The standard library, compiled once at image build (Dockerfile): an importcfg naming
# each package's archive. Read-only, so no build cache is shared between jobs.
GO_STD = "/opt/go-std"
IMPORTCFG = f"{GO_STD}/importcfg"


class GoLanguage(BaseLanguage):
    """
    Layout in code_dir:  solution.go (user) and main.go (driver), both package main;
    main.a (compiled package), main (static binary). Compiled and linked directly
    against the prebuilt standard library: about a second, where `go build` with an
    empty cache spends ~10 s rebuilding it.
    """
    compile_toolchain = Toolchain(mounts=(GOROOT, GO_STD), env=(f"GOROOT={GOROOT}",))
    # Static: the run jail holds nothing but the workspace. One P, so the scheduler and
    # GC don't size themselves to whatever CPU count the jail reports.
    run_toolchain = Toolchain(env=("GOMAXPROCS=1",))
    # Garbage collected and bounds-checked: judgebox's x1.5, and its measured 8 MB of runtime.
    time_multiplier = 1.5
    memory_baseline_mb = 8
    oom_error_markers = ("runtime: out of memory",)   # "fatal error: ...", exit 2

    @property
    def name(self) -> str:
        return "Go"

    def write_files(self, code_dir: str, user_code: str, driver_code: str) -> None:
        with open(os.path.join(code_dir, "solution.go"), "w") as f:
            f.write(user_code)
        with open(os.path.join(code_dir, "main.go"), "w") as f:
            f.write(driver_code)

    def compile_commands(self) -> List[List[str]]:
        # cwd=/code. -complete: no assembly files, so every function needs a body.
        return [
            [f"{GO_TOOL_DIR}/compile", "-p", "main", "-complete", "-importcfg", IMPORTCFG,
             "-pack", "-o", "main.a", "main.go", "solution.go"],
            [f"{GO_TOOL_DIR}/link", "-s", "-w", "-buildmode=exe", "-importcfg", IMPORTCFG,
             "-o", "main", "main.a"],
        ]

    def run_command(self, memory_limit_mb: int) -> List[str]:
        return ["/code/main"]

    def version_command(self) -> List[str]:
        return [f"{GO_TOOL_DIR}/compile", "-V"]
