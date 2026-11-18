import os
from typing import List

from languages.base import BaseLanguage, LOADER, Toolchain

RUST_ROOT = "/opt/rust"
RUSTC = f"{RUST_ROOT}/bin/rustc"


class RustLanguage(BaseLanguage):
    """
    Layout in code_dir:  solution.rs (user), main.rs (driver, `mod solution;`),
    main (static binary). Only main.rs is passed to rustc; it finds solution.rs
    through the `mod`. The run jail holds nothing but the workspace.
    """
    # gcc-13 links (from /usr). rustc finds its libraries through $ORIGIN, which the
    # loader resolves from /proc/self/exe; jails have no /proc, so name the directory.
    compile_toolchain = Toolchain(mounts=("/usr", LOADER, RUST_ROOT),
                                  env=(f"LD_LIBRARY_PATH={RUST_ROOT}/lib",))
    run_toolchain = Toolchain()   # static: nothing but the workspace
    # Compiled to native code with no runtime: the reference language's x1 and no baseline,
    # so the base defaults stand.
    oom_error_markers = ("memory allocation of",)   # "memory allocation of N bytes failed", SIGABRT

    @property
    def name(self) -> str:
        return "Rust"

    def write_files(self, code_dir: str, user_code: str, driver_code: str) -> None:
        with open(os.path.join(code_dir, "solution.rs"), "w") as f:
            f.write(user_code)
        with open(os.path.join(code_dir, "main.rs"), "w") as f:
            f.write(driver_code)

    def compile_commands(self) -> List[List[str]]:
        # cwd=/code. crt-static: glibc linked in, so the binary runs with nothing mounted.
        # The image keeps no rust-lld (its wrapper needs /proc/self/exe anyway): link with gcc.
        return [[RUSTC, "--edition", "2021", "-O", "-C", "debuginfo=0",
                 "-C", "target-feature=+crt-static",
                 "-C", "linker=/usr/bin/gcc-13", "-C", "linker-features=-lld",
                 "-o", "main", "main.rs"]]

    def run_command(self, memory_limit_mb: int) -> List[str]:
        return ["/code/main"]

    def version_command(self) -> List[str]:
        return [RUSTC, "--version"]
