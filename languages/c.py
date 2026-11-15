import os
from typing import List

from languages.cpp import CppLanguage


class CLanguage(CppLanguage):
    """
    Layout in code_dir:  solution.c (user), main.c (driver, #include "solution.c"),
    main (compiled binary). As C++: only main.c is passed to gcc, the binary is
    static, and the run jail holds nothing but the workspace.
    """
    oom_error_markers = ()   # malloc returns NULL; C has no runtime out-of-memory message

    @property
    def name(self) -> str:
        return "C"

    def write_files(self, code_dir: str, user_code: str, driver_code: str) -> None:
        with open(os.path.join(code_dir, "solution.c"), "w") as f:
            f.write(user_code)
        with open(os.path.join(code_dir, "main.c"), "w") as f:
            f.write(driver_code)

    def compile_commands(self) -> List[List[str]]:
        # -lm: static glibc keeps the math functions in libm, which gcc doesn't link by default.
        return [["/usr/bin/gcc-13", "-std=gnu17", "-O2", "-static", "-o", "main", "main.c", "-lm"]]

    def version_command(self) -> List[str]:
        return ["/usr/bin/gcc-13", "--version"]
