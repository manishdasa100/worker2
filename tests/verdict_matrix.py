"""
Verdict matrix against the real sandbox: TLE/MLE/RE classification, per-language
fairness, worker caps. time_limit is CPU-ms, memory_limit is MB.

Parked: the judge now runs only inside an executor container (cgroups.py), so
this in-process script no longer runs as is. Ticket 07 moves it onto Seam A
(tests/executor_harness.py).
"""
import asyncio
import os
import sys
import time
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cgroups
from config import load_config
from judge import Judge
from languages import LANGUAGES
from languages.python import PythonLanguage
from models import ExecutionRequest

PY_DRV = "from solution import f\nprint(f())\n"
CPP_DRV = '#include <iostream>\n#include "solution.cpp"\nint main(){ std::cout << f() << std::endl; }\n'
JAVA_DRV = "public class Main { public static void main(String[] a){ System.out.println(Solution.f()); } }"


class UnlaunchableRun(PythonLanguage):
    def run_command(self, memory_limit_mb):
        return ["/nonexistent"]


class UnlaunchableCompile(PythonLanguage):
    def compile_commands(self):
        return [["/nonexistent"]]


# nsjail setup failures must stay worker failures (IE -> FAILED).
LANGUAGES["broken-run"] = UnlaunchableRun()
LANGUAGES["broken-compile"] = UnlaunchableCompile()

# (name, lang, solution, driver, time_ms, mem_mb, expected[, runtime_error must contain])
CASES = [
    ("java-64mb-ok", "java",
     "public class Solution { static long f(){ long s=0; int[][] a=new int[64][];"
     " for(int i=0;i<64;i++){a[i]=new int[262144]; s+=a[i].length;} return s>0?42:0; } }", JAVA_DRV, 5000, 128, "ACC"),
    ("java-300mb-mle", "java",
     "public class Solution { static long f(){ long s=0; int[][] a=new int[300][];"
     " for(int i=0;i<300;i++){a[i]=new int[262144]; s+=a[i].length;} return s>0?42:0; } }", JAVA_DRV, 5000, 128, "MLE"),
    ("cpp-2gb-mle", "cpp",
     "#include <vector>\nlong f(){ std::vector<char> v(2000000000,1); return v.size()>0?42:0; }\n", CPP_DRV, 5000, 128, "MLE"),
    ("py-200mb-mle", "python",
     "def f():\n    x=' '*(200*1024*1024)\n    return 42 if len(x) else 0\n", PY_DRV, 5000, 128, "MLE"),
    ("py-loop-tle", "python", "def f():\n    while True: pass\n", PY_DRV, 1000, 64, "TLE"),
    ("cpp-loop-tle", "cpp", "long f(){ volatile long i=0; while(true) i++; return i; }\n", CPP_DRV, 1000, 64, "TLE"),
    ("py-sleeper-tle", "python", "import time\ndef f():\n    time.sleep(60)\n    return 42\n", PY_DRV, 1000, 64, "TLE"),
    ("py-slow-acc", "python",
     "import time\ndef f():\n    t=time.process_time()\n    while time.process_time()-t<2.2: pass\n    return 42\n",
     PY_DRV, 1000, 64, "ACC"),   # 1000ms x3 python = 3000ms CPU budget; 2.2s passes
    ("cpp-segv-re", "cpp", "long f(){ int* p=0; *p=1; return *p; }\n", CPP_DRV, 2000, 64, "RE", "SIGSEGV"),
    # D1: a program's own exit code is never a worker failure nor a signal
    ("py-exit255-re", "python", "import sys\ndef f():\n    sys.exit(255)\n", PY_DRV, 1000, 64, "RE", "exit code 255"),
    ("py-stderr-exit-re", "python", "import sys\ndef f():\n    print('oops', file=sys.stderr)\n    sys.exit(3)\n",
     PY_DRV, 1000, 64, "RE", "exit code 3"),
    ("py-exit139-re", "python", "import sys\ndef f():\n    sys.exit(139)\n", PY_DRV, 1000, 64, "RE", "exit code 139"),
    ("cpp-sigsys-re", "cpp", "#include <sched.h>\nlong f(){ unshare(0); return 42; }\n", CPP_DRV, 2000, 64,
     "RE", "forbidden syscall"),
    # A runtime memory marker after a lot of stderr is still seen (stderr keeps its tail)
    ("py-noisy-memerr-mle", "python",
     "import sys\ndef f():\n    sys.stderr.write('e' * 300000 + '\\n')\n    x = 'x' * (10**12)\n    return 42\n",
     PY_DRV, 1000, 64, "MLE"),
    ("run-setup-ie", "broken-run", "def f():\n    return 42\n", PY_DRV, 1000, 64, "IE"),
    ("compile-setup-ie", "broken-compile", "def f():\n    return 42\n", PY_DRV, 1000, 64, "IE"),
]
EXPECTED = {"input": "", "expectedOutput": "42"}


async def main():
    config = load_config(env_file=".env.dev")
    cgroups.require()
    judge = Judge(config)
    failures = 0

    for name, lang, sol, drv, tl, ml, want, *must_say in CASES:
        t0 = time.monotonic()
        report = await judge.judge(ExecutionRequest(
            job_id=name, language=lang, user_code=sol, driver_code=drv,
            task="SUBMIT_CODE", time_limit=tl, memory_limit=ml, test_cases=[EXPECTED]))
        said = report.runtime_error or ""
        ok = report.status_code == want and all(m in said for m in must_say)
        failures += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'} {name:16s} -> {report.status_code:3s} (want {want}) "
              f"wall={time.monotonic()-t0:4.1f}s mem={report.memory_mb}MB"
              + (f" error={said[:60]!r}" if must_say else ""))

    # too many test cases -> IE
    report = await judge.judge(ExecutionRequest(
        job_id="too-many", language="python", user_code="def f():\n    return 42\n", driver_code=PY_DRV,
        task="SUBMIT_CODE", time_limit=5000, memory_limit=64, test_cases=[EXPECTED]*(config.execution.max_testcases+1)))
    ok = report.status_code == "IE"; failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {'too-many-tc':16s} -> {report.status_code:3s} (want IE)")

    # TLE keeps partial output
    report = await judge.judge(ExecutionRequest(
        job_id="tle-output", language="python",
        user_code="def f():\n    print('debug marker 123')\n    while True: pass\n", driver_code=PY_DRV,
        task="SUBMIT_CODE", time_limit=1000, memory_limit=64, test_cases=[EXPECTED]))
    kept = report.failed_testcase and "debug marker 123" in (report.failed_testcase.std_output or "")
    failures += 0 if kept else 1
    print(f"{'PASS' if kept else 'FAIL'} {'tle-keeps-output':16s} -> retained: {bool(kept)}")

    # D2: a stdout flood is cut off at the output cap, promptly, without the
    # worker buffering it; stdout just under the cap is judged normally.
    cap = config.execution.max_output_bytes
    tracemalloc.start()
    t0 = time.monotonic()
    report = await judge.judge(ExecutionRequest(
        job_id="stdout-flood", language="python",
        user_code="def f():\n    while True: print('x' * 65536)\n", driver_code=PY_DRV,
        task="SUBMIT_CODE", time_limit=1000, memory_limit=64, test_cases=[EXPECTED]))
    wall = time.monotonic() - t0
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    ok = report.status_code == "OLE" and wall < 1 and peak < 4 * cap
    failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {'stdout-flood-ole':16s} -> {report.status_code:3s} (want OLE) "
          f"wall={wall:4.1f}s (<1s) worker-peak={peak // 1024}KB (<{4 * cap // 1024}KB)")

    report = await judge.judge(ExecutionRequest(
        job_id="stdout-under-cap", language="python",
        user_code=f"def f():\n    print('x' * {cap - 100})\n    return 42\n", driver_code=PY_DRV,
        task="SUBMIT_CODE", time_limit=2000, memory_limit=64, test_cases=[EXPECTED]))
    ok = report.status_code == "ACC"; failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {'stdout-under-cap':16s} -> {report.status_code:3s} (want ACC)")

    # stderr is capped separately and never ends a run: the flood finishes and
    # the program's own exit code is reported, with stderr truncated to the cap.
    report = await judge.judge(ExecutionRequest(
        job_id="stderr-flood", language="python",
        user_code="import sys\ndef f():\n    for _ in range(64): sys.stderr.write('e' * 65536)\n    sys.exit(3)\n",
        driver_code=PY_DRV, task="SUBMIT_CODE", time_limit=2000, memory_limit=64, test_cases=[EXPECTED]))
    stderr_len = len(report.failed_testcase.stderr or "") if report.failed_testcase else -1
    ok = (report.status_code == "RE" and "exit code 3" in (report.runtime_error or "")
          and 0 < stderr_len <= cap)
    failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {'stderr-flood-re':16s} -> {report.status_code:3s} (want RE) "
          f"stderr={stderr_len}B (<={cap}B)")

    # ...but a stderr flood (past 32x the cap) is cut off like a stdout one.
    t0 = time.monotonic()
    report = await judge.judge(ExecutionRequest(
        job_id="stderr-flood-ole", language="python",
        user_code="import sys\ndef f():\n    while True: sys.stderr.write('e' * 65536)\n", driver_code=PY_DRV,
        task="SUBMIT_CODE", time_limit=1000, memory_limit=64, test_cases=[EXPECTED]))
    wall = time.monotonic() - t0
    ok = report.status_code == "OLE" and wall < 1
    failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {'stderr-flood-ole':16s} -> {report.status_code:3s} (want OLE) wall={wall:4.1f}s (<1s)")

    total = len(CASES) + 6
    print(f"\n{total - failures}/{total} passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    asyncio.run(main())
