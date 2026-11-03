"""
Verdict matrix against the real sandbox: TLE/MLE/RE classification, per-language
fairness, worker caps. time_limit is CPU-ms, memory_limit is MB.

    systemd-run --user --scope -p Delegate=yes .venv/bin/python tests/verdict_matrix.py
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cgroups import CgroupDelegation
from config import load_config
from judge import Judge
from models import ExecutionRequest

PY_DRV = "from solution import f\nprint(f())\n"
CPP_DRV = '#include <iostream>\n#include "solution.cpp"\nint main(){ std::cout << f() << std::endl; }\n'
JAVA_DRV = "public class Main { public static void main(String[] a){ System.out.println(Solution.f()); } }"

# (name, lang, solution, driver, time_ms, mem_mb, expected)
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
    ("cpp-segv-re", "cpp", "long f(){ int* p=0; *p=1; return *p; }\n", CPP_DRV, 2000, 64, "RE"),
]
EXPECTED = {"input": "", "expectedOutput": "42"}


async def main():
    config = load_config(env_file=".env.dev")
    delegation = CgroupDelegation.try_setup()
    if delegation is None:
        print("No delegated cgroup subtree — run via systemd-run"); sys.exit(2)
    judge = Judge(config, delegation)
    await judge.warmup()
    failures = 0

    for name, lang, sol, drv, tl, ml, want in CASES:
        t0 = time.monotonic()
        report = await judge.judge(ExecutionRequest(
            job_id=name, language=lang, user_code=sol, driver_code=drv,
            task="SUBMIT_CODE", time_limit=tl, memory_limit=ml, test_cases=[EXPECTED]))
        ok = report.status_code == want
        failures += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'} {name:16s} -> {report.status_code:3s} (want {want}) "
              f"wall={time.monotonic()-t0:4.1f}s mem={report.memory_mb}MB")

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

    total = len(CASES) + 2
    print(f"\n{total - failures}/{total} passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    asyncio.run(main())
