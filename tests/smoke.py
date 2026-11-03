"""
End-to-end smoke test through the real Judge + sandbox (all three languages,
sandboxed compile + run). Run inside a delegated scope:

    systemd-run --user --scope -p Delegate=yes .venv/bin/python tests/smoke.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cgroups import CgroupDelegation
from config import load_config
from judge import Judge
from models import ExecutionRequest

PY = ("def add(a,b):\n    return a+b\n",
      "from solution import add\na,b=map(int,input().split())\nprint(add(a,b))\n")
CPP = ("int add(int a,int b){return a+b;}\n",
       '#include <iostream>\n#include "solution.cpp"\nint main(){int a,b;std::cin>>a>>b;std::cout<<add(a,b)<<std::endl;}\n')
JAVA = ("public class Solution { static int add(int a,int b){ return a+b; } }\n",
        "import java.util.Scanner;\npublic class Main{public static void main(String[] x){Scanner s=new Scanner(System.in);System.out.println(Solution.add(s.nextInt(),s.nextInt()));}}\n")

CASES = [{"input": "3 4", "expectedOutput": "7"}, {"input": "10 -2", "expectedOutput": "8"}]


async def main():
    config = load_config(env_file=".env.dev")
    delegation = CgroupDelegation.try_setup()
    if delegation is None:
        print("No delegated cgroup subtree — run via systemd-run (see docstring)"); sys.exit(2)
    judge = Judge(config, delegation)
    await judge.warmup()

    failures = 0
    for lang, (sol, drv), mem in [("python", PY, 128), ("cpp", CPP, 128), ("java", JAVA, 128)]:
        report = await judge.judge(ExecutionRequest(
            job_id=f"smoke-{lang}", language=lang, user_code=sol, driver_code=drv,
            task="SUBMIT_CODE", time_limit=2000, memory_limit=mem, test_cases=CASES))
        ok = report.status_code == "ACC" and report.total_correct == 2
        print(f"{lang:7s} status={report.status_code} passed={report.total_correct}/{report.total_testcases} "
              f"runtime={report.runtime_ms}ms mem={report.memory_mb}MB -> {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures += 1
            print(f"    compile_error={report.compile_error!r} internal={report.internal_error!r}")

    # Compile-error path: malformed C++
    report = await judge.judge(ExecutionRequest(
        job_id="smoke-ce", language="cpp", user_code="int add(int a,int b){return a+b", driver_code=CPP[1],
        task="SUBMIT_CODE", time_limit=2000, memory_limit=128, test_cases=CASES))
    ce_ok = report.status_code == "CE"
    print(f"compile-error -> {report.status_code} ({'PASS' if ce_ok else 'FAIL'})")
    failures += 0 if ce_ok else 1

    print(f"\n{'ALL PASS' if not failures else str(failures)+' FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    asyncio.run(main())
