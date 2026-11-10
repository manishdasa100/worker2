"""
Adversarial sandbox-strength suite.

Each probe is untrusted code that ATTEMPTS something it should not be able to
do; the test asserts the sandbox CONTAINED it. "Contained" means one of:
  * the action raised / was denied and the probe printed  BLOCKED:...   (answer line)
  * the process was killed by seccomp/limits -> verdict RE/TLE/MLE (no leak)
A probe that prints  OPEN:<data>  (the sensitive action succeeded) FAILS the test.

Parked: the judge now runs only inside an executor container (cgroups.py), so
this in-process script no longer runs as is. Ticket 09 moves it onto Seam A
(tests/executor_harness.py).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cgroups
from config import load_config
from judge import Judge
from models import ExecutionRequest

# Python driver: call solution.f() (returns a status string) and print it as the answer.
PY_DRV = "from solution import f\nprint(f())\n"

# Each probe's f() tries the action and returns 'OPEN:...' on success (BAD) or
# 'BLOCKED:...' on denial (GOOD).
PROBES = {
    # ---- filesystem confinement ----
    "fs-read-passwd": """
def f():
    try:
        return 'OPEN:' + open('/etc/passwd').read()[:40]
    except Exception as e:
        return 'BLOCKED:' + type(e).__name__
""",
    "fs-read-shadow": """
def f():
    try:
        return 'OPEN:' + open('/etc/shadow').read()[:40]
    except Exception as e:
        return 'BLOCKED:' + type(e).__name__
""",
    "fs-write-code": """
def f():
    try:
        open('/code/pwned','w').write('x'); return 'OPEN:wrote /code'
    except Exception as e:
        return 'BLOCKED:' + type(e).__name__
""",
    "fs-write-root": """
def f():
    try:
        open('/pwned','w').write('x'); return 'OPEN:wrote /'
    except Exception as e:
        return 'BLOCKED:' + type(e).__name__
""",
    "fs-escape-dotdot": """
def f():
    try:
        return 'OPEN:' + open('/code/../../../../etc/passwd').read()[:40]
    except Exception as e:
        return 'BLOCKED:' + type(e).__name__
""",
    "fs-proc-root-escape": """
def f():
    try:
        return 'OPEN:' + open('/proc/1/root/etc/passwd').read()[:40]
    except Exception as e:
        return 'BLOCKED:' + type(e).__name__
""",
    # ---- worker-secret / host-info leakage ----
    "env-leak-secrets": """
import os
def f():
    leaked = [k for k in os.environ if 'REDIS' in k.upper() or 'PASS' in k.upper() or 'AWS' in k.upper()]
    vals = ' '.join('%s=%s' % (k, os.environ[k]) for k in leaked)
    return ('OPEN:' + vals) if leaked else 'BLOCKED:env-clean(%d vars)' % len(os.environ)
""",
    "proc-environ-leak": """
def f():
    try:
        data = open('/proc/self/environ','rb').read().decode('latin1')
        return ('OPEN:' + data[:60]) if ('REDIS' in data or 'PASS' in data.upper()) else 'BLOCKED:no-secret-in-environ'
    except Exception as e:
        return 'BLOCKED:' + type(e).__name__
""",
    # ---- network isolation (empty net namespace) ----
    "net-connect-out": """
import socket
def f():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
        s.connect(('8.8.8.8', 53)); return 'OPEN:connected'
    except Exception as e:
        return 'BLOCKED:' + type(e).__name__
""",
    "net-dns": """
import socket
def f():
    try:
        return 'OPEN:' + socket.gethostbyname('example.com')
    except Exception as e:
        return 'BLOCKED:' + type(e).__name__
""",
    # ---- privilege ----
    "priv-setuid-root": """
import os
def f():
    try:
        os.setuid(0); return 'OPEN:uid=%d' % os.getuid()
    except Exception as e:
        return 'BLOCKED:' + type(e).__name__
""",
    # ---- resource: output / disk ----
    "disk-fill-tmp": """
def f():
    try:
        with open('/tmp/big','wb') as fh:
            chunk = b'x'*(1024*1024)
            for _ in range(4096): fh.write(chunk)   # try to write 4 GB
        import os; return 'OPEN:wrote %d bytes' % os.path.getsize('/tmp/big')
    except Exception as e:
        return 'BLOCKED:' + type(e).__name__
""",
}

# Probes judged by verdict, not answer line:
#   seccomp default-deny: call an unlisted-but-harmless syscall (getcpu, nr 309)
#   via ctypes -> KILL_PROCESS -> verdict RE. Proves the allow-list denies by default.
SECCOMP_KILL = """
import ctypes
def f():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall(309)          # getcpu: read-only, harmless, NOT in the allow-list
    return 'OPEN:survived-unlisted-syscall'
"""

# Fork-bomb containment: bounded spawn; pids.max must cap it and the worker must
# survive (a later job still runs).
FORK_BOMB = """
import os
def f():
    n = 0
    try:
        for _ in range(500):
            if os.fork() == 0:
                import time; time.sleep(30); os._exit(0)
            n += 1
    except Exception as e:
        return 'BLOCKED:capped_at_%d:%s' % (n, type(e).__name__)
    return 'OPEN:forked_%d' % n
"""


async def run(judge, name, code, task="SUBMIT_CODE", tl=3000, ml=128):
    return await judge.judge(ExecutionRequest(
        job_id=f"sec-{name}", language="python", user_code=code, driver_code=PY_DRV,
        task=task, time_limit=tl, memory_limit=ml, test_cases=[{"input": "", "expectedOutput": "__never__"}]))


def answer_line(report):
    tc = report.failed_testcase or (report.test_results[0] if report.test_results else None)
    if tc is None:
        return ""
    return (tc.actual_output or "") + (tc.std_output or "")


async def main():
    config = load_config(env_file=".env.dev")
    cgroups.require()
    judge = Judge(config)
    await judge.warmup()

    passed = failed = 0

    def check(name, contained, detail):
        nonlocal passed, failed
        if contained:
            passed += 1; print(f"CONTAINED {name:22s} {detail}")
        else:
            failed += 1; print(f"LEAK!!!   {name:22s} {detail}")

    # Answer-line probes: contained iff the probe did NOT print OPEN:
    for name, code in PROBES.items():
        report = await run(judge, name, code)
        ans = answer_line(report)
        leaked = "OPEN:" in ans
        check(name, not leaked, f"[{report.status_code}] {ans.strip()[:70]}")

    # seccomp default-deny: calling an unlisted syscall must kill the process (RE),
    # and must NOT print the 'survived' sentinel.
    report = await run(judge, "seccomp-default-deny", SECCOMP_KILL)
    ans = answer_line(report)
    killed = report.status_code in ("RE", "IE") and "survived" not in ans
    check("seccomp-default-deny", killed, f"[{report.status_code}] {ans.strip()[:60]}")

    # compile-time file read (the worker1 hole): a C++ source that #includes a
    # host file must FAIL to compile (CE) WITHOUT the file's contents leaking
    # into the compiler diagnostics.
    cpp_leak = '#include "/etc/passwd"\nint f(){return 0;}\n'
    cpp_drv = '#include <iostream>\n#include "solution.cpp"\nint main(){ std::cout << f() << std::endl; }\n'
    report = await judge.judge(ExecutionRequest(
        job_id="sec-compile-leak", language="cpp", user_code=cpp_leak, driver_code=cpp_drv,
        task="SUBMIT_CODE", time_limit=3000, memory_limit=128,
        test_cases=[{"input": "", "expectedOutput": "0"}]))
    err = report.compile_error or ""
    # Contained iff it's a compile error AND no /etc/passwd CONTENT (e.g. root:x:0:0) leaked.
    leak_contained = report.status_code == "CE" and "root:" not in err and ":0:0:" not in err
    check("compile-time-file-read", leak_contained, f"[{report.status_code}] {err.strip().splitlines()[0][:60] if err else ''}")

    # fork bomb: must be capped (not 'forked_500') and worker survives afterward.
    report = await run(judge, "fork-bomb", FORK_BOMB, tl=3000)
    ans = answer_line(report)
    bomb_contained = "forked_500" not in ans and report.status_code in ("RE", "TLE", "WA", "ACC")
    # worker still alive?
    after = await run(judge, "post-forkbomb", "def f():\n    return 'alive'\n")
    alive = "alive" in answer_line(after)
    check("fork-bomb", bomb_contained and alive, f"[{report.status_code}] {ans.strip()[:50]} | worker_alive={alive}")

    total = passed + failed
    print(f"\n{passed}/{total} contained" + ("" if not failed else f"  ** {failed} LEAK(S) **"))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
