"""
Adversarial containment, mostly through Seam A (see the compile phase below): untrusted code attempts what a jail must not
allow, against a real executor container under runsc.
    .venv/bin/python -m unittest tests.test_adversarial -v   (needs Docker; see executor_harness)

Kernel surface (seccomp). The probe below tries each syscall and reports how it was
refused, so a refusal the program can handle shows up as an ordinary errno and a
policy kill shows up as Runtime Error "forbidden syscall".

No language runs submitted code at compile time (py_compile, javac and g++ execute
nothing from the source), so the compile-phase cases run the probe in the executor's
own compile jail, inside the same container. Ticket 13's self-test replaces this with
probes reported through `ready`.
"""
import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.executor_harness import ExecutorContainer
from tests.test_executor import CPP_DRIVER, Verdicts, job, python_job

executor = None


def setUpModule():
    global executor
    executor = ExecutorContainer().__enter__()


def tearDownModule():
    executor.__exit__()


# f() returns "check=outcome ..." where outcome is "ok" or the errno's name.
PROBE = r'''
import ctypes, errno, os, threading
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
buf = ctypes.create_string_buffer(64)
PTR = ctypes.addressof(buf)

def call(nr, *args):
    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_ulong(a) for a in args])
    return 'ok' if r >= 0 else errno.errorcode[ctypes.get_errno()]

def spawn(nr, *args):   # fork-like: the child, if any, leaves at once
    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_ulong(a) for a in args])
    if r == 0:
        os._exit(0)
    if r > 0:
        os.waitpid(r, 0)
        return 'ok'
    return errno.errorcode[ctypes.get_errno()]

def os_fork():
    try:
        pid = os.fork()
    except OSError as e:
        return errno.errorcode[e.errno]
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
    return 'ok'

def thread():
    t = threading.Thread(target=lambda: None)
    t.start()
    t.join()
    return 'ok'

SIGCHLD, CLONE_NEWUSER = 17, 0x10000000
THREAD_FLAGS = 0x100 | 0x800 | 0x10000   # CLONE_VM | CLONE_SIGHAND | CLONE_THREAD
CHECKS = {
    'thread': thread,
    'os_fork': os_fork,
    'fork': lambda: spawn(57),
    'vfork': lambda: spawn(58),   # only safe while refused: a vfork child returning here corrupts the parent's stack
    'clone': lambda: spawn(56, SIGCHLD, 0, 0, 0, 0),
    'clone_newuser': lambda: spawn(56, SIGCHLD | CLONE_NEWUSER, 0, 0, 0, 0),
    # A thread clone, so only the namespace mask refuses it (the kernel would say EINVAL).
    'clone_thread_newuser': lambda: call(56, THREAD_FLAGS | CLONE_NEWUSER, 0, 0, 0, 0),
    'clone3': lambda: call(435, 0, 0),
    'io_uring_setup': lambda: call(425, 1, 0),
    'socket_inet': lambda: call(41, 2, 1, 0),
    'socket_inet6': lambda: call(41, 10, 1, 0),
    'socket_unix': lambda: call(41, 1, 1, 0),
    'socket_netlink': lambda: call(41, 16, 3, 0),
    'socket_packet': lambda: call(41, 17, 3, 0),
    'socketpair_unix': lambda: call(53, 1, 1, 0, PTR),
    'socketpair_inet': lambda: call(53, 2, 1, 0, PTR),
    'ioctl_fionread': lambda: call(16, 0, 0x541B, PTR),
    'ioctl_fionread_high_bits': lambda: call(16, 0, 0x1_0000541B, PTR),
    'ioctl_tiocsti': lambda: call(16, 0, 0x5412, PTR),
    'prlimit_self': lambda: call(302, 0, 7, 0, PTR),
    'prlimit_other': lambda: call(302, 1, 7, 0, PTR),
    'x32_getpid': lambda: call(0x40000000 | 39),
    'unlisted_mlock': lambda: call(149, PTR, 64),
}

def f(skip=()):
    return ' '.join(f'{name}={check()}' for name, check in CHECKS.items() if name not in skip)
'''

RUN_PHASE = {
    "thread": "ok", "os_fork": "EAGAIN", "fork": "EAGAIN", "vfork": "EAGAIN",
    "clone": "EAGAIN", "clone_newuser": "EAGAIN", "clone_thread_newuser": "EAGAIN", "clone3": "ENOSYS", "io_uring_setup": "ENOSYS",
    "socket_inet": "EACCES", "socket_inet6": "EACCES", "socket_unix": "EACCES",
    "socket_netlink": "EACCES", "socket_packet": "EACCES",
    "socketpair_unix": "EACCES", "socketpair_inet": "EACCES",
    "ioctl_fionread": "ok", "ioctl_fionread_high_bits": "ENOTTY", "ioctl_tiocsti": "ENOTTY",
    "prlimit_self": "ok", "prlimit_other": "EPERM", "x32_getpid": "ENOSYS", "unlisted_mlock": "ENOSYS",
}
# Compilers spawn subprocesses and the rustc jobserver needs an AF_UNIX pair; nothing else changes.
# The probe can't test vfork where it is allowed (see PROBE).
COMPILE_PHASE = {**RUN_PHASE, "os_fork": "ok", "fork": "ok", "clone": "ok", "socketpair_unix": "ok"}
del COMPILE_PHASE["vfork"]

# Killed outright in both phases: (name, syscall number, args).
FORBIDDEN = [
    ("ptrace", 101, (0,)),               # PTRACE_TRACEME
    ("unshare", 272, (0x10000000,)),     # CLONE_NEWUSER
    ("mount", 165, (0, 0, 0, 0, 0)),
    ("chroot", 161, (0,)),
    ("bpf", 321, (0, 0, 0)),
    ("keyctl", 250, (0,)),
]


def forbidden_call(nr, args):
    return (f"import ctypes\ndef f():\n    ctypes.CDLL(None).syscall({nr}, "
            + "".join(f"ctypes.c_ulong({a}), " for a in args) + ")\n    return 42\n")


def outcomes(line):
    return dict(token.split("=", 1) for token in line.split())


def compile_phase(code):
    """Run `python3 -c code` in the executor's compile jail; the sandbox's result as a dict."""
    script = (
        "import asyncio, json, sys, tempfile\n"
        "from config import load_config\nfrom sandbox import NsjailSandbox\n"
        "sandbox = NsjailSandbox(load_config(None).sandbox, 65536)\n"
        "r = asyncio.run(sandbox.compile(['/usr/bin/python3', '-c', sys.argv[1]],"
        " tempfile.mkdtemp(), time_limit_ms=10000, memory_limit=256))\n"
        "print(json.dumps({'stdout': r.stdout, 'stderr': r.stderr, 'signal': r.signal,"
        " 'exit_code': r.exit_code, 'setup_failed': r.setup_failed}))\n")
    out = subprocess.run(["docker", "exec", "-w", "/opt/executor", executor.container,
                          "python3", "-c", script, code],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out.splitlines()[-1])


class TestRunPhaseSyscalls(Verdicts):
    def test_refused_syscalls_fail_with_an_ordinary_error(self):
        # fork fails with EAGAIN and the program goes on to report it; it is not killed.
        report = self.verdict(executor.run_job(**python_job(PROBE, task="RUN_CODE", test_cases=[{"input": "", "expectedOutput": ""}])), "ACC")
        self.assertEqual(outcomes(report["test_results"][0]["actual_output"]), RUN_PHASE)

    def test_fork_fails_in_a_compiled_program(self):
        solution = ("#include <unistd.h>\n#include <cerrno>\n"
                    "int f() { pid_t p = fork(); if (p == 0) _exit(0); return p < 0 && errno == EAGAIN ? 42 : 0; }\n")
        self.verdict(executor.run_job(**job("cpp", solution, CPP_DRIVER)), "ACC")

    def test_dangerous_syscalls_are_forbidden(self):
        for name, nr, args in FORBIDDEN:
            with self.subTest(syscall=name):
                report = self.verdict(executor.run_job(**python_job(forbidden_call(nr, args))), "RE")
                self.assertIn("forbidden syscall", report["runtime_error"])


class TestCompilePhaseSyscalls(unittest.TestCase):
    def test_refused_syscalls_fail_with_an_ordinary_error(self):
        result = compile_phase(PROBE + "print(f(skip={'vfork'}))\n")
        self.assertEqual(result["exit_code"], 0, result)
        self.assertEqual(outcomes(result["stdout"].strip().splitlines()[-1]), COMPILE_PHASE)

    def test_dangerous_syscalls_are_forbidden(self):
        for name, nr, args in FORBIDDEN:
            with self.subTest(syscall=name):
                result = compile_phase(forbidden_call(nr, args) + "f()\n")
                self.assertFalse(result["setup_failed"], result)
                self.assertEqual(result["signal"], 31, result)   # SIGSYS


if __name__ == "__main__":
    unittest.main()
