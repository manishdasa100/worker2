"""
Adversarial containment, mostly through Seam A (see the compile phase below): untrusted code attempts what a jail must not
allow, against a real executor container under runsc.
    .venv/bin/python -m unittest tests.test_adversarial -v   (needs Docker; see executor_harness)

Filesystem and identity. A probe lists what the jail can see and tries host files,
/proc, writes, the network, setuid and a disk fill; each outcome is "ok", an errno's
name or a listing. A compile may only fill its own size-capped workspace, and
nothing one job writes survives into the next.

Kernel surface (seccomp). The probe below tries each syscall and reports how it was
refused, so a refusal the program can handle shows up as an ordinary errno and a
policy kill shows up as Runtime Error "forbidden syscall". The same checks run from
Python (ctypes) and from a static C binary making raw syscalls.

No language runs submitted code at compile time (py_compile, javac, gcc, g++ and Go's
compile and link execute nothing they are given), so the compile-phase cases run the probe in the executor's
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
from tests.test_executor import C_DRIVER, CPP_DRIVER, Verdicts, job, python_job

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


# The same checks in C, through raw syscall(2), plus filesystem escapes. A driver
# that prints "check=outcome ..." (outcome "ok", the errno's name or a listing).
C_PROBE = r"""#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char buf[64];
static const char* outcome(long r) {
  static char other[16];
  if (r >= 0) return "ok";
  switch (errno) {
    case EAGAIN: return "EAGAIN"; case ENOSYS: return "ENOSYS"; case EACCES: return "EACCES";
    case ENOTTY: return "ENOTTY"; case EPERM: return "EPERM"; case ENOENT: return "ENOENT";
    case EROFS: return "EROFS"; case EINVAL: return "EINVAL";
  }
  snprintf(other, sizeof other, "E%d", errno);
  return other;
}
static long spawned(long r) {   /* fork-like: the child, if any, leaves at once */
  if (r == 0) _exit(0);
  if (r > 0) waitpid(r, 0, 0);
  return r;
}
static void* noop(void* a) { return a; }
static long thread(void) {
  pthread_t t;
  int e = pthread_create(&t, 0, noop, 0);
  if (e) { errno = e; return -1; }
  return pthread_join(t, 0);
}
static void ls(const char* name, const char* path) {
  char out[256] = "";
  DIR* d = opendir(path);
  struct dirent* e;
  if (!d) { printf("%s=%s ", name, outcome(-1)); return; }
  /* readdir order isn't sorted; the test compares sets of entries */
  while ((e = readdir(d))) if (e->d_name[0] != '.') { strcat(out, out[0] ? "," : ""); strcat(out, e->d_name); }
  closedir(d);
  printf("%s=%s ", name, out[0] ? out : "-");
}
#define CHECK(name, expr) printf("%s=%s ", name, outcome(expr))
#define SIGCHLD_ 17L
#define CLONE_NEWUSER_ 0x10000000L
#define THREAD_FLAGS (0x100L | 0x800L | 0x10000L)
int main(void) {
  CHECK("thread", thread());
  CHECK("os_fork", spawned(fork()));
  CHECK("fork", spawned(syscall(57)));
  CHECK("vfork", spawned(syscall(58)));   /* only safe while refused */
  CHECK("clone", spawned(syscall(56, SIGCHLD_, 0L, 0L, 0L, 0L)));
  CHECK("clone_newuser", spawned(syscall(56, SIGCHLD_ | CLONE_NEWUSER_, 0L, 0L, 0L, 0L)));
  CHECK("clone_thread_newuser", syscall(56, THREAD_FLAGS | CLONE_NEWUSER_, 0L, 0L, 0L, 0L));
  CHECK("clone3", syscall(435, 0L, 0L));
  CHECK("io_uring_setup", syscall(425, 1L, 0L));
  CHECK("socket_inet", syscall(41, 2L, 1L, 0L));
  CHECK("socket_inet6", syscall(41, 10L, 1L, 0L));
  CHECK("socket_unix", syscall(41, 1L, 1L, 0L));
  CHECK("socket_netlink", syscall(41, 16L, 3L, 0L));
  CHECK("socket_packet", syscall(41, 17L, 3L, 0L));
  CHECK("socketpair_unix", syscall(53, 1L, 1L, 0L, buf));
  CHECK("socketpair_inet", syscall(53, 2L, 1L, 0L, buf));
  CHECK("ioctl_fionread", syscall(16, 0L, 0x541BL, buf));
  CHECK("ioctl_fionread_high_bits", syscall(16, 0L, 0x10000541BL, buf));
  CHECK("ioctl_tiocsti", syscall(16, 0L, 0x5412L, buf));
  CHECK("prlimit_self", syscall(302, 0L, 7L, 0L, buf));
  CHECK("prlimit_other", syscall(302, 1L, 7L, 0L, buf));
  CHECK("x32_getpid", syscall(0x40000000L | 39));
  CHECK("unlisted_mlock", syscall(149, buf, 64L));
  CHECK("setuid_root", syscall(105, 0L));
  CHECK("proc_environ", syscall(257, AT_FDCWD, "/proc/self/environ", (long)O_RDONLY));
  CHECK("proc_1_root", syscall(257, AT_FDCWD, "/proc/1/root/etc/hostname", (long)O_RDONLY));
  CHECK("shadow", syscall(257, AT_FDCWD, "/etc/shadow", (long)O_RDONLY));
  CHECK("executor_source", syscall(257, AT_FDCWD, "/code/../opt/executor/config.py", (long)O_RDONLY));
  CHECK("write_root", syscall(257, AT_FDCWD, "/pwned", (long)(O_WRONLY | O_CREAT), 0644L));
  CHECK("write_code", syscall(257, AT_FDCWD, "/code/pwned", (long)(O_WRONLY | O_CREAT), 0644L));
  CHECK("write_dev", syscall(257, AT_FDCWD, "/dev/pwned", (long)(O_WRONLY | O_CREAT), 0644L));
  ls("root", "/");
  ls("dev", "/dev");
  ls("proc", "/proc");
  ls("sys", "/sys");
  printf("\n");
  return 0;
}
"""
C_RUN_PHASE = {**RUN_PHASE, "setuid_root": "ENOSYS", "proc_environ": "ENOENT", "proc_1_root": "ENOENT",
               "shadow": "ENOENT", "executor_source": "ENOENT", "write_root": "EROFS",
               "write_code": "EROFS", "write_dev": "EROFS", "root": "code,dev,etc,stats,tmp",
               "dev": "null,urandom,zero", "proc": "ENOENT", "sys": "ENOENT"}


def c_forbidden_call(nr, args):
    return ("#include <unistd.h>\n#include <sys/syscall.h>\n"
            f"int f(void) {{ syscall({nr}" + "".join(f", {a}L" for a in args) + "); return 42; }\n")


def forbidden_call(nr, args):
    return (f"import ctypes\ndef f():\n    ctypes.CDLL(None).syscall({nr}, "
            + "".join(f"ctypes.c_ulong({a}), " for a in args) + ")\n    return 42\n")


def outcomes(line):
    return dict(token.split("=", 1) for token in line.split())


def compile_phase(code):
    """
    Run `python3 -c code` in the executor's compile jail, with Python's toolchain and
    the default compile memory limit; the sandbox's result as a dict.
    """
    script = (
        "import asyncio, json, sys\n"
        "from config import load_config\nfrom languages import get_language\nfrom sandbox import NsjailSandbox, workspace\n"
        "sandbox = NsjailSandbox(load_config(None).sandbox, 65536)\n"
        "async def main():\n"
        "    with workspace() as code_dir:\n"
        "        return await sandbox.compile(['/usr/bin/python3', '-c', sys.argv[1]], code_dir,"
        " get_language('python').compile_toolchain, time_limit_ms=10000, memory_limit=load_config(None).execution.compile_memory_limit)\n"
        "r = asyncio.run(main())\n"
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


class TestRunPhaseInC(Verdicts):
    """Raw syscalls from a static C binary: the likeliest escape attempts."""

    def test_raw_syscalls_are_refused_and_the_host_is_out_of_reach(self):
        report = self.verdict(executor.run_job(**job(
            "c", "", C_PROBE, task="RUN_CODE", test_cases=[{"input": "", "expectedOutput": ""}])), "ACC")
        seen = outcomes(report["test_results"][0]["actual_output"])
        self.assertEqual({k: ",".join(sorted(v.split(","))) for k, v in seen.items()}, C_RUN_PHASE)

    def test_dangerous_syscalls_are_forbidden(self):
        for name, nr, args in FORBIDDEN:
            with self.subTest(syscall=name):
                report = self.verdict(executor.run_job(**job("c", c_forbidden_call(nr, args), C_DRIVER)), "RE")
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


# f() returns "check=outcome ...": "ok", the errno's (or exception's) name, or a listing.
FS_PROBE = r"""
import errno, os, pwd, socket

def attempt(action):
    try:
        action()
        return 'ok'
    except OSError as e:
        return errno.errorcode.get(e.errno, type(e).__name__)

def ls(path):
    try:
        return ','.join(sorted(os.listdir(path))) or '-'
    except OSError as e:
        return errno.errorcode[e.errno]

def write(path, size=1):
    def action():
        with open(path, 'wb') as fh:
            for _ in range(size):
                fh.write(b'x' * (1 << 20))
    return attempt(action)

def connect():
    with socket.create_connection(('8.8.8.8', 53), timeout=3):
        pass

CHECKS = {
    'root': lambda: ls('/'),
    'usr': lambda: ls('/usr'),
    'dev': lambda: ls('/dev'),
    'etc': lambda: ls('/etc'),
    'me': lambda: pwd.getpwuid(os.getuid()).pw_name,
    'users': lambda: ','.join(sorted(p.pw_name for p in pwd.getpwall())),
    'env': lambda: ','.join(sorted(os.environ)),
    'proc': lambda: ls('/proc'),
    'proc_environ': lambda: attempt(lambda: open('/proc/self/environ').read()),
    'proc_1_root': lambda: attempt(lambda: open('/proc/1/root/etc/hostname').read()),
    'sys': lambda: ls('/sys'),
    'shadow': lambda: attempt(lambda: open('/etc/shadow').read()),
    'executor_source': lambda: attempt(lambda: open('/code/../opt/executor/config.py').read()),
    'write_code': lambda: write('/code/pwned'),
    'write_root': lambda: write('/pwned'),
    'write_dev': lambda: write('/dev/pwned'),
    'dev_null': lambda: write('/dev/null'),
    'tmp_4gb_file': lambda: write('/tmp/big', 4096),
    'setuid_root': lambda: attempt(lambda: os.setuid(0)),
    'connect': lambda: attempt(connect),
    'dns': lambda: attempt(lambda: socket.gethostbyname('example.com')),
}

def f():
    return ' '.join(f'{name}={check()}' for name, check in CHECKS.items())
"""

# What any jail sees: its workspace, a fake /etc and three devices. A job owns its /code
# only in the compile phase; in the run phase it is read-only, as is everything but /tmp.
JAIL_FS = {
    "dev": "null,urandom,zero", "etc": "group,passwd", "me": "jail", "users": "jail,root",
    "env": "HOME,LANG,PATH,TMPDIR", "proc": "ENOENT", "proc_environ": "ENOENT",
    "proc_1_root": "ENOENT", "sys": "ENOENT", "shadow": "ENOENT", "executor_source": "ENOENT",
    "write_root": "EROFS", "write_dev": "EROFS", "dev_null": "ok", "setuid_root": "ENOSYS",
    "connect": "EACCES", "dns": "gaierror",
}
# Python sees only its interpreter, its standard library and the shared libraries.
PYTHON_RUN_FS = {**JAIL_FS, "root": "code,dev,etc,lib64,stats,tmp,usr", "usr": "bin,lib",
                 "write_code": "EROFS", "tmp_4gb_file": "EFBIG"}

LS_DRIVER = r"""#include <dirent.h>
#include <iostream>
#include <set>
#include <string>
std::string ls(const char* path) {
  DIR* d = opendir(path);
  if (!d) return "-";
  std::set<std::string> names;
  while (dirent* e = readdir(d)) if (e->d_name[0] != '.') names.insert(e->d_name);
  closedir(d);
  std::string out;
  for (const auto& n : names) out += (out.empty() ? "" : ",") + n;
  return out;
}
int main() { std::cout << "root=" << ls("/") << " dev=" << ls("/dev") << " etc=" << ls("/etc")
                       << " usr=" << ls("/usr") << " proc=" << ls("/proc") << std::endl; }
"""

# Lists the workspace and /tmp, then leaves a file in /tmp for whoever runs next.
LEFTOVERS = """import os
def f():
    seen = ls('/code') + ' ' + ls('/tmp')
    open('/tmp/leftover', 'w').close()
    return seen

def ls(path):
    return ','.join(sorted(os.listdir(path))) or '-'
"""


def run_code(job_kwargs):
    """The answer line of each test case of a RUN_CODE job."""
    response = executor.run_job(**job_kwargs)
    report = response["report"]
    return [tc["actual_output"] for tc in report["test_results"]]


class TestRunPhaseFilesystem(Verdicts):
    def test_python_sees_only_its_toolchain_and_cannot_reach_the_host(self):
        report = self.verdict(executor.run_job(**python_job(
            FS_PROBE, task="RUN_CODE", time_limit=3000,
            test_cases=[{"input": "", "expectedOutput": ""}])), "ACC")
        self.assertEqual(outcomes(report["test_results"][0]["actual_output"]), PYTHON_RUN_FS)

    def test_a_static_binary_runs_with_nothing_but_its_workspace(self):
        report = self.verdict(executor.run_job(**job(
            "cpp", "", LS_DRIVER, task="RUN_CODE", test_cases=[{"input": "", "expectedOutput": ""}])), "ACC")
        self.assertEqual(outcomes(report["test_results"][0]["actual_output"]),
                         {"root": "code,dev,etc,stats,tmp", "dev": "null,urandom,zero",
                          "etc": "group,passwd", "usr": "-", "proc": "-"})

    def test_filling_tmp_with_many_files_is_memory_limit_exceeded(self):
        # Each file stays under the file-size limit; the jail's /tmp counts against its memory.
        solution = ("def f():\n    for i in range(64):\n"
                    "        with open(f'/tmp/fill{i}', 'wb') as fh: fh.write(b'x' * (32 << 20))\n"
                    "    return 42\n")
        self.verdict(executor.run_job(**python_job(solution, time_limit=5000, memory_limit=128)), "MLE")

    def test_fork_bomb_is_contained_and_the_executor_keeps_serving(self):
        solution = ("import os, time\ndef f():\n    n = 0\n    try:\n"
                    "        for _ in range(500):\n"
                    "            if os.fork() == 0:\n                time.sleep(30)\n                os._exit(0)\n"
                    "            n += 1\n    except OSError:\n        pass\n    return 42 if n == 0 else n\n")
        self.verdict(executor.run_job(**python_job(solution)), "ACC")
        self.verdict(executor.run_job(**python_job("def f():\n    return 42\n")), "ACC")


class TestCompilePhaseFilesystem(Verdicts):
    def test_compile_jail_sees_only_the_toolchain_and_a_writable_workspace(self):
        result = compile_phase(FS_PROBE + "print(f())\n")
        self.assertEqual(result["exit_code"], 0, result)
        seen = outcomes(result["stdout"].strip().splitlines()[-1])
        self.assertEqual(seen, {**JAIL_FS, "root": "code,dev,etc,lib64,tmp,usr", "usr": "bin,lib",
                                "write_code": "ok", "tmp_4gb_file": "EFBIG"})

    def test_host_files_cannot_be_included_at_compile_time(self):
        for language, driver in (("cpp", CPP_DRIVER), ("c", C_DRIVER)):
            for path in ("/etc/shadow", "/opt/executor/config.py", "/proc/self/environ"):
                with self.subTest(language=language, path=path):
                    report = self.verdict(executor.run_job(**job(
                        language, f'#include "{path}"\nint f() {{ return 42; }}\n', driver)), "CE")
                    self.assertIn("No such file or directory", report["compile_error"])

    def test_a_compile_that_overflows_its_workspace_is_a_compile_error(self):
        # A 100 MB initialised array: the linker's output can't fit the workspace.
        driver = "char big[100 << 20] = {1};\nint main() { return big[12345]; }\n"
        report = self.verdict(executor.run_job(**job("cpp", "", driver)), "CE")
        self.assertIn("No space left on device", report["compile_error"])


class TestNothingSurvivesAJob(unittest.TestCase):
    def test_the_next_job_sees_a_fresh_workspace_and_tmp(self):
        executor.run_job(**job("cpp", "int f() { return 42; }\n", CPP_DRIVER))   # leaves main in its workspace
        cases = [{"input": "", "expectedOutput": ""}] * 2
        first = run_code(python_job(LEFTOVERS, task="RUN_CODE", test_cases=cases))
        second = run_code(python_job(LEFTOVERS, task="RUN_CODE", test_cases=cases))
        self.assertEqual(first + second, ["__pycache__,main.py,solution.py -"] * 4)


if __name__ == "__main__":
    unittest.main()
