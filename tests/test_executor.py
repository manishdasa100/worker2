"""
Seam A: jobs judged by a real executor container under runsc.
    .venv/bin/python -m unittest tests.test_executor -v   (needs Docker; see executor_harness)
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.executor_harness import ExecutorContainer

ADD = "def add(a,b):\n    return a+b\n"
ADD_DRIVER = "from solution import add\na,b=map(int,input().split())\nprint(add(a,b))\n"
F_DRIVER = "from solution import f\nprint(f())\n"
CASES = [{"input": "3 4", "expectedOutput": "7"}, {"input": "10 -2", "expectedOutput": "8"}]
# Today's report shape: the backend parses exactly these fields.
REPORT_FIELDS = {"execution_id", "language", "task", "status_code", "status_msg", "total_testcases",
                 "total_correct", "runtime_ms", "memory_mb", "test_results", "failed_testcase",
                 "compile_error", "runtime_error", "internal_error", "calibration", "created_at"}
OUTPUT_CAP = 262144     # MAX_OUTPUT_BYTES default
# CPU an empty jail costs before the program's own clock starts (nsjail, runtime
# startup under systrap). Ticket 13 subtracts it; until then tests allow for it.
JAIL_CPU_OVERHEAD_MS = 500

executor = None


def setUpModule():
    global executor
    executor = ExecutorContainer().__enter__()


def tearDownModule():
    executor.__exit__()


def job(language, user_code, driver_code, task="SUBMIT_CODE", time_limit=1000,
        memory_limit=64, test_cases=({"input": "", "expectedOutput": "42"},), **extra):
    return dict(job_id=f"seam-a-{os.urandom(4).hex()}", language=language, user_code=user_code,
                driver_code=driver_code, task=task, time_limit=time_limit,
                memory_limit=memory_limit, test_cases=list(test_cases), **extra)


def python_job(user_code, driver_code=F_DRIVER, **kw):
    return job("python", user_code, driver_code, **kw)


CPP_DRIVER = '#include <iostream>\n#include "solution.cpp"\nint main(){ std::cout << f() << std::endl; }\n'
JAVA_DRIVER = "public class Main { public static void main(String[] a){ System.out.println(Solution.f()); } }\n"


def java_solution(body):
    return "public class Solution { static int f() { " + body + " } }\n"


# Per language: its driver and one solution per verdict. "MLE-cgroup" is killed by the
# executor's memory watch, so stderr carries no runtime marker; "MLE-runtime" is the
# runtime's own out-of-memory error, so it does.
MATRIX = {
    "python": (F_DRIVER, {
        "ACC": "def f():\n    return 42\n",
        "WA": "def f():\n    return 41\n",
        "TLE": "def f():\n    while True: pass\n",
        "MLE-cgroup": "def f():\n    x = ' ' * (200 << 20)\n    return 42 if x else 0\n",
        "MLE-runtime": "def f():\n    x = 'x' * 10**12\n    return 42\n",
        "RE": "def f():\n    raise ValueError('boom')\n",
        "CE": "def f(:\n    return 42\n",
    }),
    "cpp": (CPP_DRIVER, {
        "ACC": "int f() { return 42; }\n",
        "WA": "int f() { return 41; }\n",
        "TLE": "int f() { volatile long i = 0; while (true) i++; }\n",
        "MLE-cgroup": "#include <vector>\nint f() { std::vector<char> v(200 << 20, 1);"
                      " volatile char* p = v.data(); return p[100 << 20] + 41; }\n",
        "MLE-runtime": "#include <cstddef>\nint f() { volatile std::size_t n = 1ULL << 40;"
                       " volatile char* p = new char[n]; p[0] = 1; return 42; }\n",
        "RE": "int f() { volatile int* p = nullptr; *p = 1; return 42; }\n",
        "CE": "int f( { return 42; }\n",
    }),
    "java": (JAVA_DRIVER, {
        "ACC": java_solution("return 42;"),
        "WA": java_solution("return 41;"),
        "TLE": java_solution("while (true) {}"),
        "MLE-cgroup": java_solution("java.util.List<byte[]> l = new java.util.ArrayList<>();"
                                    " for (int i = 0; i < 1000; i++) l.add(new byte[1 << 20]);"
                                    " return l.size() > 0 ? 42 : 0;"),
        "MLE-runtime": java_solution("long[] a = new long[Integer.MAX_VALUE - 8]; return a.length > 0 ? 42 : 0;"),
        "RE": java_solution("throw new RuntimeException(\"boom\");"),
        "CE": java_solution("return 42"),
    }),
}
OOM_MARKERS = {"python": "MemoryError", "cpp": "std::bad_alloc", "java": "java.lang.OutOfMemoryError"}


class Verdicts(unittest.TestCase):
    def verdict(self, response, want):
        self.assertEqual(response["status"], "COMPLETED", response)
        report = response["report"]
        self.assertEqual(set(report), REPORT_FIELDS)        # today's report shape
        self.assertEqual(report["status_code"], want, report)
        return report


class TestVerdictMatrix(Verdicts):
    def test_every_verdict_in_every_language(self):
        for language, (driver, solutions) in MATRIX.items():
            for case, solution in solutions.items():
                with self.subTest(language=language, case=case):
                    report = self.verdict(executor.run_job(**job(language, solution, driver)),
                                          case.split("-")[0])
                    stderr = (report["failed_testcase"] or {}).get("stderr") or ""
                    if case == "MLE-runtime":
                        self.assertIn(OOM_MARKERS[language], stderr)
                    if case == "MLE-cgroup":
                        self.assertNotIn(OOM_MARKERS[language], stderr)
                    if case == "CE":
                        self.assertTrue(report["compile_error"])


class TestCpp(Verdicts):
    def test_driver_including_the_solution_links_without_duplicate_symbols(self):
        # Compiling solution.cpp on its own as well would define f and counter twice.
        solution = "int counter = 41;\nint f() { return counter + 1; }\n"
        self.verdict(executor.run_job(**job("cpp", solution, CPP_DRIVER)), "ACC")

    def test_cpp20_features_compile(self):
        solution = ("#include <concepts>\n#include <ranges>\n#include <vector>\n"
                    "template <std::integral T> T twice(T x) { return 2 * x; }\n"
                    "int f() { std::vector<int> v{-1, 20, 1}; int s = 0;\n"
                    "  for (int x : v | std::views::filter([](int x) { return x > 0; })) s += twice(x);\n"
                    "  return s; }\n")
        self.verdict(executor.run_job(**job("cpp", solution, CPP_DRIVER)), "ACC")

    def test_segfault_names_the_signal(self):
        report = self.verdict(executor.run_job(**job("cpp", MATRIX["cpp"][1]["RE"], CPP_DRIVER)), "RE")
        self.assertIn("SIGSEGV", report["runtime_error"])

    def test_forbidden_syscall_is_a_runtime_error(self):
        solution = "#include <sched.h>\nint f() { unshare(0); return 42; }\n"
        report = self.verdict(executor.run_job(**job("cpp", solution, CPP_DRIVER)), "RE")
        self.assertIn("forbidden syscall", report["runtime_error"])

    def test_recursive_dfs_of_depth_100000_fits_a_128_mb_budget(self):
        # ~300 bytes a frame: about 30 MB of stack, far past the usual 8 MB default.
        solution = ("#include <vector>\nstd::vector<std::vector<int>> adj;\n"
                    "int depth(int u, int p) { volatile char frame[256]; frame[0] = 0; int best = 0;\n"
                    "  for (int v : adj[u]) if (v != p) { int d = depth(v, u); if (d > best) best = d; }\n"
                    "  return best + 1 + frame[0]; }\n"
                    "int f() { const int n = 100000; adj.assign(n, {});\n"
                    "  for (int i = 1; i < n; i++) { adj[i - 1].push_back(i); adj[i].push_back(i - 1); }\n"
                    "  return depth(0, -1) == n ? 42 : 0; }\n")
        self.verdict(executor.run_job(**job("cpp", solution, CPP_DRIVER, memory_limit=128)), "ACC")


class TestJava(Verdicts):
    def test_64_mb_of_arrays_fits_a_128_mb_budget(self):
        solution = java_solution("int[][] a = new int[64][];"
                                 " for (int i = 0; i < 64; i++) a[i] = new int[262144]; return 42;")
        self.verdict(executor.run_job(**job("java", solution, JAVA_DRIVER, time_limit=5000,
                                            memory_limit=128)), "ACC")

    def test_cpu_time_of_a_single_threaded_workload_is_not_inflated(self):
        # Allocation-heavy, so a parallel collector would burn CPU on other cores.
        # The driver prints the JVM's uptime (its wall time) before the answer.
        solution = java_solution(
            "long end = System.nanoTime() + 1_500_000_000L, s = 0;"
            " while (System.nanoTime() < end) { java.util.List<Integer> l = new java.util.ArrayList<>();"
            " for (int i = 0; i < 10000; i++) l.add(i); s += l.size(); }"
            " return s > 0 ? 42 : 0;")
        driver = ("public class Main { public static void main(String[] a) { int r = Solution.f();"
                  " System.out.println(\"uptime_ms \" + java.lang.management.ManagementFactory"
                  ".getRuntimeMXBean().getUptime()); System.out.println(r); } }\n")
        report = self.verdict(executor.run_job(**job("java", solution, driver, task="RUN_CODE",
                                                     time_limit=5000, memory_limit=128)), "ACC")
        uptime_ms = int(report["test_results"][0]["std_output"].split()[-1])
        self.assertGreaterEqual(uptime_ms, 1500)
        self.assertLessEqual(report["runtime_ms"], uptime_ms + JAIL_CPU_OVERHEAD_MS, report["runtime_ms"])


class TestPythonVerdicts(Verdicts):
    def test_syntax_error_is_a_compile_error_with_the_interpreters_message(self):
        report = self.verdict(executor.run_job(**python_job("def f(:\n    return 42\n")), "CE")
        self.assertIn("solution.py", report["compile_error"])
        self.assertIn("SyntaxError", report["compile_error"])

    def test_memory_marker_after_a_lot_of_stderr_is_still_memory_limit_exceeded(self):
        # stderr keeps its tail, where the marker is.
        self.verdict(executor.run_job(**python_job(
            "import sys\ndef f():\n    sys.stderr.write('e' * 300000 + '\\n')\n    x = 'x' * (10**12)\n"
            "    return 42\n")), "MLE")

    def test_time_limit_keeps_partial_output(self):
        report = self.verdict(executor.run_job(**python_job(
            "def f():\n    print('debug marker 123')\n    while True: pass\n")), "TLE")
        self.assertIn("debug marker 123", report["failed_testcase"]["std_output"])

    def test_submit_accepted(self):
        report = self.verdict(executor.run_job(**python_job(ADD, ADD_DRIVER, test_cases=CASES)), "ACC")
        self.assertEqual((report["total_correct"], report["total_testcases"]), (2, 2))

    def test_run_code_reports_every_test_case(self):
        cases = [CASES[0], {"input": "1 1", "expectedOutput": "3"}]
        report = self.verdict(executor.run_job(**python_job(ADD, ADD_DRIVER, task="RUN_CODE",
                                                            test_cases=cases)), "WA")
        self.assertEqual([t["status"] for t in report["test_results"]], ["PASSED", "FAILED"])
        self.assertEqual(report["test_results"][1]["actual_output"], "2")

    def test_wrong_answer_stops_submit(self):
        report = self.verdict(executor.run_job(**python_job(
            "def add(a,b):\n    return a-b\n", ADD_DRIVER, test_cases=CASES)), "WA")
        self.assertEqual(report["failed_testcase"]["index"], 0)

    def test_exit_255_is_runtime_error(self):
        report = self.verdict(executor.run_job(**python_job(
            "import sys\ndef f():\n    sys.exit(255)\n")), "RE")
        self.assertIn("exit code 255", report["runtime_error"])

    def test_exit_139_is_an_exit_code_not_a_signal(self):
        report = self.verdict(executor.run_job(**python_job(
            "import sys\ndef f():\n    sys.exit(139)\n")), "RE")
        self.assertIn("exit code 139", report["runtime_error"])

    def test_forbidden_syscall_is_a_runtime_error(self):
        report = self.verdict(executor.run_job(**python_job(
            "import ctypes\ndef f():\n    ctypes.CDLL(None).syscall(165)\n    return 42\n")), "RE")   # mount
        self.assertIn("forbidden syscall", report["runtime_error"])

    def test_cpu_loop_is_time_limit_exceeded(self):
        self.verdict(executor.run_job(**python_job("def f():\n    while True: pass\n")), "TLE")

    def test_cpu_spin_is_killed_soon_after_the_cpu_limit(self):
        # 200 ms budget x Python's 3 = 600 ms enforced, above the ~400 ms an empty jail's
        # startup costs, so the kill lands in the loop. No driver timing: runtime is CPU time.
        report = self.verdict(executor.run_job(**python_job(
            "def f():\n    while True: pass\n", time_limit=200)), "TLE")
        self.assertIn("cpu time", report["failed_testcase"]["error_message"])
        self.assertLessEqual(report["runtime_ms"], 900)   # at most ~300 ms past the limit

    def test_sleeping_is_a_wall_time_limit(self):
        # 333 ms x 3 = 999 ms CPU enforced; wall is killed at 2 x 999 + 1000 ms.
        started = time.monotonic()
        report = self.verdict(executor.run_job(**python_job(
            "import time\ndef f():\n    time.sleep(30)\n", time_limit=333)), "TLE")
        self.assertLess(time.monotonic() - started, 4)
        self.assertIn("wall time", report["failed_testcase"]["error_message"])

    def test_finishing_just_under_the_enforced_cpu_limit_is_accepted(self):
        # 500 ms x 3 = 1500 ms enforced; leave room for interpreter startup.
        self.verdict(executor.run_job(**python_job(
            "import time\ndef f():\n    while time.process_time() < 1.2: pass\n    return 42\n",
            time_limit=500)), "ACC")

    def test_runtime_is_the_drivers_own_timing_when_it_emits_one(self):
        driver = F_DRIVER + "open('/stats/stats.txt', 'a').write('driver_ns 7000000\\n')\n"
        report = self.verdict(executor.run_job(**python_job("def f():\n    return 42\n", driver)), "ACC")
        self.assertEqual(report["runtime_ms"], 7)

    def test_runtime_without_driver_timing_is_cpu_time_not_wall_time(self):
        report = self.verdict(executor.run_job(**python_job(
            "import time\ndef f():\n    time.sleep(2)\n    return 42\n")), "ACC")
        self.assertLess(report["runtime_ms"], 1000)   # startup CPU only; the 2 s sleep isn't counted

    def test_allocating_past_the_limit_is_memory_limit_exceeded(self):
        self.verdict(executor.run_job(**python_job(
            "def f():\n    x = ' ' * (200 * 1024 * 1024)\n    return 42 if x else 0\n",
            memory_limit=128, time_limit=5000)), "MLE")

    def test_stdout_flood_is_output_limit_exceeded_quickly(self):
        started = time.monotonic()
        self.verdict(executor.run_job(**python_job(
            "def f():\n    while True: print('x' * 65536)\n")), "OLE")
        self.assertLess(time.monotonic() - started, 3)   # cut at the cap, not at the time limit

    def test_stdout_just_under_the_cap_is_judged(self):
        self.verdict(executor.run_job(**python_job(
            f"def f():\n    print('x' * {OUTPUT_CAP - 100})\n    return 42\n", time_limit=2000)), "ACC")

    def test_stderr_is_capped_but_not_fatal(self):
        report = self.verdict(executor.run_job(**python_job(
            "import sys\ndef f():\n    for _ in range(64): sys.stderr.write('e' * 65536)\n    sys.exit(3)\n",
            time_limit=2000)), "RE")
        self.assertIn("exit code 3", report["runtime_error"])
        self.assertLessEqual(len(report["failed_testcase"]["stderr"]), OUTPUT_CAP)

    def test_stderr_flood_is_output_limit_exceeded(self):
        self.verdict(executor.run_job(**python_job(
            "import sys\ndef f():\n    while True: sys.stderr.write('e' * 65536)\n")), "OLE")


class TestWorkerFailures(unittest.TestCase):
    def assertWorkerFailure(self, response):
        self.assertEqual(response["status"], "FAILED", response)
        self.assertTrue(response["error"])
        self.assertNotIn("report", response)

    def test_malformed_messages_fail_and_the_executor_keeps_serving(self):
        self.assertWorkerFailure(executor.send(b"not json\n"))
        self.assertWorkerFailure(executor.send(b'{"method": "launch_missiles"}\n'))
        self.assertWorkerFailure(executor.send(b'{"method": "run_job", "job": {"job_id": "x"}}\n'))
        self.assertWorkerFailure(executor.send(b"\n"))
        response = executor.run_job(**python_job(ADD, ADD_DRIVER, test_cases=CASES))
        self.assertEqual(response["report"]["status_code"], "ACC", response)

    def test_too_many_test_cases(self):
        response = executor.run_job(**python_job(ADD, ADD_DRIVER, test_cases=CASES * 26))   # 52 > 50
        self.assertWorkerFailure(response)
        self.assertIn("52", response["error"])

    def test_unsupported_language(self):
        job = python_job(ADD, ADD_DRIVER, test_cases=CASES)
        job["language"] = "cobol"
        response = executor.run_job(**job)
        self.assertWorkerFailure(response)
        self.assertIn("cobol", response["error"])


if __name__ == "__main__":
    unittest.main()
