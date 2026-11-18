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
# CPU a runtime burns before its own clock starts (JVM startup under systrap). The
# self-test takes an empty jail's share off every reading; the runtime's stays.
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


C_DRIVER = '#include <stdio.h>\n#include "solution.c"\nint main(void) { printf("%d\\n", f()); return 0; }\n'
GO_DRIVER = 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println(f()) }\n'
JS_DRIVER = "const { f } = require('./solution');\nconsole.log(f());\n"
RUST_DRIVER = 'mod solution;\n\nfn main() {\n    println!("{}", solution::f());\n}\n'


def java_solution(body):
    return "public class Solution { static int f() { " + body + " } }\n"


def go_solution(body):
    return "package main\n\nfunc f() int {\n" + body + "\n}\n"


def js_solution(body):
    return "function f() {\n" + body + "\n}\nmodule.exports = { f };\n"


def rust_solution(body):
    return "pub fn f() -> i32 {\n" + body + "\n}\n"


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
    # C has no runtime out-of-memory message (malloc just returns NULL), so no MLE-runtime.
    "c": (C_DRIVER, {
        "ACC": "int f(void) { return 42; }\n",
        "WA": "int f(void) { return 41; }\n",
        "TLE": "int f(void) { volatile long i = 0; for (;;) i++; }\n",
        "MLE-cgroup": "#include <stdlib.h>\n#include <string.h>\n"
                      "int f(void) { char* p = malloc(200 << 20); memset(p, 1, 200 << 20);"
                      " return ((volatile char*)p)[100 << 20] + 41; }\n",
        "RE": "int f(void) { volatile int* p = 0; *p = 1; return 42; }\n",
        "CE": "int f( { return 42; }\n",
    }),
    "go": (GO_DRIVER, {
        "ACC": go_solution("return 42"),
        "WA": go_solution("return 41"),
        "TLE": go_solution("for {\n}"),
        "MLE-cgroup": go_solution("b := make([]byte, 200<<20)\nfor i := range b {\nb[i] = 1\n}\nreturn int(b[100<<20]) + 41"),
        "MLE-runtime": go_solution("b := make([]byte, 1<<40)\nb[0] = 1\nreturn 42"),
        "RE": go_solution('panic("boom")'),
        "CE": go_solution("return 42 +"),
    }),
    # Node's heap is as large as the limit, so the memory watch kills a heap blow-up
    # before V8 reports it: no MLE-runtime.
    "javascript": (JS_DRIVER, {
        "ACC": js_solution("return 42;"),
        "WA": js_solution("return 41;"),
        "TLE": js_solution("for (;;) {}"),
        # Buffers live outside the JavaScript heap, so this is the cgroup's limit, not V8's.
        "MLE-cgroup": js_solution("const a = []; for (let i = 0; i < 200; i++) a.push(Buffer.alloc(1 << 20, 1));"
                                  " return a.length > 0 ? 42 : 0;"),
        "RE": js_solution("throw new Error('boom');"),
        "CE": js_solution("return 42 +;"),
    }),
    "rust": (RUST_DRIVER, {
        "ACC": rust_solution("42"),
        "WA": rust_solution("41"),
        "TLE": rust_solution("loop {\n    std::hint::black_box(0);\n}"),
        "MLE-cgroup": rust_solution("let v = vec![1u8; 200 << 20];\nstd::hint::black_box(&v);\nv[100 << 20] as i32 + 41"),
        "MLE-runtime": rust_solution("let v: Vec<u8> = Vec::with_capacity(1 << 40);\nstd::hint::black_box(&v);\n42"),
        "RE": rust_solution('panic!("boom")'),
        "CE": rust_solution("42 +"),
    }),
}
OOM_MARKERS = {"python": "MemoryError", "cpp": "std::bad_alloc", "java": "java.lang.OutOfMemoryError",
               "go": "runtime: out of memory", "rust": "memory allocation of"}


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
                    if case == "MLE-cgroup" and language in OOM_MARKERS:
                        self.assertNotIn(OOM_MARKERS[language], stderr)
                    if case == "CE":
                        self.assertTrue(report["compile_error"])
                    elif case == "ACC":
                        self.assertIsNone(report["failed_testcase"])
                    else:
                        self.assertTrue(report["failed_testcase"]["reason"])
                        self.assertIsInstance(report["failed_testcase"]["cpu_ms"], int)


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
        self.assertEqual(report["failed_testcase"]["reason"], "signal SIGSEGV")

    def test_forbidden_syscall_is_a_runtime_error(self):
        solution = "#include <sched.h>\nint f() { unshare(0); return 42; }\n"
        report = self.verdict(executor.run_job(**job("cpp", solution, CPP_DRIVER)), "RE")
        self.assertIn("forbidden syscall", report["runtime_error"])
        self.assertEqual(report["failed_testcase"]["reason"], "forbidden syscall")

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


class TestSandboxOverhead(Verdicts):
    def test_a_trivial_program_reports_less_than_an_empty_jail_costs(self):
        overhead = executor.ready()["overhead"]
        self.assertGreater(overhead["memory_kb"], 1024, overhead)   # nsjail's own footprint
        report = self.verdict(executor.run_job(**job("c", "int f(void) { return 42; }\n", C_DRIVER)), "ACC")
        self.assertLessEqual(report["memory_mb"], 2, report)   # a static binary's few pages
        self.assertLess(report["memory_mb"] * 1024, overhead["memory_kb"], (report, overhead))
        self.assertLess(report["runtime_ms"], max(overhead["cpu_ms"], 20), (report, overhead))


class TestC(Verdicts):
    def test_driver_including_the_solution_links_with_libm(self):
        # Compiling solution.c on its own as well would define f and counter twice.
        solution = "#include <math.h>\nint counter = 41;\nint f(void) { volatile double x = 2; return counter + (int)sqrt(x * 0.5); }\n"
        self.verdict(executor.run_job(**job("c", solution, C_DRIVER)), "ACC")


class TestGo(Verdicts):
    def test_a_job_compiles_well_under_the_compile_time_limit(self):
        # Prebuilt standard library: compile and link take about a second, not the
        # ~10 s a cold `go build` spends rebuilding the standard library.
        solution = ('package main\n\nimport (\n"sort"\n"strings"\n)\n\n'
                    'func f() int {\ns := strings.Fields("3 1 2")\nsort.Strings(s)\nreturn len(s) * 14\n}\n')
        started = time.monotonic()
        self.verdict(executor.run_job(**job("go", solution, GO_DRIVER)), "ACC")
        self.assertLess(time.monotonic() - started, 5)   # the compile limit is 30 s

    def test_runtime_error_is_the_panics_exit_code(self):
        report = self.verdict(executor.run_job(**job("go", MATRIX["go"][1]["RE"], GO_DRIVER)), "RE")
        self.assertIn("exit code 2", report["runtime_error"])
        self.assertIn("panic: boom", report["runtime_error"])


class TestJavaScript(Verdicts):
    def test_syntax_error_is_a_compile_error_with_nodes_message(self):
        report = self.verdict(executor.run_job(**job("javascript", MATRIX["javascript"][1]["CE"], JS_DRIVER)), "CE")
        self.assertIn("solution.js", report["compile_error"])
        self.assertIn("SyntaxError", report["compile_error"])

    def test_syntax_error_in_the_driver_is_a_compile_error_too(self):
        report = self.verdict(executor.run_job(**job("javascript", MATRIX["javascript"][1]["ACC"],
                                                     "const { f } = require('./solution');\nconsole.log(f(;\n")), "CE")
        self.assertIn("main.js", report["compile_error"])

    def test_heap_blow_up_is_memory_limit_exceeded(self):
        self.verdict(executor.run_job(**job("javascript", js_solution("const a = []; for (;;) a.push({ i: a.length });"),
                                            JS_DRIVER, time_limit=5000, memory_limit=128)), "MLE")

    def test_calibrations_memory_limit_starts_node(self):
        # 1024 MB stack rlimit: with V8's default four worker threads Node hangs at startup.
        report = self.verdict(executor.run_job(**job("javascript", MATRIX["javascript"][1]["ACC"], JS_DRIVER,
                                                     task="CALIBRATE")), "ACC")
        self.assertTrue(report["calibration"])

    def test_64_mb_of_objects_fits_a_128_mb_budget(self):
        solution = js_solution("const a = []; for (let i = 0; i < 64; i++) a.push(new Array(1 << 17).fill(i));"
                               " return a.length === 64 ? 42 : 0;")
        self.verdict(executor.run_job(**job("javascript", solution, JS_DRIVER, time_limit=5000,
                                            memory_limit=128)), "ACC")


class TestRust(Verdicts):
    def test_a_compile_past_768_mb_is_a_compile_error(self):
        # Constant evaluation builds the 1 GiB array in rustc's own memory.
        solution = "static A: [u8; 1 << 30] = [1; 1 << 30];\npub fn f() -> i32 {\n    A[7] as i32 + 41\n}\n"
        report = self.verdict(executor.run_job(**job("rust", solution, RUST_DRIVER)), "CE")
        self.assertIn("exceeded its memory limit", report["compile_error"])

    def test_runtime_error_is_the_panics_exit_code(self):
        report = self.verdict(executor.run_job(**job("rust", MATRIX["rust"][1]["RE"], RUST_DRIVER)), "RE")
        self.assertIn("exit code 101", report["runtime_error"])
        self.assertIn("boom", report["runtime_error"])

    def test_recursive_dfs_of_depth_100000_fits_a_128_mb_budget(self):
        solution = ("fn depth(adj: &[Vec<usize>], u: usize, p: usize) -> usize {\n"
                    "    let frame = std::hint::black_box([0u8; 256]);\n"
                    "    let mut best = 0;\n"
                    "    for &v in &adj[u] { if v != p { best = best.max(depth(adj, v, u)); } }\n"
                    "    best + 1 + frame[0] as usize\n}\n"
                    "pub fn f() -> i32 {\n    let n = 100_000;\n    let mut adj = vec![Vec::new(); n];\n"
                    "    for i in 1..n { adj[i - 1].push(i); adj[i].push(i - 1); }\n"
                    "    if depth(&adj, 0, usize::MAX) == n { 42 } else { 0 }\n}\n")
        self.verdict(executor.run_job(**job("rust", solution, RUST_DRIVER, memory_limit=128)), "ACC")


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
        self.assertIsNone(report["test_results"][0]["reason"])
        self.assertTrue(report["test_results"][1]["reason"])
        for outcome in report["test_results"]:
            self.assertIsInstance(outcome["cpu_ms"], int)

    def test_wrong_answer_stops_submit(self):
        report = self.verdict(executor.run_job(**python_job(
            "def add(a,b):\n    return a-b\n", ADD_DRIVER, test_cases=CASES)), "WA")
        self.assertEqual(report["failed_testcase"]["index"], 0)

    def test_exit_255_is_runtime_error(self):
        report = self.verdict(executor.run_job(**python_job(
            "import sys\ndef f():\n    sys.exit(255)\n")), "RE")
        self.assertIn("exit code 255", report["runtime_error"])
        self.assertEqual(report["failed_testcase"]["reason"], "exit code 255")

    def test_exit_139_is_an_exit_code_not_a_signal(self):
        report = self.verdict(executor.run_job(**python_job(
            "import sys\ndef f():\n    sys.exit(139)\n")), "RE")
        self.assertIn("exit code 139", report["runtime_error"])
        self.assertEqual(report["failed_testcase"]["reason"], "exit code 139")

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
        self.assertEqual(report["failed_testcase"]["reason"], "cpu time limit exceeded")
        self.assertIsNone(report["failed_testcase"]["error_message"])
        self.assertLessEqual(report["runtime_ms"], 900)   # at most ~300 ms past the limit

    def test_sleeping_is_a_wall_time_limit(self):
        # 333 ms x 3 = 999 ms CPU enforced; wall is killed at 2 x 999 + 1000 ms.
        started = time.monotonic()
        report = self.verdict(executor.run_job(**python_job(
            "import time\ndef f():\n    time.sleep(30)\n", time_limit=333)), "TLE")
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(report["failed_testcase"]["reason"], "wall time limit exceeded")

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


ANSWER_DRIVER = "import sys\nprint(sys.stdin.read())\n"   # the input is the answer line


class TestCheckers(Verdicts):
    def judge(self, answer, expected, checker=None):
        extra = {} if checker is None else {"checker": checker}
        return executor.run_job(**python_job("", ANSWER_DRIVER, test_cases=[
            {"input": answer, "expectedOutput": expected}], **extra))

    def test_without_a_checker_the_answer_line_must_match_exactly(self):
        self.verdict(self.judge("  1 2  \n", "1 2"), "ACC")    # the answer line is stripped
        self.verdict(self.judge("1  2", "1 2"), "WA")
        self.verdict(self.judge("0.30000000000000004", "0.3"), "WA")

    def test_exact_mode_is_the_default(self):
        self.verdict(self.judge("1  2", "1 2", {"mode": "exact"}), "WA")

    def test_tokens_ignores_whitespace_between_tokens(self):
        self.verdict(self.judge("1 \t 2", "1 2", {"mode": "tokens"}), "ACC")
        self.verdict(self.judge("1 2 3", "1 2", {"mode": "tokens"}), "WA")

    def test_float_accepts_within_the_default_epsilon(self):
        self.verdict(self.judge("0.30000000000000004", "0.3", {"mode": "float"}), "ACC")
        self.verdict(self.judge("yes 1.0000001", "yes 1", {"mode": "float"}), "ACC")

    def test_float_rejects_outside_the_epsilon(self):
        self.verdict(self.judge("0.3001", "0.3", {"mode": "float"}), "WA")
        self.verdict(self.judge("no 0.3", "yes 0.3", {"mode": "float"}), "WA")
        self.verdict(self.judge("nan", "nan", {"mode": "float", "absEpsilon": 1}), "ACC")   # same token
        self.verdict(self.judge("0.31", "0.3", {"mode": "float", "absEpsilon": 0.001, "relEpsilon": 0}), "WA")

    def test_float_epsilons_widen_the_tolerance(self):
        self.verdict(self.judge("0.31", "0.3", {"mode": "float", "absEpsilon": 0.02}), "ACC")
        self.verdict(self.judge("1050", "1000", {"mode": "float", "relEpsilon": 0.1}), "ACC")

    def test_unknown_mode_is_a_worker_failure_naming_it(self):
        response = self.judge("1", "1", {"mode": "lines"})
        self.assertEqual(response["status"], "FAILED", response)
        self.assertIn("lines", response["error"])

    def test_a_negative_epsilon_is_a_worker_failure(self):
        response = self.judge("1", "1", {"mode": "float", "absEpsilon": -1})
        self.assertEqual(response["status"], "FAILED", response)
        self.assertIn("absEpsilon", response["error"])


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
        self.assertIn("50", response["error"])

    def test_out_of_range_limits_are_not_clamped(self):
        for limits, cap in (({"time_limit": 6000}, "5000"), ({"time_limit": 0}, "5000"),
                            ({"memory_limit": 129}, "128"), ({"memory_limit": 0}, "128")):
            with self.subTest(**limits):
                response = executor.run_job(**python_job(ADD, ADD_DRIVER, test_cases=CASES, **limits))
                self.assertWorkerFailure(response)
                self.assertIn(cap, response["error"])

    def test_oversize_code_and_input(self):
        big = "#" * (256 * 1024) + "\n"     # one byte over judgebox's 256 KiB
        case = {"input": "x" * (16 * 1024 * 1024 + 1), "expectedOutput": "1"}
        half = {"input": "x" * (12 * 1024 * 1024), "expectedOutput": "1"}       # 4 of them: 48 MiB + 4
        for name, job, cap in (("user code", python_job(ADD + big, ADD_DRIVER, test_cases=CASES), "262144"),
                               ("driver code", python_job(ADD, ADD_DRIVER + big, test_cases=CASES), "262144"),
                               ("input", python_job(ADD, ADD_DRIVER, test_cases=[case]), "16777216"),
                               ("total", python_job(ADD, ADD_DRIVER, test_cases=[half] * 4), "50331648")):
            with self.subTest(name):
                response = executor.run_job(**job)
                self.assertWorkerFailure(response)
                self.assertIn(cap, response["error"])

    def test_unsupported_language(self):
        job = python_job(ADD, ADD_DRIVER, test_cases=CASES)
        job["language"] = "cobol"
        response = executor.run_job(**job)
        self.assertWorkerFailure(response)
        self.assertIn("cobol", response["error"])


if __name__ == "__main__":
    unittest.main()
