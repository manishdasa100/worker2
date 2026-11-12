"""
Seam A: Python jobs judged by a real executor container under runsc.
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

executor = None


def setUpModule():
    global executor
    executor = ExecutorContainer().__enter__()


def tearDownModule():
    executor.__exit__()


def python_job(user_code, driver_code=F_DRIVER, task="SUBMIT_CODE", time_limit=1000,
               memory_limit=64, test_cases=({"input": "", "expectedOutput": "42"},), **extra):
    return dict(job_id=f"seam-a-{os.urandom(4).hex()}", language="python", user_code=user_code,
                driver_code=driver_code, task=task, time_limit=time_limit,
                memory_limit=memory_limit, test_cases=list(test_cases), **extra)


class TestPythonVerdicts(unittest.TestCase):
    def verdict(self, response, want):
        self.assertEqual(response["status"], "COMPLETED", response)
        report = response["report"]
        self.assertEqual(set(report), REPORT_FIELDS)        # today's report shape
        self.assertEqual(report["status_code"], want, report)
        return report

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

    def test_unlisted_syscall_is_forbidden(self):
        report = self.verdict(executor.run_job(**python_job(
            "import ctypes\ndef f():\n    ctypes.CDLL(None).syscall(309)\n    return 42\n")), "RE")
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

    def test_stdout_flood_is_output_limit_exceeded(self):
        self.verdict(executor.run_job(**python_job(
            "def f():\n    while True: print('x' * 65536)\n")), "OLE")

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

    def test_unsupported_language(self):
        job = python_job(ADD, ADD_DRIVER, test_cases=CASES)
        job["language"] = "cobol"
        response = executor.run_job(**job)
        self.assertWorkerFailure(response)
        self.assertIn("cobol", response["error"])


if __name__ == "__main__":
    unittest.main()
