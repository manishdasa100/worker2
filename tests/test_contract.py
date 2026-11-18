"""
Fast, sandbox-free checks of the backend wire contract (parse in, payload out).
    python3 -m unittest tests.test_contract -v   (from the worker2 dir)
"""
import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import (ExecutionReport, TestCaseResult, TestStatus, parse_job_message, result_payload,
                    safe_base64_decode)


def b64(s): return base64.b64encode(s.encode()).decode()


class TestInboundParse(unittest.TestCase):
    def _msg(self, **over):
        body = {"jobId": "j1", "language": "Python", "userCode": b64("u"), "driverCode": b64("d"),
                "task": "SUBMIT_CODE", "timeLimit": 2000, "memoryLimit": 128,
                "testCases": [{"input": "1", "expectedOutput": "1"}]}
        body.update(over)
        return json.dumps(body)

    def test_basic_fields(self):
        r = parse_job_message(self._msg())
        self.assertEqual(r.job_id, "j1")
        self.assertEqual(r.language, "python")          # normalized lower
        self.assertEqual(r.user_code, "u")
        self.assertEqual(r.driver_code, "d")
        self.assertEqual(r.time_limit, 2000)
        self.assertEqual(r.memory_limit, 128)
        self.assertEqual(len(r.test_cases), 1)

    def test_snake_case_limits_accepted(self):
        body = json.loads(self._msg())
        del body["timeLimit"]; del body["memoryLimit"]
        body["time_limit"] = 1500; body["memory_limit"] = 64
        r = parse_job_message(json.dumps(body))
        self.assertEqual(r.time_limit, 1500)
        self.assertEqual(r.memory_limit, 64)

    def test_missing_limits_default(self):
        body = json.loads(self._msg())
        del body["timeLimit"]; del body["memoryLimit"]
        r = parse_job_message(json.dumps(body))
        self.assertEqual(r.time_limit, 5000)
        self.assertEqual(r.memory_limit, 50)

    def test_calibrate_adversaries_decoded(self):
        r = parse_job_message(self._msg(task="CALIBRATE", slowCode=b64("slow"), hogCode=b64("hog")))
        self.assertEqual(r.slow_code, "slow")
        self.assertEqual(r.hog_code, "hog")

    def test_checker_is_optional(self):
        self.assertIsNone(parse_job_message(self._msg()).checker)

    def test_checker_is_passed_through(self):
        checker = {"mode": "float", "absEpsilon": 1e-9, "relEpsilon": 1e-4}
        self.assertEqual(parse_job_message(self._msg(checker=checker)).checker, checker)

    def test_malformed_raises(self):
        with self.assertRaises((KeyError, ValueError, TypeError)):
            parse_job_message('{"not":"a job"}')

    def test_base64_padding_tolerated(self):
        self.assertEqual(safe_base64_decode(base64.b64encode(b"abc").decode().rstrip("=")), "abc")


class TestOutboundPayload(unittest.TestCase):
    def test_completed_has_report(self):
        p = json.loads(result_payload("j1", "COMPLETED", '{"x":1}'))
        self.assertEqual(p, {"job_id": "j1", "status": "COMPLETED",
                             "worker_type": "GVISOR_WORKER", "execution_report": '{"x":1}'})

    def test_failed_omits_report(self):
        p = json.loads(result_payload("j1", "FAILED"))
        self.assertEqual(p, {"job_id": "j1", "status": "FAILED", "worker_type": "GVISOR_WORKER"})
        self.assertNotIn("execution_report", p)

    def test_failed_carries_an_optional_error(self):
        p = json.loads(result_payload("j1", "FAILED", error="retries exhausted"))
        self.assertEqual(p, {"job_id": "j1", "status": "FAILED", "worker_type": "GVISOR_WORKER",
                             "error": "retries exhausted"})

    def test_every_test_outcome_carries_cpu_ms_and_an_optional_reason(self):
        report = ExecutionReport("j1", "python", "RUN_CODE", "TLE", "Time Limit Exceeded", test_results=[
            TestCaseResult(0, TestStatus.PASSED, cpu_ms=12),
            TestCaseResult(1, TestStatus.TIMEOUT, cpu_ms=1003, reason="cpu time limit exceeded")])
        outcomes = json.loads(report.to_json())["test_results"]
        self.assertEqual([(t["cpu_ms"], t["reason"]) for t in outcomes],
                         [(12, None), (1003, "cpu time limit exceeded")])


if __name__ == "__main__":
    unittest.main()
