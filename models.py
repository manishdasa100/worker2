"""
Wire models + (de)serialization.

The payloads here are a FIXED CONTRACT with the backend. They match worker1's
except for the spec's additive changes and the worker_type rename:

  Inbound (submission stream entry `body` field, JSON):
    {"jobId", "language", "userCode"(b64), "driverCode"(b64), "task",
     "timeLimit"(CPU-ms), "memoryLimit"(MB), "testCases":[{input,expectedOutput}],
     "slowCode"(b64, CALIBRATE), "hogCode"(b64, CALIBRATE),
     "checker": {"mode": exact|tokens|float, "absEpsilon"?, "relEpsilon"?}}   # optional

  Outbound (result stream entry `body` field, JSON):
    {"job_id", "status": COMPLETED|FAILED, "worker_type": "GVISOR_WORKER",
     "execution_report": <JSON string>,   # COMPLETED only
     "error": <string>}                   # FAILED only, optional
"""
import base64
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Dict, List, Optional

WORKER_TYPE = "GVISOR_WORKER"   # Identifies this producer on the result stream (contract)


class StatusCode(str, Enum):
    """Job-level verdict codes the backend classifies on."""
    ACCEPTED = "ACC"
    WRONG_ANSWER = "WA"
    TIME_LIMIT_EXCEEDED = "TLE"
    MEMORY_LIMIT_EXCEEDED = "MLE"
    OUTPUT_LIMIT_EXCEEDED = "OLE"
    COMPILE_ERROR = "CE"
    RUNTIME_ERROR = "RE"
    INTERNAL_ERROR = "IE"
    UNSUPPORTED_LANGUAGE = "UL"


# A report with one of these is a worker failure (FAILED), not a verdict.
WORKER_FAILURE_CODES = (StatusCode.INTERNAL_ERROR, StatusCode.UNSUPPORTED_LANGUAGE)


class TestStatus(str, Enum):
    """Per-test-case outcome."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    MEMORY_EXCEED = "MEMORY_EXCEED"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    RUNTIME_ERROR = "RUNTIME_ERROR"
    ERROR = "ERROR"


@dataclass
class ExecutionRequest:
    """One decoded submission from the stream."""
    job_id: str
    language: str
    user_code: str
    driver_code: str
    task: str                              # RUN_CODE | SUBMIT_CODE | CALIBRATE
    time_limit: int                        # CPU-ms budget per test case
    memory_limit: int                      # MB per sandbox
    test_cases: List[Dict[str, str]] = field(default_factory=list)
    stream_id: str = ""                    # Redis entry ID (for XACK + XDEL)
    slow_code: str = ""                    # CALIBRATE: too-slow adversary (time gap check)
    hog_code: str = ""                     # CALIBRATE: memory-hungry adversary (mem gap check)
    checker: Optional[dict] = None         # {mode, absEpsilon?, relEpsilon?}; None is exact


@dataclass
class RejectedEntry:
    """A stream entry to publish as FAILED and ack without running: malformed, or retries exhausted."""
    stream_id: str
    job_id: Optional[str] = None
    error: str = ""


@dataclass
class TestCaseResult:
    index: int
    status: TestStatus
    input_data: str = ""
    expected_output: str = ""
    actual_output: str = ""
    std_output: str = ""                   # Debug output (everything but the answer line)
    stderr: str = ""
    runtime_ms: int = 0
    memory_mb: int = 0
    error_message: Optional[str] = None
    reason: Optional[str] = None           # Why it didn't pass: "exit code 1", "signal SIGSEGV", ...
    cpu_ms: int = 0


@dataclass
class ExecutionReport:
    """Final per-job report. Serialized into the result payload's execution_report."""
    execution_id: str
    language: str
    task: str
    status_code: str                       # StatusCode value
    status_msg: str
    total_testcases: int = 0
    total_correct: int = 0
    runtime_ms: int = 0                     # Worst-case test runtime
    memory_mb: int = 0                      # Peak memory across tests
    test_results: Optional[List[TestCaseResult]] = None   # RUN_CODE only
    failed_testcase: Optional[Dict[str, str]] = None      # SUBMIT_CODE only
    compile_error: Optional[str] = None
    runtime_error: Optional[str] = None
    internal_error: Optional[str] = None
    calibration: Optional[Dict] = None     # CALIBRATE only
    created_at: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def safe_base64_decode(encoded: str) -> str:
    """Decode base64, tolerating missing '=' padding."""
    missing = len(encoded) % 4
    if missing:
        encoded += "=" * (4 - missing)
    return base64.b64decode(encoded).decode("utf-8")


def parse_job_message(body: str, stream_id: str = "") -> ExecutionRequest:
    """
    Parse a submission stream entry body into an ExecutionRequest.

    camelCase is the backend's shape; snake_case timeLimit/memoryLimit are
    accepted for compatibility. timeLimit is CPU-ms, memoryLimit is MB; either
    may be null/absent (defaults apply). The judge validates limits and checker.
    Raises KeyError/ValueError/TypeError on a malformed body.
    """
    data = json.loads(body)

    def limit(camel: str, snake: str, default: int) -> int:
        value = data.get(camel)
        if value is None:
            value = data.get(snake)
        return default if value is None else int(value)

    slow_code = data.get("slowCode")
    hog_code = data.get("hogCode")

    return ExecutionRequest(
        job_id=data["jobId"],
        language=data["language"].strip().lower(),
        user_code=safe_base64_decode(data["userCode"]),
        driver_code=safe_base64_decode(data["driverCode"]),
        task=data.get("task", "RUN_CODE"),
        time_limit=limit("timeLimit", "time_limit", 5000),
        memory_limit=limit("memoryLimit", "memory_limit", 50),
        test_cases=data.get("testCases", []),
        stream_id=stream_id,
        slow_code=safe_base64_decode(slow_code) if slow_code else "",
        hog_code=safe_base64_decode(hog_code) if hog_code else "",
        checker=data.get("checker"),
    )


def result_payload(job_id: str, status: str, report_json: Optional[str] = None,
                   error: Optional[str] = None) -> str:
    """
    Build the result stream entry's `body` JSON (worker -> backend).

    status is COMPLETED (report attached) or FAILED (no report — worker-level
    failure, not a verdict — optionally with the error saying why).
    """
    payload = {"job_id": job_id, "status": status, "worker_type": WORKER_TYPE}
    if report_json is not None:
        payload["execution_report"] = report_json
    if error is not None:
        payload["error"] = error
    return json.dumps(payload)
