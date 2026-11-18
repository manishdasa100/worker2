"""
Judge — turns one ExecutionRequest into an ExecutionReport.

Pipeline:  validate language, limits, payload sizes and checker -> write files
-> compile IN THE JAIL -> run each test case in a fresh jail -> classify ->
aggregate. A job that fails validation is a worker failure: nothing runs and
nothing is clamped.

SUBMIT_CODE stops at the first failing test; RUN_CODE runs all and reports
the worst by precedence; CALIBRATE is delegated to calibrate.Calibrator.

Verdict classification is preserved verbatim from worker1 (it matches what the
backend expects). The structural change is that compilation runs through
sandbox.compile() instead of a host subprocess.
"""
import asyncio
import logging
import math
import signal
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from config import WorkerConfig
from languages import get_language
from models import (
    ExecutionReport,
    ExecutionRequest,
    StatusCode,
    TestCaseResult,
    TestStatus,
)
from sandbox import NsjailSandbox, SandboxResult, workspace

logger = logging.getLogger(__name__)

CHECKER_MODES = ("exact", "tokens", "float")
DEFAULT_EPSILON = 1e-6


def checker_error(checker) -> Optional[str]:
    """Why `checker` (the job's optional checker object) is invalid, or None."""
    if checker is None:
        return None
    if not isinstance(checker, dict):
        return f"checker must be an object, got {checker!r}"
    if checker.get("mode", "exact") not in CHECKER_MODES:
        return f"unknown checker mode {checker.get('mode')!r}; expected one of {', '.join(CHECKER_MODES)}"
    for key in ("absEpsilon", "relEpsilon"):
        eps = checker.get(key)
        if eps is not None and (isinstance(eps, bool) or not isinstance(eps, (int, float))
                                or not 0 <= eps < math.inf):
            return f"checker {key} must be a non-negative number, got {eps!r}"
    return None


def answer_matches(answer: str, expected: str, checker: Optional[dict]) -> bool:
    """
    Compare the answer line with the expected output (both stripped) by the
    checker's mode: exact, tokens (whitespace-separated), or float (tokens, numeric
    ones within an absolute or relative epsilon of the expected value).
    """
    mode = (checker or {}).get("mode", "exact")
    if mode == "exact":
        return answer == expected
    got, want = answer.split(), expected.split()
    if len(got) != len(want):
        return False
    if mode == "tokens":
        return got == want
    abs_eps, rel_eps = (DEFAULT_EPSILON if checker.get(k) is None else checker[k]
                        for k in ("absEpsilon", "relEpsilon"))
    return all(g == w or floats_close(g, w, abs_eps, rel_eps) for g, w in zip(got, want))


def floats_close(got: str, want: str, abs_eps: float, rel_eps: float) -> bool:
    try:
        x, y = float(got), float(want)
    except ValueError:
        return False
    if not (math.isfinite(x) and math.isfinite(y)):
        return False
    return abs(x - y) <= max(abs_eps, rel_eps * abs(y))


def signal_name(number: int) -> str:
    try:
        return signal.Signals(number).name
    except ValueError:
        return str(number)


@dataclass
class CompileOutcome:
    ok: bool
    error_message: str = ""
    compile_ms: int = 0


class Judge:
    def __init__(self, config: WorkerConfig):
        self.config = config
        self.sandbox = NsjailSandbox(config.sandbox, config.execution.max_output_bytes)

    # ---- compile (sandboxed) ------------------------------------------------

    async def _compile(self, lang, code_dir: str) -> CompileOutcome:
        """
        Compile inside the jail (no host FS, no network, cgroup-bounded), one jail
        per compile command, sharing one compile CPU limit. Maps the first failing
        command's sandbox result to a compile verdict:
          no commands       -> nothing to compile, trivially ok
          time_limit_hit    -> compile time limit (likely a compile bomb)
          oom_killed        -> compile exceeded its memory limit
          exit != 0         -> compiler diagnostics (stderr, else stdout: Go's compiler prints there)
        """
        started = time.monotonic()
        compile_cpu_left_ms = self.config.execution.compile_timeout * 1000
        for command in lang.compile_commands():
            sr = await self.sandbox.compile(
                command=command, code_dir=code_dir, toolchain=lang.compile_toolchain,
                time_limit_ms=compile_cpu_left_ms,
                memory_limit=self.config.execution.compile_memory_limit,
            )
            compile_ms = int((time.monotonic() - started) * 1000)

            if sr.setup_failed:
                raise RuntimeError(f"Jail failed to launch the compiler (exit={sr.exit_code}): "
                                   f"{sr.nsjail_log[-500:]}")
            if sr.time_limit_hit:
                return CompileOutcome(False, "Compilation timed out", compile_ms)
            if sr.oom_killed:
                return CompileOutcome(False, "Compilation exceeded its memory limit", compile_ms)
            if sr.exit_code != 0:
                msg = (sr.stderr or sr.stdout or "Compilation error").strip()
                return CompileOutcome(False, msg[: self.config.execution.max_output_bytes], compile_ms)
            compile_cpu_left_ms = max(1, compile_cpu_left_ms - sr.cpu_ms)
        return CompileOutcome(ok=True, compile_ms=int((time.monotonic() - started) * 1000))

    # ---- main entry ---------------------------------------------------------

    async def judge(self, request: ExecutionRequest) -> ExecutionReport:
        job_id = request.job_id
        logger.info("[%s] Judging: language=%s, task=%s", job_id, request.language, request.task)

        lang = get_language(request.language)
        if lang is None:
            logger.warning("[%s] Unsupported language: %s", job_id, request.language)
            return self._error_report(request, StatusCode.UNSUPPORTED_LANGUAGE,
                                      f"Language '{request.language}' is not supported")

        # Breaking a worker cap is a config error on the backend's side, not a user verdict.
        invalid = self._validate(request)
        if invalid:
            logger.error("[%s] Invalid job: %s", job_id, invalid)
            report = self._error_report(request, StatusCode.INTERNAL_ERROR, "Internal execution error")
            report.internal_error = invalid
            return report

        try:
            with workspace() as code_dir:
                lang.write_files(code_dir, request.user_code, request.driver_code)

                outcome = await self._compile(lang, code_dir)
                if not outcome.ok:
                    logger.info("[%s] Compilation failed", job_id)
                    report = self._error_report(request, StatusCode.COMPILE_ERROR, "Compilation error")
                    report.compile_error = outcome.error_message
                    return report

                if request.task == "CALIBRATE":
                    from calibrate import Calibrator
                    time_limit_ms = self.config.execution.calibration_time_limit * 1000
                    memory_limit = self.config.execution.calibration_memory_limit
                    logger.info("[%s] Calibration limits: time %dms, memory %dMB",
                                job_id, time_limit_ms, memory_limit)
                    return await Calibrator(self).run(
                        request=request, lang=lang, command=lang.run_command(memory_limit),
                        code_dir=code_dir, time_limit_ms=time_limit_ms,
                        memory_limit=memory_limit, compile_ms=outcome.compile_ms)

                time_limit_ms, memory_limit = self._resolve_limits(request, lang)
                logger.info("[%s] Limits: cpu %dms, memory %dMB", job_id, time_limit_ms, memory_limit)

                test_results = await self._run_test_cases(
                    job_id=job_id, command=lang.run_command(memory_limit), code_dir=code_dir,
                    toolchain=lang.run_toolchain,
                    test_cases=request.test_cases, time_limit_ms=time_limit_ms,
                    memory_limit=memory_limit, oom_markers=lang.oom_error_markers,
                    stop_on_failure=(request.task == "SUBMIT_CODE"), checker=request.checker)

                report = self._build_report(request, test_results)
                logger.info("[%s] Complete: status=%s, passed=%d/%d", job_id,
                            report.status_msg, report.total_correct, report.total_testcases)
                return report

        except Exception as e:
            logger.exception("[%s] Internal error during judging", job_id)
            report = self._error_report(request, StatusCode.INTERNAL_ERROR, "Internal execution error")
            report.internal_error = str(e)
            return report

    def _validate(self, request: ExecutionRequest) -> Optional[str]:
        """Why the job can't be judged as sent (a cap, a limit, the checker), or None."""
        caps = self.config.execution
        cases = request.test_cases
        if len(cases) > caps.max_testcases:
            return f"{len(cases)} test cases exceed the worker limit of {caps.max_testcases}"
        # CALIBRATE runs under its own limits and ignores the job's.
        if request.task != "CALIBRATE":
            if not 1 <= request.time_limit <= caps.default_time_limit_ms:
                return f"time limit {request.time_limit} ms is outside the worker's 1..{caps.default_time_limit_ms} ms"
            if not 1 <= request.memory_limit <= caps.default_memory_limit:
                return f"memory limit {request.memory_limit} MB is outside the worker's 1..{caps.default_memory_limit} MB"
        for name, code, cap in (("user code", request.user_code, caps.max_user_code_bytes),
                                ("driver code", request.driver_code, caps.max_driver_code_bytes)):
            size = len(code.encode())
            if size > cap:
                return f"{name} is {size} bytes, over the worker limit of {cap}"
        total = 0
        for i, case in enumerate(cases):
            size = len(case.get("input", "").encode())
            if size > caps.max_input_bytes:
                return f"test case {i}'s input is {size} bytes, over the worker limit of {caps.max_input_bytes}"
            total += size + len((case.get("expectedOutput") or "").encode())
        if total > caps.max_total_input_bytes:
            return (f"test cases' input and expected output total {total} bytes, over the worker limit "
                    f"of {caps.max_total_input_bytes}")
        return checker_error(request.checker)

    def _resolve_limits(self, request: ExecutionRequest, lang) -> Tuple[int, int]:
        """
        Per-language fairness on the validated budget: CPU budget x time_multiplier,
        memory budget + runtime baseline.
        """
        time_limit_ms = math.ceil(request.time_limit * lang.time_multiplier)
        memory_limit = request.memory_limit + lang.memory_baseline_mb
        return time_limit_ms, memory_limit

    # ---- running + classification (preserved from worker1) ------------------

    async def _run_test_cases(self, job_id, command, code_dir, toolchain, test_cases, time_limit_ms,
                              memory_limit, oom_markers, stop_on_failure, checker) -> List[TestCaseResult]:
        results = []
        for i, test_case in enumerate(test_cases):
            input_data = test_case.get("input", "")
            expected_output = test_case.get("expectedOutput", "").strip()
            sr = await self.sandbox.run(command=command, code_dir=code_dir, toolchain=toolchain, stdin_data=input_data,
                                        time_limit_ms=time_limit_ms, memory_limit=memory_limit)
            tc = self._evaluate_test_case(i, sr, input_data, expected_output, oom_markers, checker)
            results.append(tc)
            if stop_on_failure and tc.status != TestStatus.PASSED:
                logger.info("[%s] Test case %d failed, stopping (SUBMIT_CODE)", job_id, i)
                break
        return results

    def _evaluate_test_case(self, index, sandbox_result: SandboxResult, input_data,
                            expected_output, oom_markers=(), checker=None) -> TestCaseResult:
        cap = self.config.execution.max_output_bytes
        partial_stdout = sandbox_result.stdout[:cap]
        partial_stderr = (sandbox_result.stderr or "")[:cap]
        measured = dict(runtime_ms=sandbox_result.runtime_ms, memory_mb=sandbox_result.peak_memory_mb,
                        cpu_ms=sandbox_result.cpu_ms)

        if sandbox_result.output_exceeded:
            return TestCaseResult(index, TestStatus.OUTPUT_LIMIT, input_data, expected_output,
                                  reason="output limit exceeded", **measured)

        if sandbox_result.time_limit_hit:
            return TestCaseResult(index, TestStatus.TIMEOUT, input_data, expected_output,
                                  std_output=partial_stdout, stderr=partial_stderr,
                                  reason=f"{sandbox_result.time_limit_hit} time limit exceeded", **measured)

        runtime_oom = any(m in (sandbox_result.stderr or "") for m in oom_markers)
        if sandbox_result.oom_killed or (sandbox_result.exit_code != 0 and runtime_oom):
            return TestCaseResult(index, TestStatus.MEMORY_EXCEED, input_data, expected_output,
                                  std_output=partial_stdout, stderr=partial_stderr,
                                  reason="memory limit exceeded", **measured)

        if sandbox_result.setup_failed:
            logger.error("Jail failed to execute (exit=%d) stderr=%r log=%r", sandbox_result.exit_code,
                         partial_stderr, sandbox_result.nsjail_log)
            return TestCaseResult(index, TestStatus.ERROR, input_data, expected_output,
                                  stderr=partial_stderr, error_message="Sandbox failed to execute",
                                  reason="jail failed to execute", runtime_ms=sandbox_result.runtime_ms,
                                  cpu_ms=sandbox_result.cpu_ms)

        if sandbox_result.exit_code != 0:
            stderr = sandbox_result.stderr.strip() if sandbox_result.stderr else ""
            if sandbox_result.signal:
                names = {9: "SIGKILL", 11: "SIGSEGV (Segmentation fault)",
                         6: "SIGABRT", 8: "SIGFPE (Floating point exception)",
                         31: "SIGSYS (forbidden syscall)"}
                error_msg = f"Process killed by {names.get(sandbox_result.signal, f'Signal {sandbox_result.signal}')}"
                reason = ("forbidden syscall" if sandbox_result.signal == signal.SIGSYS
                          else f"signal {signal_name(sandbox_result.signal)}")
            else:
                error_msg = f"Runtime error (exit code {sandbox_result.exit_code})" + (f"\n{stderr}" if stderr else "")
                reason = f"exit code {sandbox_result.exit_code}"
            return TestCaseResult(index, TestStatus.RUNTIME_ERROR, input_data, expected_output,
                                  std_output=sandbox_result.stdout, stderr=stderr, error_message=error_msg,
                                  reason=reason, **measured)

        stdout = sandbox_result.stdout
        # Answer = last non-empty line; everything before it is debug output.
        non_empty = [ln for ln in stdout.rstrip("\n").split("\n") if ln.strip()]
        if not non_empty:
            actual_output, std_output = "", ""
        else:
            actual_output = non_empty[-1].strip()
            std_output = "\n".join(non_empty[:-1])

        # No expected output (RUN_CODE without one) passes whatever was printed.
        if not expected_output or answer_matches(actual_output, expected_output, checker):
            status, reason = TestStatus.PASSED, None
        else:
            status, reason = TestStatus.FAILED, "answer line differs from the expected output"

        return TestCaseResult(index, status, input_data, expected_output, actual_output=actual_output,
                              std_output=std_output, reason=reason, **measured)

    def _resolve_status(self, tc: TestCaseResult):
        if tc.status == TestStatus.ERROR:
            return (StatusCode.INTERNAL_ERROR, "Internal Error", None, tc.error_message)
        if tc.status == TestStatus.RUNTIME_ERROR:
            return (StatusCode.RUNTIME_ERROR, "Runtime Error", tc.error_message, None)
        if tc.status == TestStatus.TIMEOUT:
            return (StatusCode.TIME_LIMIT_EXCEEDED, "Time Limit Exceeded", None, None)
        if tc.status == TestStatus.MEMORY_EXCEED:
            return (StatusCode.MEMORY_LIMIT_EXCEEDED, "Memory Limit Exceeded", None, None)
        if tc.status == TestStatus.OUTPUT_LIMIT:
            return (StatusCode.OUTPUT_LIMIT_EXCEEDED, "Output Limit Exceeded", None, None)
        return (StatusCode.WRONG_ANSWER, "Wrong Answer", None, None)

    def _build_report(self, request: ExecutionRequest, test_results: List[TestCaseResult]) -> ExecutionReport:
        total = len(request.test_cases)
        passed = sum(1 for r in test_results if r.status == TestStatus.PASSED)
        is_submit = request.task == "SUBMIT_CODE"
        runtime_error = internal_error = first_failure = None

        if total == 0:
            logger.error("[%s] No test cases in request", request.job_id)
            status_code, status_msg = StatusCode.INTERNAL_ERROR, "No test cases"
        elif passed == total:
            status_code, status_msg = StatusCode.ACCEPTED, "Accepted"
        elif is_submit:
            first_failure = next(r for r in test_results if r.status != TestStatus.PASSED)
            status_code, status_msg, runtime_error, internal_error = self._resolve_status(first_failure)
        else:
            precedence = [TestStatus.ERROR, TestStatus.RUNTIME_ERROR, TestStatus.TIMEOUT,
                          TestStatus.MEMORY_EXCEED, TestStatus.OUTPUT_LIMIT, TestStatus.FAILED]
            failures = [r for r in test_results if r.status != TestStatus.PASSED]
            dominant = min(failures, key=lambda r: precedence.index(r.status)
                           if r.status in precedence else len(precedence))
            status_code, status_msg, runtime_error, internal_error = self._resolve_status(dominant)

        return ExecutionReport(
            execution_id=request.job_id, language=request.language, task=request.task,
            status_code=status_code, status_msg=status_msg, runtime_error=runtime_error,
            internal_error=internal_error, total_testcases=total, total_correct=passed,
            runtime_ms=max((r.runtime_ms for r in test_results), default=0),
            memory_mb=max((r.memory_mb for r in test_results), default=0),
            failed_testcase=first_failure if is_submit else None,
            test_results=test_results if not is_submit else None)

    def _error_report(self, request: ExecutionRequest, status_code, status_msg) -> ExecutionReport:
        return ExecutionReport(execution_id=request.job_id, language=request.language,
                               task=request.task, status_code=status_code, status_msg=status_msg)
