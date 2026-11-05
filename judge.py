"""
Judge — turns one ExecutionRequest into an ExecutionReport.

Pipeline:  validate language -> cap test count -> write files -> compile
IN THE JAIL -> run each test case in a fresh jail -> classify -> aggregate.

SUBMIT_CODE stops at the first failing test; RUN_CODE runs all and reports
the worst by precedence; CALIBRATE is delegated to calibrate.Calibrator.

Verdict classification is preserved verbatim from worker1 (it matches what the
backend expects). The structural change is that compilation runs through
sandbox.compile() instead of a host subprocess.
"""
import asyncio
import logging
import math
import os
import shutil
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from cgroups import CgroupDelegation
from config import WorkerConfig
from languages import get_language, LANGUAGES
from models import (
    ExecutionReport,
    ExecutionRequest,
    StatusCode,
    TestCaseResult,
    TestStatus,
)
from sandbox import NsjailSandbox, SandboxResult

logger = logging.getLogger(__name__)

# Trivial per-language programs to pre-fault runtimes (interpreter/JVM/compiler/
# libs) into the page cache so the first real submission doesn't pay cold-cache
# latency inside its enforced window.
WARMUP_PROGRAMS = {
    "python": ("def f():\n    return 42\n",
               "from solution import f\nprint(f())\n"),
    "cpp": ("int f() { return 42; }\n",
            '#include <iostream>\n#include "solution.cpp"\nint main(){ std::cout << f() << std::endl; }\n'),
    "java": ("public class Solution { static int f() { return 42; } }\n",
             "public class Main { public static void main(String[] a) { System.out.println(Solution.f()); } }\n"),
}


@dataclass
class CompileOutcome:
    ok: bool
    error_message: str = ""
    compile_ms: int = 0


class Judge:
    def __init__(self, config: WorkerConfig, delegation: CgroupDelegation):
        self.config = config
        self.sandbox = NsjailSandbox(config.sandbox, delegation, config.execution.max_output_bytes)

    # ---- warmup -------------------------------------------------------------

    async def warmup(self) -> None:
        """Compile+run a trivial program per language so the first real job runs warm."""
        started = time.monotonic()
        for name, lang in LANGUAGES.items():
            if name not in WARMUP_PROGRAMS:
                continue
            user_code, driver_code = WARMUP_PROGRAMS[name]
            warm_dir = os.path.join(self.config.execution.temp_dir, f"warmup_{name}_{os.getpid()}")
            try:
                os.makedirs(warm_dir, exist_ok=True)
                lang.write_files(warm_dir, user_code, driver_code)
                outcome = await self._compile(lang, warm_dir)
                if not outcome.ok:
                    logger.warning("Warmup compile failed for %s: %s", name, outcome.error_message[:200])
                    continue
                result = await self.sandbox.run(
                    command=lang.run_command(256), code_dir=warm_dir,
                    time_limit_ms=10000, memory_limit=256)
                if result.exit_code != 0:
                    logger.warning("Warmup run failed for %s (exit=%d): %s",
                                   name, result.exit_code, result.stderr.strip()[:200])
            except Exception as e:
                logger.warning("Warmup for %s failed: %s", name, e)
            finally:
                shutil.rmtree(warm_dir, ignore_errors=True)
        logger.info("Language runtimes warmed in %dms", int((time.monotonic() - started) * 1000))

    # ---- compile (sandboxed) ------------------------------------------------

    async def _compile(self, lang, code_dir: str) -> CompileOutcome:
        """
        Compile inside the jail (no host FS, no network, cgroup-bounded). Maps the
        sandbox result to a compile verdict:
          None command      -> interpreted, trivially ok
          timed_out         -> compile time limit (likely a compile bomb)
          oom_killed        -> compile ran out of memory
          exit != 0         -> compiler diagnostics (stderr)
        """
        command = lang.compile_command()
        if command is None:
            return CompileOutcome(ok=True)

        started = time.monotonic()
        sr = await self.sandbox.compile(
            command=command, code_dir=code_dir,
            time_limit_ms=self.config.execution.compile_timeout * 1000,
            memory_limit=self.config.execution.compile_memory_limit,
        )
        compile_ms = int((time.monotonic() - started) * 1000)

        if sr.setup_failed:
            raise RuntimeError(f"Jail failed to launch the compiler (exit={sr.exit_code}): "
                               f"{sr.nsjail_log[-500:]}")
        if sr.timed_out:
            return CompileOutcome(False, "Compilation timed out", compile_ms)
        if sr.oom_killed:
            return CompileOutcome(False, "Compilation ran out of memory", compile_ms)
        if sr.exit_code != 0:
            msg = (sr.stderr or sr.stdout or "Compilation error").strip()
            return CompileOutcome(False, msg[: self.config.execution.max_output_bytes], compile_ms)
        return CompileOutcome(ok=True, compile_ms=compile_ms)

    # ---- main entry ---------------------------------------------------------

    async def judge(self, request: ExecutionRequest) -> ExecutionReport:
        job_id = request.job_id
        logger.info("[%s] Judging: language=%s, task=%s", job_id, request.language, request.task)

        lang = get_language(request.language)
        if lang is None:
            logger.warning("[%s] Unsupported language: %s", job_id, request.language)
            return self._error_report(request, StatusCode.UNSUPPORTED_LANGUAGE,
                                      f"Language '{request.language}' is not supported")

        # Worker backstop on job duration (backend should cap too). Breaching is a
        # config error, not a user verdict.
        if len(request.test_cases) > self.config.execution.max_testcases:
            logger.error("[%s] Too many test cases: %d > %d", job_id,
                         len(request.test_cases), self.config.execution.max_testcases)
            report = self._error_report(request, StatusCode.INTERNAL_ERROR, "Internal execution error")
            report.internal_error = (f"Test case count {len(request.test_cases)} exceeds the worker "
                                     f"limit of {self.config.execution.max_testcases}")
            return report

        exec_dir = os.path.join(self.config.execution.temp_dir, f"exec_{job_id}")
        code_dir = os.path.join(exec_dir, "code")
        try:
            os.makedirs(code_dir, exist_ok=True)
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
                test_cases=request.test_cases, time_limit_ms=time_limit_ms,
                memory_limit=memory_limit, oom_markers=lang.oom_error_markers,
                stop_on_failure=(request.task == "SUBMIT_CODE"))

            report = self._build_report(request, test_results)
            logger.info("[%s] Complete: status=%s, passed=%d/%d", job_id,
                        report.status_msg, report.total_correct, report.total_testcases)
            return report

        except Exception as e:
            logger.exception("[%s] Internal error during judging", job_id)
            report = self._error_report(request, StatusCode.INTERNAL_ERROR, "Internal execution error")
            report.internal_error = str(e)
            return report
        finally:
            shutil.rmtree(exec_dir, ignore_errors=True)

    def _resolve_limits(self, request: ExecutionRequest, lang) -> Tuple[int, int]:
        """
        Clamp request budget to worker caps, floor at 1 (0 = UNLIMITED to nsjail),
        then apply per-language fairness: CPU budget x time_multiplier, memory
        budget + runtime baseline.
        """
        time_budget_ms = max(1, min(request.time_limit, self.config.execution.default_time_limit_ms))
        memory_budget = max(1, min(request.memory_limit, self.config.execution.default_memory_limit))
        time_limit_ms = math.ceil(time_budget_ms * lang.time_multiplier)
        memory_limit = memory_budget + lang.memory_baseline_mb
        return time_limit_ms, memory_limit

    # ---- running + classification (preserved from worker1) ------------------

    async def _run_test_cases(self, job_id, command, code_dir, test_cases, time_limit_ms,
                              memory_limit, oom_markers, stop_on_failure) -> List[TestCaseResult]:
        results = []
        for i, test_case in enumerate(test_cases):
            input_data = test_case.get("input", "")
            expected_output = test_case.get("expectedOutput", "").strip()
            sr = await self.sandbox.run(command=command, code_dir=code_dir, stdin_data=input_data,
                                        time_limit_ms=time_limit_ms, memory_limit=memory_limit)
            tc = self._evaluate_test_case(i, sr, input_data, expected_output, oom_markers)
            results.append(tc)
            if stop_on_failure and tc.status != TestStatus.PASSED:
                logger.info("[%s] Test case %d failed, stopping (SUBMIT_CODE)", job_id, i)
                break
        return results

    def _evaluate_test_case(self, index, sandbox_result: SandboxResult, input_data,
                            expected_output, oom_markers=()) -> TestCaseResult:
        cap = self.config.execution.max_output_bytes
        partial_stdout = sandbox_result.stdout[:cap]
        partial_stderr = (sandbox_result.stderr or "")[:cap]

        if sandbox_result.output_exceeded:
            return TestCaseResult(index, TestStatus.OUTPUT_LIMIT, input_data, expected_output,
                                  runtime_ms=sandbox_result.runtime_ms, memory_mb=sandbox_result.peak_memory_mb)

        if sandbox_result.timed_out:
            return TestCaseResult(index, TestStatus.TIMEOUT, input_data, expected_output,
                                  std_output=partial_stdout, stderr=partial_stderr,
                                  runtime_ms=sandbox_result.runtime_ms, memory_mb=sandbox_result.peak_memory_mb)

        runtime_oom = any(m in (sandbox_result.stderr or "") for m in oom_markers)
        if sandbox_result.oom_killed or (sandbox_result.exit_code != 0 and runtime_oom):
            return TestCaseResult(index, TestStatus.MEMORY_EXCEED, input_data, expected_output,
                                  std_output=partial_stdout, stderr=partial_stderr,
                                  runtime_ms=sandbox_result.runtime_ms, memory_mb=sandbox_result.peak_memory_mb)

        if sandbox_result.setup_failed:
            logger.error("Jail failed to execute (exit=%d) stderr=%r log=%r", sandbox_result.exit_code,
                         partial_stderr, sandbox_result.nsjail_log)
            return TestCaseResult(index, TestStatus.ERROR, input_data, expected_output,
                                  stderr=partial_stderr, error_message="Sandbox failed to execute",
                                  runtime_ms=sandbox_result.runtime_ms)

        if sandbox_result.exit_code != 0:
            stderr = sandbox_result.stderr.strip() if sandbox_result.stderr else ""
            if sandbox_result.signal:
                names = {9: "SIGKILL", 11: "SIGSEGV (Segmentation fault)",
                         6: "SIGABRT", 8: "SIGFPE (Floating point exception)",
                         31: "SIGSYS (forbidden syscall)"}
                error_msg = f"Process killed by {names.get(sandbox_result.signal, f'Signal {sandbox_result.signal}')}"
            else:
                error_msg = f"Runtime error (exit code {sandbox_result.exit_code})" + (f"\n{stderr}" if stderr else "")
            return TestCaseResult(index, TestStatus.RUNTIME_ERROR, input_data, expected_output,
                                  std_output=sandbox_result.stdout, stderr=stderr, error_message=error_msg,
                                  runtime_ms=sandbox_result.runtime_ms, memory_mb=sandbox_result.peak_memory_mb)

        stdout = sandbox_result.stdout
        # Answer = last non-empty line; everything before it is debug output.
        non_empty = [ln for ln in stdout.rstrip("\n").split("\n") if ln.strip()]
        if not non_empty:
            actual_output, std_output = "", ""
        else:
            actual_output = non_empty[-1].strip()
            std_output = "\n".join(non_empty[:-1])

        if expected_output and actual_output == expected_output:
            status = TestStatus.PASSED
        elif not expected_output:
            status = TestStatus.PASSED      # RUN_CODE with no expected output
        else:
            status = TestStatus.FAILED

        return TestCaseResult(index, status, input_data, expected_output, actual_output=actual_output,
                              std_output=std_output, runtime_ms=sandbox_result.runtime_ms,
                              memory_mb=sandbox_result.peak_memory_mb)

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
