"""
Calibrator — the CALIBRATE task.

Measures a reference solution under generous caps (k runs per test case,
output verified each run), derives a concrete limit recommendation, and — if
slowCode/hogCode were supplied — verifies the derived time/memory limit rejects
the wrong complexity class with a decisive gap.

Uses the Judge's sandbox primitives (run one test, evaluate, compile). Logic is
preserved from worker1; the only change is that adversary solutions compile
through the sandbox (judge._compile) rather than a host subprocess.
"""
import asyncio
import logging
import os
import shutil
import socket
import statistics
import subprocess

from models import ExecutionReport, StatusCode, TestStatus

logger = logging.getLogger(__name__)

_RUNTIME_VERSIONS: dict = {}


class Calibrator:
    def __init__(self, judge):
        self.judge = judge
        self.config = judge.config
        self.sandbox = judge.sandbox

    async def run(self, request, lang, command, code_dir, time_limit_ms, memory_limit, compile_ms) -> ExecutionReport:
        job_id = request.job_id
        runs = max(1, min(self.config.execution.calibration_runs, 20))
        total = len(request.test_cases)

        calibration = {
            "runs_per_testcase": runs,
            "compile_ms": compile_ms,
            "time_limit_ms_used": time_limit_ms,
            "memory_limit_used": memory_limit,
            "environment": await asyncio.to_thread(self._environment_metadata, lang),
            "testcases": [],
        }

        entries, failure = await self._measure_solution(
            job_id, "reference", lang, command, code_dir,
            request.test_cases, runs, time_limit_ms, memory_limit)
        calibration["testcases"] = entries
        verified = [e for e in entries if e["verified"]]

        if total == 0:
            status_code, status_msg = StatusCode.INTERNAL_ERROR, "No test cases"
            runtime_error, internal_error = None, "CALIBRATE request carried no test cases"
        elif failure is not None:
            status_code, status_msg, runtime_error, internal_error = self.judge._resolve_status(failure)
            logger.warning("[%s] Calibration failed on test case %d: %s", job_id, failure.index, status_msg)
        else:
            status_code, status_msg = StatusCode.ACCEPTED, "Accepted"
            runtime_error = internal_error = None
            calibration["recommendation"] = await self._recommend_limits(
                request, lang, code_dir, verified, memory_limit, runs)

        report = ExecutionReport(
            execution_id=job_id, language=request.language, task=request.task,
            status_code=status_code, status_msg=status_msg, runtime_error=runtime_error,
            internal_error=internal_error, total_testcases=total, total_correct=len(verified),
            runtime_ms=max((e["runtime_ms_stats"]["min"] for e in verified), default=0),
            memory_mb=max((e["memory_mb_stats"]["max"] for e in verified), default=0),
            failed_testcase=failure, calibration=calibration)
        rec = calibration.get("recommendation")
        logger.info("[%s] Calibration complete: status=%s, verified=%d/%d%s", job_id, status_msg,
                    len(verified), total,
                    f", time={rec['time_limit_ms']}ms memory={rec['memory_limit_mb']}MB" if rec else "")
        return report

    async def _measure_solution(self, job_id, label, lang, command, code_dir,
                                test_cases, runs, time_limit_ms, memory_limit):
        entries = []
        for i, test_case in enumerate(test_cases):
            input_data = test_case.get("input", "")
            expected = test_case.get("expectedOutput", "").strip()
            entry = {"index": i, "verified": False, "samples": []}
            entries.append(entry)
            logger.info("[%s] Calibrating %s test case %d/%d (%d runs)",
                        job_id, label, i + 1, len(test_cases), runs)
            for run_no in range(1, runs + 1):
                sr = await self.sandbox.run(command=command, code_dir=code_dir, stdin_data=input_data,
                                            time_limit_ms=time_limit_ms, memory_limit=memory_limit)
                tc = self.judge._evaluate_test_case(i, sr, input_data, expected, lang.oom_error_markers)
                entry["samples"].append({"run": run_no, "runtime_ms": sr.runtime_ms, "driver_ms": sr.driver_ms,
                                         "wrapper_ms": sr.wrapper_ms, "wall_ms": sr.wall_ms,
                                         "cpu_ms": sr.cpu_ms, "memory_mb": sr.peak_memory_mb})
                if tc.status != TestStatus.PASSED:
                    return entries, tc
            entry["verified"] = True
            for metric in ("runtime_ms", "cpu_ms", "memory_mb"):
                values = [s[metric] for s in entry["samples"]]
                entry[f"{metric}_stats"] = {"min": min(values), "median": statistics.median(values), "max": max(values)}
        return entries, None

    async def _recommend_limits(self, request, lang, code_dir, verified_entries, memory_limit, runs):
        cfg = self.config.execution
        t_ref = max((e["cpu_ms_stats"]["min"] for e in verified_entries), default=0)
        mem_ref = max((e["memory_mb_stats"]["max"] for e in verified_entries), default=0)
        raw_time = max(cfg.calibration_time_floor_ms, int(cfg.calibration_time_margin * t_ref))
        time_ms = self._round_up_nice(raw_time)
        memory_mb = max(cfg.calibration_memory_floor_mb, int(cfg.calibration_memory_margin * mem_ref))

        rec = {"reference_cpu_ms": t_ref, "reference_memory_mb": mem_ref,
               "time_margin": cfg.calibration_time_margin, "memory_margin": cfg.calibration_memory_margin,
               "time_limit_ms": time_ms, "memory_limit_mb": memory_mb,
               "gap_verified": None, "time_gap_ok": None, "memory_gap_ok": None,
               "slow_code_cpu_ms": None, "hog_code_memory_mb": None, "notes": []}

        performed = []
        if request.slow_code:
            await self._verify_time_gap(request, lang, code_dir, rec, memory_limit, runs)
            performed.append("runtime")
        else:
            rec["notes"].append("No slowCode supplied — time limit not gap-verified.")
        if request.hog_code:
            await self._verify_memory_gap(request, lang, code_dir, rec, runs)
            performed.append("memory")
        else:
            rec["notes"].append("No hogCode supplied — memory limit not gap-verified.")
        if performed:
            rec["gap_verified"] = "both" if len(performed) == 2 else performed[0]
        return rec

    async def _verify_time_gap(self, request, lang, code_dir, rec, memory_limit, runs):
        time_ms = rec["time_limit_ms"]
        cpu_cap_ms = 2 * time_ms + 1000
        entries = await self._measure_adversary(request, lang, code_dir, request.slow_code, "slow",
                                                 rec, "time_gap_ok", runs, cpu_cap_ms, memory_limit)
        if entries is None:
            return
        slow_cpu = max((min(s["cpu_ms"] for s in e["samples"]) for e in entries if e["samples"]), default=0)
        rec["slow_code_cpu_ms"] = slow_cpu
        rec["time_gap_ok"] = slow_cpu >= 2 * time_ms
        if not rec["time_gap_ok"]:
            rec["notes"].append(f"Time gap too small: slow used {slow_cpu}ms CPU vs 2x budget {2*time_ms}ms. "
                                f"Strengthen test data — do NOT lower the limit.")

    async def _verify_memory_gap(self, request, lang, code_dir, rec, runs):
        cfg = self.config.execution
        memory_mb = rec["memory_limit_mb"]
        mem_cap = min(2 * memory_mb + 64, cfg.calibration_memory_limit)
        entries = await self._measure_adversary(request, lang, code_dir, request.hog_code, "hog",
                                                 rec, "memory_gap_ok", min(runs, 2),
                                                 cfg.calibration_time_limit * 1000, mem_cap)
        if entries is None:
            return
        hog_mem = max((min(s["memory_mb"] for s in e["samples"]) for e in entries if e["samples"]), default=0)
        rec["hog_code_memory_mb"] = hog_mem
        rec["memory_gap_ok"] = hog_mem >= 2 * memory_mb
        if not rec["memory_gap_ok"]:
            rec["notes"].append(f"Memory gap too small: hog peaked at {hog_mem}MB vs 2x limit {2*memory_mb}MB. "
                                f"Strengthen test data — do NOT raise the limit.")

    async def _measure_adversary(self, request, lang, code_dir, code, label, rec, ok_key,
                                 runs, cpu_cap_ms, mem_cap_mb):
        """Compile + measure an adversary (slow/hog) in a sibling dir. Compiles in-jail."""
        adv_dir = os.path.join(os.path.dirname(code_dir), label)
        try:
            os.makedirs(adv_dir, exist_ok=True)
            await asyncio.to_thread(lang.write_files, adv_dir, code, request.driver_code)
            outcome = await self.judge._compile(lang, adv_dir)
            if not outcome.ok:
                rec[ok_key] = False
                rec["notes"].append(f"{label}Code failed to compile: {(outcome.error_message or '')[:200]}")
                return None
            cmd = lang.run_command(mem_cap_mb)
            entries, _ = await self._measure_solution(request.job_id, label, lang, cmd, adv_dir,
                                                       request.test_cases, runs, cpu_cap_ms, mem_cap_mb)
            return entries
        finally:
            shutil.rmtree(adv_dir, ignore_errors=True)

    @staticmethod
    def _round_up_nice(ms: int) -> int:
        for nice in (500, 1000, 1500, 2000, 3000, 5000, 8000, 10000, 15000, 20000, 30000):
            if ms <= nice:
                return nice
        return ms

    def _environment_metadata(self, lang) -> dict:
        lang_name = lang.name
        if lang_name not in _RUNTIME_VERSIONS:
            version = "unknown"
            try:
                proc = subprocess.run(lang.version_command(), capture_output=True, text=True, timeout=10)
                lines = [ln.strip() for ln in ((proc.stdout or "") + (proc.stderr or "")).splitlines() if ln.strip()]
                if lines:
                    version = lines[0]
            except Exception as e:
                logger.warning("Could not resolve %s runtime version: %s", lang_name, e)
            _RUNTIME_VERSIONS[lang_name] = version
        cpu_model = "unknown"
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith("model name"):
                        cpu_model = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass
        return {"hostname": socket.gethostname(), "cpu_model": cpu_model,
                "cpu_count": os.cpu_count(), "runtime_version": _RUNTIME_VERSIONS[lang_name]}
