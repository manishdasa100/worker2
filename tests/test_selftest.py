"""
Seam A: the containment self-test, read back through `ready`, on a healthy
executor and on ones deliberately weakened or broken.
    .venv/bin/python -m unittest tests.test_selftest -v   (needs Docker; see executor_harness)

Each class starts its own container, and each container runs a full self-test
before it answers.
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.executor_harness import ROOT, ExecutorContainer
from tests.test_executor import python_job

KILLS = {f"seccomp_kills_{s}" for s in ("ptrace", "unshare", "mount", "chroot", "bpf", "keyctl")}
RUN_CHECKS = {"overhead", "memory_limit", "cpu_time_limit", "cpu_kill_latency", "wall_time_limit",
              "pids_limit", "output_limit", *KILLS, "no_fork_in_run_phase", "no_sockets", "x32_abi_blocked", "io_uring_blocked",
              "ioctl_high_bits_blocked", "no_capabilities", "default_action_denies_unlisted",
              "filesystem_isolation"}
COMPILE_CHECKS = {*(f"compile_{k}" for k in KILLS), "compile_no_sockets",
                  "compile_x32_abi_blocked", "compile_io_uring_blocked", "compile_ioctl_high_bits_blocked",
                  "compile_no_capabilities", "compile_default_action_denies_unlisted",
                  "compile_filesystem_isolation", "compile_fork_bounded"}
SMOKE_CHECKS = {f"smoke_{language}" for language in
                ("python", "cpp", "java", "c", "go", "javascript", "rust")}
ACCEPTED = python_job("def f():\n    return 42\n")


def failing(report):
    return {c["name"] for c in report["checks"] if not c["ok"]}


class ExecutorCase(unittest.TestCase):
    docker_args = ()

    @classmethod
    def setUpClass(cls):
        cls.executor = ExecutorContainer(docker_args=cls.docker_args, require_ready=False).__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.executor.__exit__()

    def assertRefused(self):
        response = self.executor.run_job(**ACCEPTED)
        self.assertEqual(response["status"], "NOT_READY", response)
        self.assertIn("not ready", response["error"])


class TestHealthyExecutor(ExecutorCase):
    # Short, so a repeat lands within the test.
    docker_args = ("-e", "SELF_TEST_INTERVAL_S=5")

    def test_every_check_passes_or_is_not_applicable(self):
        report = self.executor.ready()
        self.assertTrue(report["ready"], failing(report))
        self.assertTrue(report["ran_at"])
        self.assertEqual({c["name"] for c in report["checks"]}, RUN_CHECKS | COMPILE_CHECKS | SMOKE_CHECKS)
        for check in report["checks"]:
            with self.subTest(check=check["name"]):
                self.assertTrue(check["ok"], check)
                if check.get("not_applicable"):
                    self.assertNotIn(check["name"], SMOKE_CHECKS | {"overhead", "no_fork_in_run_phase"})

    def test_the_self_test_repeats_without_disturbing_jobs(self):
        first = self.executor.ready()["ran_at"]
        deadline = time.monotonic() + 300
        verdicts = []
        # Jobs back to back, so the next self-test comes due while one is in flight.
        while self.executor.ready()["ran_at"] == first:
            self.assertLess(time.monotonic(), deadline, "the self-test did not repeat")
            verdicts.append(self.executor.run_job(**ACCEPTED)["report"]["status_code"])
        verdicts.append(self.executor.run_job(**ACCEPTED)["report"]["status_code"])
        self.assertEqual(set(verdicts), {"ACC"})
        self.assertTrue(self.executor.ready()["ready"])


class TestWeakenedRunPolicy(ExecutorCase):
    """fork allowed and the default action ALLOW, in the run phase only."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "sandbox", "run.kafel")) as f:
            policy = f.read()
        weakened = (policy.replace("ERRNO(11) { fork, vfork, clone }", "ALLOW { fork, vfork, clone }")
                          .replace("\nDEFAULT ERRNO(38)", "\nDEFAULT ALLOW"))
        cls.policy_dir = tempfile.mkdtemp(prefix="policy-")
        path = os.path.join(cls.policy_dir, "run.kafel")
        with open(path, "w") as f:
            f.write(weakened)
        os.chmod(cls.policy_dir, 0o755)
        os.chmod(path, 0o644)
        cls.docker_args = ("-v", f"{path}:/opt/executor/sandbox/run.kafel:ro")
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        os.unlink(os.path.join(cls.policy_dir, "run.kafel"))
        os.rmdir(cls.policy_dir)

    def test_the_matching_checks_fail_and_the_executor_is_not_ready(self):
        report = self.executor.ready()
        self.assertFalse(report["ready"])
        # Exactly these: the policy loaded (every other run check passed) and
        # compile.kafel is intact.
        self.assertEqual(failing(report), {"no_fork_in_run_phase", "default_action_denies_unlisted"})

    def test_jobs_are_refused(self):
        self.assertRefused()


class TestMissingToolchain(ExecutorCase):
    docker_args = ("-e", "JAVA_PATH=/opt/missing/bin/java")

    def test_the_languages_smoke_test_fails_and_the_executor_is_not_ready(self):
        report = self.executor.ready()
        self.assertFalse(report["ready"])
        self.assertEqual(failing(report), {"smoke_java"})

    def test_jobs_are_refused(self):
        self.assertRefused()


if __name__ == "__main__":
    unittest.main()
