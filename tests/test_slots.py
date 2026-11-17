"""
Seam A: two slots' executors, each pinned to its own core with its own jail uid,
as in production (core 0 stays with the consumer).
    .venv/bin/python -m unittest tests.test_slots -v   (needs Docker and 3 cores; see executor_harness)
"""
import os
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.executor_harness import ExecutorContainer
from tests.test_executor import C_DRIVER, job

SPIN = ("int f(void) { volatile unsigned long s = 0;"
        " for (unsigned long i = 0; i < 4000000000UL; i++) s += i; return 42; }\n")
TOLERANCE = 0.15
ROUNDS = 3


def spin():
    return job("c", SPIN, C_DRIVER, time_limit=5000)


def timed(executor, job):
    start = time.monotonic()
    response = executor.run_job(**job)
    return response, time.monotonic() - start


class TestTwoPinnedSlots(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.cpu_count() < 3:
            raise unittest.SkipTest("needs cores 1 and 2 for the slots")
        with ThreadPoolExecutor(2) as pool:      # each start runs a 1–2 minute self-test
            starting = [pool.submit(ExecutorContainer(cpu=slot, docker_args=("-e", f"JAIL_UID={61000 + slot}")).__enter__)
                        for slot in (1, 2)]
            cls.executors = []
            for future in starting:
                if future.exception() is None:
                    cls.executors.append(future.result())
                    cls.addClassCleanup(cls.executors[-1].__exit__)
            for future in starting:
                future.result()

    def test_the_same_job_on_both_slots_at_once_runs_concurrently_in_equal_time(self):
        # Summed over rounds: a single run's CPU time is noisy on a shared host.
        solo_wall, pair_wall, runtimes = 0, 0, [0, 0]
        for _ in range(ROUNDS):
            solo, wall = timed(self.executors[0], spin())
            self.assertEqual(solo["report"]["status_code"], "ACC", solo)
            solo_wall += wall
            with ThreadPoolExecutor(2) as pool:
                both = list(pool.map(lambda executor: timed(executor, spin()), self.executors))
            for i, (response, wall) in enumerate(both):
                self.assertEqual(response["report"]["status_code"], "ACC", response)
                runtimes[i] += response["report"]["runtime_ms"]
            pair_wall += max(wall for _, wall in both)

        # Sharing one core, each would take about twice as long.
        self.assertLess(pair_wall, 1.5 * solo_wall, (solo_wall, pair_wall))
        self.assertLessEqual(abs(runtimes[0] - runtimes[1]), TOLERANCE * max(runtimes), runtimes)


if __name__ == "__main__":
    unittest.main()
