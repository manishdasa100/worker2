"""
Seam B: the consumer against real Redis, playing the backend on suffixed keys,
with stub executors in place of real ones.
    .venv/bin/python -m unittest tests.test_consumer -v   (needs .env.dev pointing at a Redis)
"""
import asyncio
import base64
import dataclasses
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import redis as redis_client
from config import load_config
from consumer import Consumer
from redis_io import RedisTransport
from tests.stub_executor import StubExecutor, accepted, crash

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def b64(s): return base64.b64encode(s.encode()).decode()


def job_body(job_id, **extra):
    return json.dumps({**extra,
        "jobId": job_id, "language": "python",
        "userCode": b64("def add(a,b):\n    return a+b\n"),
        "driverCode": b64("from solution import add\na,b=map(int,input().split())\nprint(add(a,b))\n"),
        "task": "SUBMIT_CODE", "timeLimit": 2000, "memoryLimit": 128,
        "testCases": [{"input": "3 4", "expectedOutput": "7"}],
    })


def seam_b_config(slots=1):
    config = load_config(env_file=os.path.join(ROOT, ".env.dev"))
    suffix = f":seam-b:{os.getpid()}:{time.monotonic_ns()}"
    config.redis.stream_key += suffix
    config.redis.consumer_group = "workers-test"
    config.redis.consumer_name = "consumer-test"
    config.redis.result_stream_key += suffix
    config.redis.heartbeat_key += suffix
    config.redis.block_ms = 100
    config.redis.autoclaim_min_idle_ms = 60000
    config.redis.heartbeat_interval = 0             # ask executors and beat every loop cycle
    config.redis.heartbeat_ttl = 2
    sockets_dir = tempfile.mkdtemp(prefix="seam-b-")    # short: AF_UNIX paths max out at 108 bytes
    config.executor_sockets = [os.path.join(sockets_dir, f"slot{i}.sock") for i in range(slots)]
    return config, sockets_dir


def redis_for(config):
    return redis_client.Redis(host=config.redis.host, port=config.redis.port,
                              username=config.redis.username or None,
                              password=config.redis.password or None, decode_responses=True)


class ConsumerCase(unittest.IsolatedAsyncioTestCase):
    """Runs a consumer on throwaway keys against `slots` stub executors (none listening if not `stubbed`)."""
    slots = 1
    stubbed = True
    unready = ()                        # indexes of stubs that start out not ready
    autoclaim_min_idle_ms = 60000

    async def asyncSetUp(self):
        self.config, sockets_dir = seam_b_config(self.slots)
        self.config.redis.autoclaim_min_idle_ms = self.autoclaim_min_idle_ms
        self.addCleanup(shutil.rmtree, sockets_dir, True)
        self.r = redis_for(self.config)
        self.addCleanup(self.r.close)
        self.addCleanup(self.r.delete, self.config.redis.stream_key,
                        self.config.redis.result_stream_key, self.config.redis.heartbeat_key)
        self.stubs = []
        for i, path in enumerate(self.config.executor_sockets if self.stubbed else ()):
            stub = await StubExecutor(path, ready=i not in self.unready).__aenter__()
            self.addAsyncCleanup(stub.__aexit__)
            self.stubs.append(stub)
        self.consumer = Consumer(self.config)
        self.runner = asyncio.create_task(self.consumer.start())

        async def stop():
            self.consumer._handle_shutdown()
            await asyncio.wait_for(self.runner, 10)
        self.addAsyncCleanup(stop)
        await until(lambda: self.r.exists(self.config.redis.stream_key))   # group created

    def submit(self, body) -> str:
        return self.r.xadd(self.config.redis.stream_key, {"body": body})

    async def result(self, job_id, timeout=10.0) -> dict:
        found = []

        def published():
            found[:] = [json.loads(f["body"]) for _, f in self.r.xrange(self.config.redis.result_stream_key)
                        if json.loads(f["body"])["job_id"] == job_id]
            return found
        await until(published, timeout)
        return found[0]

    def pending(self) -> int:
        return self.r.xpending(self.config.redis.stream_key, self.config.redis.consumer_group)["pending"]

    def beating(self) -> bool:
        return bool(self.r.exists(self.config.redis.heartbeat_key))


async def until(condition, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.02)


class TestPublishing(ConsumerCase):
    async def test_a_job_is_run_on_the_executor_and_published_completed(self):
        self.submit(job_body("job-ok"))
        result = await self.result("job-ok")

        self.assertEqual({k: v for k, v in result.items() if k != "execution_report"},
                         {"job_id": "job-ok", "status": "COMPLETED", "worker_type": "GVISOR_WORKER"})
        self.assertEqual(json.loads(result["execution_report"])["status_code"], "ACC")
        sent = self.stubs[0].jobs[0]
        self.assertEqual((sent["job_id"], sent["user_code"]), ("job-ok", "def add(a,b):\n    return a+b\n"))
        self.assertNotIn("stream_id", sent)                 # Redis stays on the consumer's side
        await until(lambda: self.pending() == 0 and self.r.xlen(self.config.redis.stream_key) == 0)
        self.assertTrue(self.r.exists(self.config.redis.heartbeat_key))

    async def test_the_checker_reaches_the_executor_and_per_test_fields_reach_the_backend(self):
        outcome = {"index": 0, "status": "FAILED", "cpu_ms": 7, "reason": "answer line differs"}
        self.stubs[0].reply = lambda job: {"status": "COMPLETED", "report": {
            "execution_id": job["job_id"], "status_code": "WA", "failed_testcase": outcome}}
        checker = {"mode": "float", "absEpsilon": 0.001}
        self.submit(job_body("job-checker", checker=checker))
        result = await self.result("job-checker")

        self.assertEqual(self.stubs[0].jobs[0]["checker"], checker)
        self.assertEqual(json.loads(result["execution_report"])["failed_testcase"], outcome)

    async def test_an_executor_worker_failure_is_published_failed_with_its_error(self):
        self.stubs[0].reply = lambda job: {"status": "FAILED", "error": "Language 'cobol' is not supported"}
        self.submit(job_body("job-failed"))
        result = await self.result("job-failed")

        self.assertEqual(result, {"job_id": "job-failed", "status": "FAILED", "worker_type": "GVISOR_WORKER",
                                  "error": "Language 'cobol' is not supported"})
        await until(lambda: self.pending() == 0)

    async def test_a_malformed_entry_is_published_failed_with_an_error(self):
        self.submit(json.dumps({"jobId": "job-malformed", "language": "python"}))
        result = await self.result("job-malformed")

        self.assertEqual(result["status"], "FAILED")
        self.assertIn("malformed", result["error"])
        self.assertEqual(self.stubs[0].jobs, [])
        await until(lambda: self.pending() == 0)


class TestAtLeastOnce(ConsumerCase):
    async def test_a_publish_failure_leaves_the_job_unacked(self):
        self.r.set(self.config.redis.result_stream_key, "not a stream")   # XADD fails: WRONGTYPE
        self.submit(job_body("job-unpublished"))
        await until(lambda: self.stubs[0].jobs)
        await asyncio.sleep(4)          # publish retries back off 1 s + 2 s

        self.assertEqual(self.pending(), 1)
        self.assertEqual(self.r.xlen(self.config.redis.stream_key), 1)


class TestOneSlotNotReady(ConsumerCase):
    slots = 2
    unready = (1,)

    async def test_only_slots_whose_executor_reports_ready_get_work(self):
        for i in range(3):
            self.submit(job_body(f"job-ready-{i}"))
        for i in range(3):
            self.assertEqual((await self.result(f"job-ready-{i}"))["status"], "COMPLETED")

        self.assertEqual(len(self.stubs[0].jobs), 3)
        self.assertEqual(self.stubs[1].jobs, [])
        self.assertTrue(self.beating())


class TestReadiness(ConsumerCase):
    slots = 2

    async def test_with_no_slot_ready_the_heartbeat_lapses_and_no_job_is_read(self):
        await until(self.beating)
        for stub in self.stubs:
            stub.ready = False
        await asyncio.sleep(0.3)        # a cycle in flight may still read
        self.submit(job_body("job-waits"))
        await until(lambda: not self.beating(), timeout=5)     # heartbeat_ttl 2 s
        self.assertEqual(self.pending(), 0)
        self.assertEqual([j for stub in self.stubs for j in stub.jobs], [])

        self.stubs[1].ready = True
        self.assertEqual((await self.result("job-waits"))["status"], "COMPLETED")
        self.assertTrue(self.beating())
        self.assertEqual(len(self.stubs[1].jobs), 1)

    async def test_a_job_refused_as_not_ready_is_left_unacked(self):
        for stub in self.stubs:
            stub.reply = lambda job: {"status": "NOT_READY", "error": "executor not ready: no_sockets"}
        self.submit(job_body("job-refused"))
        await until(lambda: any(stub.jobs for stub in self.stubs))
        await asyncio.sleep(0.5)

        self.assertEqual(self.pending(), 1)
        self.assertFalse(self.r.exists(self.config.redis.result_stream_key))


class TestCrashedExecutor(ConsumerCase):
    autoclaim_min_idle_ms = 300

    async def test_a_slot_whose_executor_crashed_takes_no_work_until_it_reports_ready(self):
        def crash_and_restart(job):
            self.stubs[0].ready = False         # restarting: self-testing again
            crash(job)
        self.stubs[0].reply = crash_and_restart
        self.submit(job_body("job-crashed"))
        await until(lambda: self.stubs[0].jobs)
        self.stubs[0].reply = accepted
        self.submit(job_body("job-next"))
        await asyncio.sleep(1)                  # many cycles, past the crashed job's min idle

        self.assertEqual(len(self.stubs[0].jobs), 1)
        self.assertEqual(self.pending(), 1)

        self.stubs[0].ready = True
        for job_id in ("job-crashed", "job-next"):
            self.assertEqual((await self.result(job_id))["status"], "COMPLETED")


class TestExecutorUnreachable(ConsumerCase):
    stubbed = False

    async def test_no_job_is_read_and_there_is_no_heartbeat(self):
        self.submit(job_body("job-no-executor"))
        await asyncio.sleep(1)          # many block_ms cycles

        self.assertEqual(self.pending(), 0)
        self.assertFalse(self.beating())


class TestDeliveryLimit(ConsumerCase):
    autoclaim_min_idle_ms = 300         # redeliver a crashed job quickly

    async def test_a_job_that_crashes_its_executor_every_time_fails_on_its_third_delivery(self):
        self.stubs[0].reply = crash
        self.submit(job_body("job-crashes"))
        result = await self.result("job-crashes")

        self.assertEqual(result, {"job_id": "job-crashes", "status": "FAILED", "worker_type": "GVISOR_WORKER",
                                  "error": "retries exhausted"})
        self.assertEqual(len(self.stubs[0].jobs), 2)        # the third delivery is not run
        await until(lambda: self.pending() == 0 and self.r.xlen(self.config.redis.stream_key) == 0)

    async def test_a_job_whose_executor_dies_mid_run_completes_on_redelivery(self):
        replies = [crash, accepted]
        self.stubs[0].reply = lambda job: replies.pop(0)(job)
        self.submit(job_body("job-redelivered"))
        result = await self.result("job-redelivered")

        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(len(self.stubs[0].jobs), 2)
        await until(lambda: self.pending() == 0)


class TestDrain(ConsumerCase):
    slots = 2

    async def test_sigterm_publishes_the_jobs_in_flight_then_exits_without_reading_more(self):
        async def slow(job):
            await asyncio.sleep(1)
            return accepted(job)
        for stub in self.stubs:
            stub.reply = slow
        for i in range(4):
            self.submit(job_body(f"job-drain-{i}"))
        await until(lambda: all(stub.jobs for stub in self.stubs))

        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.wait_for(self.runner, 10)

        ran = [job["job_id"] for stub in self.stubs for job in stub.jobs]
        self.assertEqual(len(ran), 2)
        for job_id in ran:
            self.assertEqual((await self.result(job_id, timeout=0))["status"], "COMPLETED")
        self.assertEqual(self.pending(), 0)
        self.assertEqual(self.r.xlen(self.config.redis.stream_key), 2)      # left for other workers


class TestFreeSlots(ConsumerCase):
    slots = 2

    async def test_a_burst_stays_in_the_stream_while_every_slot_is_busy(self):
        async def slow(job):
            await asyncio.sleep(0.5)
            return {"status": "FAILED", "error": "slow stub"}
        for stub in self.stubs:
            stub.reply = slow
        burst = 6
        for i in range(burst):
            self.submit(job_body(f"burst-{i}"))

        most_claimed, unclaimed_when_full = 0, None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and self.r.xlen(self.config.redis.result_stream_key) < burst:
            pending = self.pending()
            most_claimed = max(most_claimed, pending)
            if pending == self.slots and unclaimed_when_full is None:
                unclaimed_when_full = self.r.xlen(self.config.redis.stream_key) - pending
            await asyncio.sleep(0.05)

        self.assertEqual(most_claimed, self.slots)
        self.assertEqual(unclaimed_when_full, burst - self.slots)
        self.assertEqual(self.r.xlen(self.config.redis.result_stream_key), burst)
        self.assertTrue(all(stub.jobs for stub in self.stubs))      # both slots ran jobs


class TestTransportLimits(unittest.TestCase):
    """Reads and reclaims take no more than they are asked for (real Redis, no consumer loop)."""

    def setUp(self):
        self.config, sockets_dir = seam_b_config()
        shutil.rmtree(sockets_dir)
        self.r = redis_for(self.config)
        self.addCleanup(self.r.close)
        self.addCleanup(self.r.delete, self.config.redis.stream_key)

    def transport(self, **changes):
        t = RedisTransport(dataclasses.replace(self.config.redis, **changes))
        self.addCleanup(t.close)
        t.ensure_group()
        return t

    def test_reads_and_reclaims_take_at_most_what_they_ask_for(self):
        reader = self.transport(consumer_name="reader")
        rescuer = self.transport(consumer_name="rescuer", autoclaim_min_idle_ms=0)
        for i in range(5):
            self.submit_raw(f"limit-{i}")

        self.assertEqual(len(reader.consume(2)[0]), 2)
        self.assertEqual(len(reader.consume(1)[0]), 1)
        self.assertEqual(len(rescuer.consume(2)[0]), 2)
        key, group = self.config.redis.stream_key, self.config.redis.consumer_group
        self.assertEqual(self.r.xlen(key) - self.r.xpending(key, group)["pending"], 2)

    def test_reclaim_finds_a_stale_entry_wherever_it_sits_in_the_pending_list(self):
        rescuer = self.transport(consumer_name="rescuer", autoclaim_min_idle_ms=1000)
        key, group = self.config.redis.stream_key, self.config.redis.consumer_group
        ids = [self.submit_raw(f"scan-{i}") for i in range(12)]
        self.r.xreadgroup(group, "other", {key: ">"}, count=12)
        self.assertEqual(rescuer.consume(1)[0], [])     # nothing idle yet; the cursor moves past the first 10

        def only_stale(stale_id):
            time.sleep(1.2)
            self.r.xclaim(key, group, "other", min_idle_time=0, justid=True,
                          message_ids=[i for i in ids if i != stale_id])

        def reclaim():
            return [job.job_id for _ in range(3) for job in rescuer.consume(1)[0]]

        only_stale(ids[0])
        self.assertEqual(reclaim(), ["scan-0"])         # behind the cursor
        only_stale(ids[11])
        self.assertEqual(reclaim(), ["scan-11"])        # behind 11 live ones

    def submit_raw(self, job_id):
        return self.r.xadd(self.config.redis.stream_key, {"body": job_body(job_id)})


class TestConsumerProcess(unittest.TestCase):
    def test_the_consumer_loads_no_judging_code(self):
        loaded = subprocess.run(
            [sys.executable, "-c", "import sys, main; print(' '.join(sys.modules))"],
            cwd=ROOT, check=True, capture_output=True, text=True).stdout.split()
        self.assertFalse({"judge", "sandbox", "cgroups", "calibrate", "languages"} & set(loaded))


if __name__ == "__main__":
    unittest.main()
