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
from tests.stub_executor import StubExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def b64(s): return base64.b64encode(s.encode()).decode()


def job_body(job_id):
    return json.dumps({
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

    async def asyncSetUp(self):
        self.config, sockets_dir = seam_b_config(self.slots)
        self.addCleanup(shutil.rmtree, sockets_dir, True)
        self.r = redis_for(self.config)
        self.addCleanup(self.r.close)
        self.addCleanup(self.r.delete, self.config.redis.stream_key,
                        self.config.redis.result_stream_key, self.config.redis.heartbeat_key)
        self.stubs = []
        for path in self.config.executor_sockets if self.stubbed else ():
            stub = await StubExecutor(path).__aenter__()
            self.addAsyncCleanup(stub.__aexit__)
            self.stubs.append(stub)
        self.consumer = Consumer(self.config)
        runner = asyncio.create_task(self.consumer.start())

        async def stop():
            self.consumer._handle_shutdown()
            await asyncio.wait_for(runner, 10)
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


class TestExecutorUnreachable(ConsumerCase):
    stubbed = False

    async def test_an_unreachable_executor_leaves_the_job_unacked_and_takes_no_more(self):
        for i in range(3):
            self.submit(job_body(f"job-no-executor-{i}"))
        await until(lambda: self.pending() == 1)
        await asyncio.sleep(1)          # many block_ms cycles: the failed slot sits out

        self.assertEqual(self.pending(), 1)
        self.assertEqual(self.r.xlen(self.config.redis.stream_key), 3)
        self.assertFalse(self.r.exists(self.config.redis.result_stream_key))


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
