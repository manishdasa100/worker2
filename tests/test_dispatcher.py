"""
The dispatcher's read loop, with the transport and judge faked (no Redis, no jails).
    python3 -m unittest tests.test_dispatcher -v   (from the worker2 dir)
"""
import asyncio
import os
import sys
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import WorkerConfig
from dispatcher import Dispatcher


class FakeTransport:
    """Records what the dispatcher asks of the queue; `batches` scripts what each read returns."""

    def __init__(self, batches):
        self.batches = list(batches)
        self.reads = []
        self.beats = 0
        self.touched = []

    def ensure_group(self): pass
    def ack(self, stream_id, job_id=""): pass
    def close(self): pass
    def beat(self): self.beats += 1
    def touch(self, stream_id): self.touched.append(stream_id)

    def consume(self, max_entries):
        self.reads.append(max_entries)
        if self.batches:
            return self.batches.pop(0), []
        time.sleep(0.005)       # an empty blocking read
        return [], []


class FakeJudge:
    """Holds each job in its slot until the test finishes it."""

    def __init__(self):
        self.running = {}

    async def warmup(self): pass

    async def judge(self, request):
        done = self.running[request.job_id] = asyncio.Event()
        await done.wait()
        return SimpleNamespace(execution_id=request.job_id)

    def finish(self, job_id):
        self.running[job_id].set()


def jobs(*job_ids):
    return [SimpleNamespace(job_id=j, stream_id=f"{j}-0") for j in job_ids]


async def until(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.005)


class TestReadLoop(unittest.IsolatedAsyncioTestCase):
    async def _start(self, slots, batches):
        config = WorkerConfig()
        config.redis.host = ""          # _publish becomes a no-op
        config.redis.block_ms = 10
        config.redis.heartbeat_interval = 0
        config.redis.autoclaim_min_idle_ms = 0     # keep-alive at its 2 s floor
        config.execution.max_concurrent = slots
        dispatcher = Dispatcher(config)
        dispatcher.transport = FakeTransport(batches)
        dispatcher.judge = FakeJudge()
        runner = asyncio.create_task(dispatcher.start())

        async def stop():
            dispatcher._handle_shutdown()
            for done in dispatcher.judge.running.values():
                done.set()
            await asyncio.wait_for(runner, 5)
        self.addAsyncCleanup(stop)
        return dispatcher.transport, dispatcher.judge

    async def test_a_read_asks_for_exactly_the_free_slots(self):
        transport, judge = await self._start(slots=3, batches=[jobs("a"), jobs("b")])
        await until(lambda: len(transport.reads) >= 3)
        self.assertEqual(transport.reads[:3], [3, 2, 1])

        judge.finish("a")
        await until(lambda: len(transport.reads) > 3 and transport.reads[-1] == 2)

    async def test_no_read_while_every_slot_is_busy(self):
        transport, judge = await self._start(slots=2, batches=[jobs("a", "b"), jobs("c")])
        await until(lambda: len(judge.running) == 2)
        await asyncio.sleep(0.1)        # many block_ms cycles
        self.assertEqual(transport.reads, [2])

        judge.finish("a")
        await until(lambda: "c" in judge.running)
        self.assertEqual(transport.reads, [2, 1])

    async def test_heartbeat_and_keepalive_run_while_every_slot_is_busy(self):
        transport, judge = await self._start(slots=1, batches=[jobs("a")])
        await until(lambda: "a" in judge.running)
        beats = transport.beats

        await until(lambda: transport.beats > beats + 3 and "a-0" in transport.touched)
        self.assertEqual(transport.reads, [1])


if __name__ == "__main__":
    unittest.main()
