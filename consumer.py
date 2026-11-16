"""
Consumer — the trusted, host-side half of the worker (ADR-0001).

Takes jobs from the queue only while a slot is free, hands each to its slot's
executor over the run_job socket protocol (executor.py), publishes the
result, and acks. It holds the Redis credentials and runs no judging code:
everything Redis lives in RedisTransport, everything verdict in the executor.
This module is the control flow: liveness, slots, in-flight keep-alive,
draining, shutdown.

At-least-once: a job is acked only after its result is published. A publish
failure, or an executor that can't be reached or answers nonsense, leaves the
job unacked, and XAUTOCLAIM redelivers it. So does one refused by an executor
whose self-test failed. A slot whose executor failed or refused sits out
SLOT_RETRY_S, so a dead executor can't drain the queue into unacked jobs.
"""
import asyncio
import dataclasses
import json
import logging
import signal
import time

from config import WorkerConfig
from models import ExecutionRequest, MalformedMessage
from redis_io import RedisTransport

logger = logging.getLogger(__name__)

# One report: up to 50 test cases, each echoing its input plus capped stdout
# and stderr.
# ponytail: up to 256 MiB buffered per slot; size it from ticket 15's input caps.
MAX_RESPONSE_BYTES = 256 * 1024 * 1024
# ponytail: a failed executor's slot just sits out this long; ticket 14 gates
# slots on the executor's `ready` answer instead.
SLOT_RETRY_S = 30


async def run_job(socket_path: str, job: ExecutionRequest) -> dict:
    """Send one job to the executor at socket_path; return its response."""
    reader, writer = await asyncio.open_unix_connection(socket_path, limit=MAX_RESPONSE_BYTES)
    try:
        fields = dataclasses.asdict(job)
        del fields["stream_id"]          # Redis bookkeeping stays on the consumer's side
        message = {"method": "run_job", "job": fields}
        writer.write(json.dumps(message).encode() + b"\n")
        await writer.drain()
        line = await reader.readline()
    finally:
        writer.close()
    if not line:
        raise ConnectionError(f"executor at {socket_path} closed without answering")
    response = json.loads(line)
    if response.get("status") == "NOT_READY":    # nothing ran: an executor failure, not a result
        raise ConnectionError(f"executor at {socket_path} refused the job: {response.get('error')}")
    return response


class Consumer:
    def __init__(self, config: WorkerConfig):
        self.config = config
        self.transport = RedisTransport(config.redis)
        self._running = True
        self._free_slots = list(config.executor_sockets)   # one executor socket per slot
        self._active_tasks: set = set()
        self._last_beat = float("-inf")    # -inf so the first cycle always beats

    async def start(self) -> None:
        logger.info("Consumer starting (slots=%d, consumer=%s)",
                    len(self._free_slots), self.config.redis.consumer_name)
        self.transport.ensure_group()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_shutdown)

        consecutive_errors = 0
        while self._running:
            try:
                await self._maybe_beat()

                if not self._free_slots:
                    # Leave jobs in the stream for other workers. Waking every
                    # block_ms keeps the beat cycle validate_config assumes.
                    if self._active_tasks:
                        await asyncio.wait(self._active_tasks, timeout=self.config.redis.block_ms / 1000,
                                           return_when=asyncio.FIRST_COMPLETED)
                    else:       # every slot is sitting out after an executor failure
                        await asyncio.sleep(self.config.redis.block_ms / 1000)
                    continue

                jobs, malformed = await loop.run_in_executor(
                    None, self.transport.consume, len(self._free_slots))
                consecutive_errors = 0

                for bad in malformed:
                    self._handle_malformed(bad)

                for job in jobs:
                    task = asyncio.create_task(self._handle_job(job, self._free_slots.pop()))
                    self._active_tasks.add(task)
                    task.add_done_callback(self._active_tasks.discard)

            except Exception as e:
                consecutive_errors += 1
                logger.error("Consume loop error (%d/%d): %s",
                             consecutive_errors, self.config.max_consecutive_errors, e)
                if consecutive_errors >= self.config.max_consecutive_errors:
                    logger.critical("Too many consecutive errors (%d), shutting down", consecutive_errors)
                    break
                await asyncio.sleep(min(2 ** consecutive_errors, 32))   # 2,4,8,16,32s

        await self._drain()
        self.transport.close()

    async def _handle_job(self, job: ExecutionRequest, slot: str) -> None:
        """
        Run one job on the slot's executor, holding the slot until this task
        ends. A keep-alive task touches the entry for the job's whole lifetime
        so a long job isn't duplicated.
        """
        job_id = job.job_id
        keepalive = asyncio.create_task(self._keepalive_loop(job))
        loop = asyncio.get_running_loop()
        executor_failed = False
        try:
            try:
                response = await run_job(slot, job)
            except Exception:
                executor_failed = True
                raise
            await loop.run_in_executor(None, self._publish, job_id, response)
            # Ack only after a successful publish (skip-on-failure => redelivery).
            await loop.run_in_executor(None, self.transport.ack, job.stream_id, job_id)
        except Exception as e:
            logger.error("[%s] Failed: %s", job_id, e)   # executor/publish/ack — leave unacked
        finally:
            keepalive.cancel()
            if executor_failed:
                logger.warning("Executor at %s failed; slot sits out %ds", slot, SLOT_RETRY_S)
                loop.call_later(SLOT_RETRY_S, self._free_slots.append, slot)
            else:
                self._free_slots.append(slot)

    def _publish(self, job_id: str, response: dict) -> None:
        """COMPLETED with the executor's report; FAILED with its error for a worker failure."""
        status = response.get("status")
        if status == "COMPLETED":
            logger.info("[%s] Pushing COMPLETED (status_code=%s)", job_id, response["report"].get("status_code"))
            self.transport.publish(job_id, "COMPLETED", json.dumps(response["report"], indent=2))
        elif status == "FAILED":
            logger.info("[%s] Pushing FAILED (%s)", job_id, response.get("error"))
            self.transport.publish(job_id, "FAILED", error=response.get("error"))
        else:
            raise ValueError(f"executor answered with status {status!r}")

    def _handle_malformed(self, bad: MalformedMessage) -> None:
        if bad.job_id:
            try:
                self.transport.publish(bad.job_id, "FAILED", error=f"malformed job: {bad.reason}")
                logger.info("[%s] Malformed entry — pushed FAILED", bad.job_id)
            except Exception as e:
                logger.error("[%s] Failed to push FAILED for malformed entry: %s", bad.job_id, e)
        else:
            logger.warning("Malformed entry with no job_id — cannot report (reason: %s)", bad.reason)
        self.transport.ack(bad.stream_id, bad.job_id or "")

    async def _maybe_beat(self) -> None:
        """Refresh the shared liveness key, at most once per heartbeat_interval. Best effort."""
        if time.monotonic() - self._last_beat < self.config.redis.heartbeat_interval:
            return
        try:
            await asyncio.get_running_loop().run_in_executor(None, self.transport.beat)
            self._last_beat = time.monotonic()
        except Exception as e:
            logger.warning("Liveness heartbeat failed: %s", e)

    async def _keepalive_loop(self, job: ExecutionRequest) -> None:
        """Touch the in-flight entry periodically (a third of the autoclaim threshold)."""
        interval = max(self.config.redis.autoclaim_min_idle_ms / 3000.0, 2.0)
        try:
            while True:
                await asyncio.sleep(interval)
                await asyncio.get_running_loop().run_in_executor(
                    None, self.transport.touch, job.stream_id)
        except asyncio.CancelledError:
            pass

    def _handle_shutdown(self) -> None:
        logger.info("Shutdown signal received, stopping after current tasks...")
        self._running = False

    async def _drain(self) -> None:
        if self._active_tasks:
            logger.info("Waiting for %d active task(s) to finish...", len(self._active_tasks))
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
            logger.info("All tasks finished")
