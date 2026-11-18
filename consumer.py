"""
Consumer — the trusted, host-side half of the worker (ADR-0001).

Takes jobs from the queue only while a slot is free and ready, hands each to
its slot's executor over the run_job socket protocol (executor.py), publishes
the result, and acks. It holds the Redis credentials and runs no judging code:
everything Redis lives in RedisTransport, everything verdict in the executor.
This module is the control flow: readiness, liveness, slots, in-flight
keep-alive, draining, shutdown.

Readiness: every heartbeat_interval the consumer asks each slot's executor
`ready` (its latest self-test). Only ready slots get work, and the heartbeat
is refreshed only while at least one slot is ready. A slot whose executor
fails a job counts as not ready until it next answers ready, so a dead or
restarting executor can't drain the queue into unacked jobs.

At-least-once: a job is acked only after its result is published. A publish
failure, or an executor that dies, can't be reached, answers nonsense or
refuses the job as not ready, leaves the job unacked, and XAUTOCLAIM
redelivers it. Its third delivery is published FAILED, "retries exhausted"
(RedisTransport).
"""
import asyncio
import dataclasses
import json
import logging
import signal
import time

from config import WorkerConfig
from models import ExecutionRequest, RejectedEntry
from redis_io import RedisTransport

logger = logging.getLogger(__name__)

# One report: up to 50 test cases echoing their input and expected output (48 MiB
# at most) plus capped stdout and stderr (25 MiB), JSON-escaped at up to 2x.
# ponytail: up to 256 MiB buffered per slot.
MAX_RESPONSE_BYTES = 256 * 1024 * 1024
# `ready` is answered without waiting for a job, so a slow answer means a sick
# executor. It delays the beat, so it stays well inside the heartbeat TTL.
READY_TIMEOUT_S = 2


async def ask_executor(socket_path: str, message: dict) -> dict:
    """One request to the executor at socket_path; its one-line JSON response."""
    reader, writer = await asyncio.open_unix_connection(socket_path, limit=MAX_RESPONSE_BYTES)
    try:
        writer.write(json.dumps(message).encode() + b"\n")
        await writer.drain()
        line = await reader.readline()
    finally:
        writer.close()
    if not line:
        raise ConnectionError(f"executor at {socket_path} closed without answering")
    return json.loads(line)


async def run_job(socket_path: str, job: ExecutionRequest) -> dict:
    """Send one job to the executor at socket_path; return its response."""
    fields = dataclasses.asdict(job)
    del fields["stream_id"]          # Redis bookkeeping stays on the consumer's side
    response = await ask_executor(socket_path, {"method": "run_job", "job": fields})
    if response.get("status") == "NOT_READY":    # nothing ran: an executor failure, not a result
        raise ConnectionError(f"executor at {socket_path} refused the job: {response.get('error')}")
    return response


async def is_ready(socket_path: str) -> bool:
    """Whether the executor at socket_path answers `ready` with a passing self-test."""
    try:
        report = await asyncio.wait_for(ask_executor(socket_path, {"method": "ready"}), READY_TIMEOUT_S)
        return report.get("ready") is True
    except Exception as e:
        logger.debug("Executor at %s did not answer ready: %s", socket_path, e)
        return False


class Consumer:
    def __init__(self, config: WorkerConfig):
        self.config = config
        self.transport = RedisTransport(config.redis)
        self._running = True
        self._free_slots = list(config.executor_sockets)   # one executor socket per slot
        self._ready_slots: set = set()     # slots whose executor last answered ready
        self._failed_slots: set = set()    # slots whose executor failed since the last check began
        self._active_tasks: set = set()
        self._last_check = float("-inf")   # -inf so the first cycle always checks

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
                await self._check_slots_and_beat()

                slots = [s for s in self._free_slots if s in self._ready_slots]
                if not slots:
                    # Leave jobs in the stream for other workers. Waking every
                    # block_ms keeps the beat cycle validate_config assumes.
                    if self._active_tasks:
                        await asyncio.wait(self._active_tasks, timeout=self.config.redis.block_ms / 1000,
                                           return_when=asyncio.FIRST_COMPLETED)
                    else:       # every free slot's executor is not ready
                        await asyncio.sleep(self.config.redis.block_ms / 1000)
                    continue

                jobs, rejected = await loop.run_in_executor(None, self.transport.consume, len(slots))
                consecutive_errors = 0

                for entry in rejected:
                    self._reject(entry)

                for job, slot in zip(jobs, slots):
                    self._free_slots.remove(slot)
                    task = asyncio.create_task(self._handle_job(job, slot))
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
                if slot in self._ready_slots:
                    logger.warning("Executor at %s failed; no work until it reports ready", slot)
                self._ready_slots.discard(slot)
                self._failed_slots.add(slot)    # an answer already in flight doesn't re-admit it
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

    def _reject(self, entry: RejectedEntry) -> None:
        """Publish FAILED for an entry that won't be run, then ack it (unacked if the publish fails)."""
        if entry.job_id:
            try:
                self.transport.publish(entry.job_id, "FAILED", error=entry.error)
                logger.info("[%s] Pushed FAILED (%s)", entry.job_id, entry.error)
            except Exception as e:
                logger.error("[%s] Failed to push FAILED (%s): %s", entry.job_id, entry.error, e)
                return
        else:
            logger.warning("Entry with no job_id — cannot report (%s)", entry.error)
        self.transport.ack(entry.stream_id, entry.job_id or "")

    async def _check_slots_and_beat(self) -> None:
        """
        At most once per heartbeat_interval: ask every slot's executor whether
        it is ready, then refresh the shared liveness key if any is. With none
        ready the key is left to expire, never deleted. A failed beat is retried
        on the next loop cycle.
        """
        if time.monotonic() - self._last_check < self.config.redis.heartbeat_interval:
            return
        self._last_check = time.monotonic()
        self._failed_slots.clear()
        slots = self.config.executor_sockets
        answers = await asyncio.gather(*(is_ready(s) for s in slots))
        ready = {s for s, ok in zip(slots, answers) if ok} - self._failed_slots
        for s in ready - self._ready_slots:
            logger.info("Executor at %s is ready", s)
        for s in self._ready_slots - ready:
            logger.warning("Executor at %s is not ready; it gets no work", s)
        self._ready_slots = ready
        if not ready:
            return
        try:
            await asyncio.get_running_loop().run_in_executor(None, self.transport.beat)
        except Exception as e:
            logger.warning("Liveness heartbeat failed: %s", e)
            self._last_check = float("-inf")

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
