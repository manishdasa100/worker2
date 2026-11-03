"""
Dispatcher — the async orchestration loop.

Pulls submissions from the transport, runs each through the judge under a
concurrency semaphore, publishes the result, and acks. Everything Redis lives
in RedisTransport; everything verdict lives in Judge. This module is just the
control flow: liveness, concurrency, in-flight keep-alive, draining, shutdown.

At-least-once: a submission is acked only after its result is published. A
publish failure raises, the ack is skipped, and XAUTOCLAIM redelivers.
"""
import asyncio
import logging
import signal
import time

from cgroups import CgroupDelegation
from config import WorkerConfig
from judge import Judge
from models import ExecutionReport, ExecutionRequest, MalformedMessage, StatusCode
from redis_io import RedisTransport

logger = logging.getLogger(__name__)

# status_codes that mean a worker-level failure (not a user verdict) -> FAILED,
# no report attached. Everything else is a COMPLETED verdict.
WORKER_FAILURE_CODES = (StatusCode.INTERNAL_ERROR, StatusCode.UNSUPPORTED_LANGUAGE)


class Dispatcher:
    def __init__(self, config: WorkerConfig, delegation: CgroupDelegation):
        self.config = config
        self.judge = Judge(config, delegation)
        self.transport = RedisTransport(config.redis)
        self.semaphore = asyncio.Semaphore(config.execution.max_concurrent)
        self._running = True
        self._active_tasks: set = set()
        self._last_activity = 0.0
        self._last_warmup = 0.0
        self._last_beat = float("-inf")    # -inf so the first cycle always beats

    async def start(self) -> None:
        logger.info("Dispatcher starting (max_concurrent=%d, consumer=%s)",
                    self.config.execution.max_concurrent, self.config.redis.consumer_name)
        self.transport.ensure_group()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_shutdown)

        # Warm runtimes once before taking jobs so the first submission runs warm.
        await self.judge.warmup()
        self._last_activity = self._last_warmup = time.monotonic()

        consecutive_errors = 0
        while self._running:
            try:
                await self._maybe_beat()

                requests, malformed = await loop.run_in_executor(None, self.transport.consume)
                consecutive_errors = 0

                for bad in malformed:
                    self._handle_malformed(bad)

                if not requests:
                    await self._maybe_rewarm()
                    continue

                self._last_activity = time.monotonic()
                for request in requests:
                    task = asyncio.create_task(self._handle_request(request))
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

    async def _handle_request(self, request: ExecutionRequest) -> None:
        """
        Judge one submission. A keep-alive task touches the entry for its whole
        lifetime (including semaphore wait) so a long job isn't duplicated.
        """
        job_id = request.job_id
        keepalive = asyncio.create_task(self._keepalive_loop(request))
        loop = asyncio.get_running_loop()
        try:
            async with self.semaphore:
                logger.info("[%s] Acquired execution slot", job_id)
                try:
                    report = await self.judge.judge(request)
                    await loop.run_in_executor(None, self._publish, report)
                    # Ack only after a successful publish (skip-on-failure => redelivery).
                    await loop.run_in_executor(None, self.transport.ack, request.stream_id, job_id)
                except Exception as e:
                    logger.error("[%s] Failed: %s", job_id, e)   # execution/publish/ack — leave unacked
        finally:
            keepalive.cancel()

    def _publish(self, report: ExecutionReport) -> None:
        """COMPLETED (with report) for a verdict; FAILED (no report) for a worker failure."""
        if not self.config.redis.host:
            logger.debug("[%s] Redis not configured — skipping publish", report.execution_id)
            return
        if report.status_code in WORKER_FAILURE_CODES:
            logger.info("[%s] Pushing FAILED (status_code=%s)", report.execution_id, report.status_code)
            self.transport.publish(report.execution_id, "FAILED")
        else:
            logger.info("[%s] Pushing COMPLETED (status_code=%s)", report.execution_id, report.status_code)
            self.transport.publish(report.execution_id, "COMPLETED", report.to_json())

    def _handle_malformed(self, bad: MalformedMessage) -> None:
        if bad.job_id and self.config.redis.host:
            try:
                self.transport.publish(bad.job_id, "FAILED")
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

    async def _keepalive_loop(self, request: ExecutionRequest) -> None:
        """Touch the in-flight entry periodically (a third of the autoclaim threshold)."""
        interval = max(self.config.redis.autoclaim_min_idle_ms / 3000.0, 2.0)
        try:
            while True:
                await asyncio.sleep(interval)
                await asyncio.get_running_loop().run_in_executor(
                    None, self.transport.touch, request.stream_id)
        except asyncio.CancelledError:
            pass

    async def _maybe_rewarm(self) -> None:
        """Re-warm runtimes after a long idle stretch (page cache may have been evicted)."""
        interval = self.config.execution.warmup_idle_seconds
        if interval <= 0 or self._active_tasks:
            return
        now = time.monotonic()
        if now - self._last_activity < interval or now - self._last_warmup < interval:
            return
        logger.info("Idle for over %ds — re-warming runtimes", interval)
        await self.judge.warmup()
        self._last_warmup = time.monotonic()

    def _handle_shutdown(self) -> None:
        logger.info("Shutdown signal received, stopping after current tasks...")
        self._running = False

    async def _drain(self) -> None:
        if self._active_tasks:
            logger.info("Waiting for %d active task(s) to finish...", len(self._active_tasks))
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
            logger.info("All tasks finished")
