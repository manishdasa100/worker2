"""
Redis transport — the single owner of every Redis interaction.

Collects what worker1 spread across consumer.py and dispatcher.py into one
cohesive object so the dispatcher deals in requests/reports, not Redis verbs.

Delivery semantics (unchanged from worker1):
  * At-least-once: an entry is XACK+XDEL'd only after its result is published.
    A crash mid-job leaves it in the group PEL; XAUTOCLAIM redelivers it after
    autoclaim_min_idle_ms. `touch()` resets that idle clock for long in-flight
    jobs so they aren't duplicated onto another worker.
  * Result delivery to the backend is its own group's concern — an entry it
    reads but never ACKs stays in its PEL and redelivers.

All methods here are synchronous (thin Redis calls). The dispatcher runs the
blocking ones (consume, publish) in a thread to keep the event loop free.
"""
import json
import logging
import time
from typing import List, Optional, Tuple

from redis import Redis
from redis.exceptions import ResponseError

from config import RedisConfig
from models import (
    ExecutionRequest,
    MalformedMessage,
    parse_job_message,
    result_payload,
)

logger = logging.getLogger(__name__)


class RedisTransport:
    def __init__(self, config: RedisConfig):
        self.config = config
        self.client = Redis(
            host=config.host,
            port=config.port,
            username=config.username or None,
            password=config.password or None,
            decode_responses=True,
        )
        self._reclaim_cursor = "0-0"

    # ---- startup ------------------------------------------------------------

    def ensure_group(self) -> None:
        """Idempotently create the consumer group (MKSTREAM). BUSYGROUP = already there."""
        try:
            self.client.xgroup_create(
                name=self.config.stream_key,
                groupname=self.config.consumer_group,
                id="$",
                mkstream=True,
            )
            logger.info("Created consumer group '%s' on '%s'",
                        self.config.consumer_group, self.config.stream_key)
        except ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    # ---- receive ------------------------------------------------------------

    def consume(self, max_entries: int) -> Tuple[List[ExecutionRequest], List[MalformedMessage]]:
        """
        Next batch to process, at most max_entries (must be >= 1). Reclaimed
        (crashed-worker) entries first, else a blocking read for fresh ones.
        BLOCKS up to block_ms — run off-loop.
        """
        count = min(max_entries, self.config.read_count)
        entries = self._reclaim(count)
        if entries:
            logger.info("Reclaimed %d pending entry(ies) via XAUTOCLAIM", len(entries))
        else:
            entries = self._read_new(count)
            if entries:
                logger.info("Received %d new entry(ies) via XREADGROUP", len(entries))
        return self._build(entries)

    def _reclaim(self, count: int) -> List[Tuple[str, dict]]:
        try:
            result = self.client.xautoclaim(
                name=self.config.stream_key,
                groupname=self.config.consumer_group,
                consumername=self.config.consumer_name,
                min_idle_time=self.config.autoclaim_min_idle_ms,
                start_id=self._reclaim_cursor,
                count=count,
            )
        except ResponseError as e:
            if "NOGROUP" in str(e):
                logger.warning("Consumer group missing; recreating")
                self.ensure_group()
                return []
            raise
        # redis-py returns [next_cursor, claimed_entries, deleted_ids]. Each call
        # scans only COUNT x 10 pending entries, so resume where this one stopped.
        if result:
            self._reclaim_cursor = result[0]
        return (result[1] if result and len(result) >= 2 else []) or []

    def _read_new(self, count: int) -> List[Tuple[str, dict]]:
        try:
            response = self.client.xreadgroup(
                groupname=self.config.consumer_group,
                consumername=self.config.consumer_name,
                streams={self.config.stream_key: ">"},
                count=count,
                block=self.config.block_ms,
            )
        except ResponseError as e:
            if "NOGROUP" in str(e):
                logger.warning("Consumer group missing; recreating")
                self.ensure_group()
                return []
            raise
        if not response:
            return []
        _, entries = response[0]           # single stream requested
        return entries or []

    def _build(self, entries) -> Tuple[List[ExecutionRequest], List[MalformedMessage]]:
        requests, malformed = [], []
        for stream_id, fields in entries:
            body = fields.get("body", "")
            try:
                requests.append(parse_job_message(body=body, stream_id=stream_id))
            except (KeyError, ValueError, TypeError) as e:
                job_id = self._extract_job_id(body)
                logger.error("Malformed entry (stream_id=%s, job_id=%s): %s",
                             stream_id, job_id or "unknown", e)
                malformed.append(MalformedMessage(stream_id=stream_id, job_id=job_id, reason=str(e)))
        return requests, malformed

    @staticmethod
    def _extract_job_id(body: str) -> Optional[str]:
        try:
            return json.loads(body).get("jobId")
        except Exception:
            return None

    # ---- in-flight keep-alive ----------------------------------------------

    def touch(self, stream_id: str) -> None:
        """
        Reset an in-flight entry's idle clock (XCLAIM min_idle=0 back to self,
        JUSTID). Keeps a legitimately long job from looking abandoned. Best
        effort — a failure at worst means a possible duplicate, never a lost job.
        """
        if not stream_id:
            return
        try:
            self.client.xclaim(
                self.config.stream_key, self.config.consumer_group,
                self.config.consumer_name, min_idle_time=0,
                message_ids=[stream_id], justid=True,
            )
        except Exception as e:
            logger.warning("touch(%s) failed: %s", stream_id, e)

    # ---- liveness -----------------------------------------------------------

    def beat(self) -> None:
        """
        Refresh the shared liveness key (SET ... EX). Value = this consumer's
        name (operator breadcrumb; backend only checks existence). Never DEL'd:
        the key is shared, deleting it would declare other live workers dead.
        """
        self.client.set(self.config.heartbeat_key, self.config.consumer_name,
                        ex=self.config.heartbeat_ttl)

    # ---- acknowledge --------------------------------------------------------

    def ack(self, stream_id: str, job_id: str = "") -> None:
        """XACK (drop from PEL) + XDEL (free the entry body). Skipping it => redelivery."""
        if not stream_id:
            logger.warning("No stream_id for job_id=%s — cannot ack", job_id or "unknown")
            return
        try:
            self.client.xack(self.config.stream_key, self.config.consumer_group, stream_id)
            self.client.xdel(self.config.stream_key, stream_id)
        except Exception as e:
            logger.error("ack failed (job_id=%s, stream_id=%s): %s", job_id or "unknown", stream_id, e)

    # ---- publish result -----------------------------------------------------

    def publish(self, job_id: str, status: str, report_json: Optional[str] = None) -> None:
        """
        XADD one result entry (single `body` field). Retries 3x, then RAISES so
        the caller skips the submission ack and XAUTOCLAIM redelivers it. BLOCKS
        on retry sleeps — run off-loop.
        """
        body = result_payload(job_id, status, report_json)
        maxlen = self.config.result_stream_maxlen or None
        attempts = 3
        for attempt in range(1, attempts + 1):
            try:
                self.client.xadd(self.config.result_stream_key, {"body": body},
                                 maxlen=maxlen, approximate=True)
                return
            except Exception as e:
                logger.warning("[%s] result push %d/%d failed: %s", job_id, attempt, attempts, e)
                if attempt < attempts:
                    time.sleep(attempt)    # 1s, 2s
        raise RuntimeError(f"[{job_id}] result push failed after {attempts} attempts — will redeliver")

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass
