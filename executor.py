"""
Executor: judges jobs inside a runsc container, one at a time, for whoever
connects to its unix socket (ADR-0001). Holds no secrets and has no network.

Protocol: one newline-terminated JSON request and one JSON response line per
connection.

    {"method": "run_job", "job": {<ExecutionRequest fields>}}
      -> {"status": "COMPLETED", "report": {<ExecutionReport fields>}}
      -> {"status": "FAILED", "error": "<why>"}     worker failure: bad message,
                                                       unsupported language, jail fault
      -> {"status": "NOT_READY", "error": "<why>"}  refused, nothing ran: the latest
                                                       self-test failed or hasn't finished
    {"method": "ready"}
      -> {"ready": bool, "ran_at": <ISO time or null>, "overhead": {...},
          "checks": [{"name", "ok", "detail", "not_applicable"?}]}   (selftest.py)

The containment self-test runs at startup and every SELF_TEST_INTERVAL_S, holding
the same lock as jobs, so it never runs beside one.

    python3 executor.py      # config from the environment (see Dockerfile)
"""
import asyncio
import dataclasses
import json
import logging
import os
import sys

import cgroups
from config import load_config
from judge import Judge
from models import WORKER_FAILURE_CODES, ExecutionRequest
from sandbox import workspace
from selftest import not_ready, self_test

logger = logging.getLogger("executor")

# Bounds one read: a job at the payload caps (config.py: 48 MiB of test data,
# 2 x 256 KiB of code), JSON-escaped at up to 2x. Bigger fails as too large.
MAX_REQUEST_BYTES = 128 * 1024 * 1024
SELF_TEST_INTERVAL_S = int(os.environ.get("SELF_TEST_INTERVAL_S", 600))


class Executor:
    def __init__(self, judge: Judge):
        self.judge = judge
        self._one_job = asyncio.Lock()
        self.report = not_ready("the first self-test has not finished")

    async def self_test_forever(self) -> None:
        while True:
            async with self._one_job:
                self.report = await self_test(self.judge)
            await asyncio.sleep(SELF_TEST_INTERVAL_S)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                line = await reader.readline()
            except ValueError as e:    # longer than MAX_REQUEST_BYTES
                response = failed(f"request too large: {e}")
            else:
                response = await self.respond(line)
            writer.write(json.dumps(response).encode() + b"\n")
            await writer.drain()
        except Exception:
            logger.exception("Connection failed")
        finally:
            writer.close()

    async def respond(self, line: bytes) -> dict:
        try:
            message = json.loads(line)
            if isinstance(message, dict) and message.get("method") == "ready":
                return self.report
            if not isinstance(message, dict) or message.get("method") != "run_job":
                raise ValueError("expected method run_job or ready")
            request = ExecutionRequest(**message["job"])
        except (ValueError, TypeError, KeyError) as e:
            logger.warning("Malformed request: %s", e)
            return failed(f"malformed run_job message: {e}")

        async with self._one_job:
            if not self.report["ready"]:
                failing = ", ".join(c["name"] for c in self.report["checks"] if not c["ok"])
                return {"status": "NOT_READY", "error": f"executor not ready: {failing}"}
            try:
                report = await self.judge.judge(request)
            except Exception as e:      # e.g. a field of the wrong type
                logger.exception("[%s] Judge failed", request.job_id)
                return failed(f"judge failed: {e}")
        if report.status_code in WORKER_FAILURE_CODES:
            return failed(report.internal_error or report.status_msg)
        return {"status": "COMPLETED", "report": dataclasses.asdict(report)}


def failed(error: str) -> dict:
    return {"status": "FAILED", "error": error}


async def serve(path: str) -> None:
    config = load_config(env_file=None)
    executor = Executor(Judge(config))
    if os.path.exists(path):
        os.unlink(path)          # left by a crashed predecessor
    server = await asyncio.start_unix_server(executor.handle, path, limit=MAX_REQUEST_BYTES)
    os.chmod(path, 0o666)        # the host consumer isn't root; the mounted dir gates access
    logger.info("Executor serving on %s", path)
    async with server:
        await asyncio.gather(server.serve_forever(), executor.self_test_forever())


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(), stream=sys.stdout,
                        format="[%(asctime)s] %(levelname)-7s %(name)-10s %(message)s")
    try:
        cgroups.require()
        with workspace():   # refuse to start if job workspaces can't be mounted
            pass
    except RuntimeError as e:
        logger.error("Refusing to start: %s", e)
        sys.exit(1)
    asyncio.run(serve(os.environ.get("EXECUTOR_SOCKET", "/run/executor/executor.sock")))


if __name__ == "__main__":
    main()
