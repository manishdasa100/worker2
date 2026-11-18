"""
A stand-in executor for Seam B: answers run_job and ready on its unix socket the way
the test says, with no jails, so consumer behaviour is tested fast and deterministically.

    async with StubExecutor(path) as stub:
        stub.reply = lambda job: {"status": "FAILED", "error": "boom"}   # sync or async
        stub.reply = crash          # dies mid-job: the connection closes unanswered
        stub.ready = False          # what `ready` reports
        ...
        stub.jobs     # every job received, in order
"""
import asyncio
import inspect
import json
import os


def accepted(job: dict) -> dict:
    """The default reply: an Accepted report for the job."""
    return {"status": "COMPLETED", "report": {
        "execution_id": job["job_id"], "language": job["language"], "task": job["task"],
        "status_code": "ACC", "status_msg": "Accepted",
        "total_testcases": len(job["test_cases"]), "total_correct": len(job["test_cases"])}}


class Crash(Exception):
    pass


def crash(job: dict) -> dict:
    """A reply that kills the executor mid-job: the connection closes with no answer."""
    raise Crash


class StubExecutor:
    def __init__(self, path: str, ready: bool = True):
        self.path = path
        self.jobs = []
        self.reply = accepted
        self.ready = ready
        self._server = None

    async def __aenter__(self):
        self._server = await asyncio.start_unix_server(self._handle, self.path)
        return self

    async def __aexit__(self, *exc):
        self._server.close()
        await self._server.wait_closed()
        os.unlink(self.path)

    async def _handle(self, reader, writer):
        try:
            message = json.loads(await reader.readline())
            if message["method"] == "ready":
                response = {"ready": self.ready, "ran_at": "2026-01-01T00:00:00+00:00", "checks": []}
            else:
                assert message["method"] == "run_job", message
                self.jobs.append(message["job"])
                response = self.reply(message["job"])
                if inspect.isawaitable(response):
                    response = await response
            writer.write(json.dumps(response).encode() + b"\n")
            await writer.drain()
        except Crash:
            pass
        finally:
            writer.close()
