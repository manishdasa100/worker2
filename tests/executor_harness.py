"""
Seam A: a real executor container under runsc, reached only through its socket.

    with ExecutorContainer() as executor:
        executor.run_job(job_id=..., language=..., ...)   # -> response dict

Builds the image from this checkout first (cached, so quick when unchanged).
EXECUTOR_RUNTIME picks the Docker runtime: it must be runsc with
--host-uds=create, or the socket never appears on the host (ticket 04).
"""
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = os.environ.get("EXECUTOR_IMAGE", "codinglemons-executor")
RUNTIME = os.environ.get("EXECUTOR_RUNTIME", "runsc-executor")
STARTUP_TIMEOUT_S = 60
JOB_TIMEOUT_S = 300


class ExecutorContainer:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="executor-")   # short: AF_UNIX paths max out at 108 bytes
        os.chmod(self.dir, 0o777)                         # the container's root binds the socket here
        self.socket = os.path.join(self.dir, "executor.sock")
        self.container = None

    def __enter__(self):
        # Host network for the build only, so apt works on hosts whose bridge can't resolve.
        subprocess.run(["docker", "build", "-q", "--network=host", "-t", IMAGE, ROOT],
                       check=True, stdout=subprocess.DEVNULL)
        self.container = subprocess.run(
            ["docker", "run", "-d", "--rm", f"--runtime={RUNTIME}", "--network=none",
             "-v", f"{self.dir}:/run/executor", IMAGE],
            check=True, capture_output=True, text=True).stdout.strip()
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        while not os.path.exists(self.socket):
            if time.monotonic() > deadline or not self._running():
                logs = self.logs()
                self.__exit__()
                raise RuntimeError(f"executor did not open its socket:\n{logs}")
            time.sleep(0.2)
        return self

    def __exit__(self, *exc):
        if self.container:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)
            self.container = None
        shutil.rmtree(self.dir, ignore_errors=True)

    def send(self, line: bytes) -> dict:
        """One connection: send `line`, read the one-line JSON response."""
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(JOB_TIMEOUT_S)
            s.connect(self.socket)
            s.sendall(line)
            s.shutdown(socket.SHUT_WR)
            data = b""
            while chunk := s.recv(65536):
                data += chunk
        return json.loads(data)

    def run_job(self, **job) -> dict:
        return self.send(json.dumps({"method": "run_job", "job": job}).encode() + b"\n")

    def logs(self) -> str:
        if not self.container:
            return ""
        return subprocess.run(["docker", "logs", self.container], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True).stdout

    def _running(self) -> bool:
        out = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", self.container],
                             capture_output=True, text=True).stdout.strip()
        return out == "true"
