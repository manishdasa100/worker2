"""
Typed configuration for the worker2 service.

All settings come from environment variables (optionally seeded from an
`.env[.name]` file). Env var names are kept identical to worker1 so existing
`.env` files carry over unchanged; the only additions are the COMPILE_*
knobs for sandboxed compilation (worker2 compiles inside the jail, not on
the host).

Grouped into four dataclasses:
    RedisConfig     — stream transport + liveness heartbeat (the backend contract)
    SandboxConfig   — nsjail binary, the run/compile jail profiles, timing backstop
    ExecutionConfig — limits, fairness caps, calibration, compile budgets
    WorkerConfig    — top-level container
"""
import os
import socket
from dataclasses import dataclass, field

from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Redis — the backend contract. Do not rename keys/streams: the backend
# produces to stream_key, consumes from result_stream_key, and gates
# enqueues on heartbeat_key. All three are a fixed contract.
# ---------------------------------------------------------------------------
@dataclass
class RedisConfig:
    host: str = ""
    port: int = 6379
    username: str = ""                    # Redis ACL user; blank -> "default"
    password: str = ""

    # Inbound submissions (backend XADDs, worker consumes via a group)
    stream_key: str = "stream:pending-submissions"
    consumer_group: str = "workers"
    consumer_name: str = ""               # Blank -> "<hostname>:<pid>"
    block_ms: int = 5000                  # XREADGROUP BLOCK timeout
    autoclaim_min_idle_ms: int = 60000    # Reclaim entries idle longer than this

    # Outbound results (worker XADDs, backend consumes via its own group)
    result_stream_key: str = "stream:execution-results"
    result_stream_maxlen: int = 10000     # Producer-side backstop; 0 = unbounded

    # Liveness: the backend only enqueues while this key EXISTS. One key
    # shared by all workers; any live worker keeps it alive. TTL spans two
    # beat cycles so a slow cycle doesn't lapse it. Never DEL'd on shutdown.
    heartbeat_key: str = "executor:nsjail:heartbeat"
    heartbeat_interval: int = 10
    heartbeat_ttl: int = 30


@dataclass
class SandboxConfig:
    """nsjail binary + the two jail profiles (runtime, compile)."""
    nsjail_path: str = ""
    run_config_path: str = ""             # Jail profile for running user code
    compile_config_path: str = ""         # Jail profile for the compiler
    java_path: str = "/usr/lib/jvm/java-11-openjdk-amd64/bin/java"
    # TLE is enforced on CPU time (cgroup counter). The wall clock is only a
    # backstop at CPU-limit + this, catching sleepers/deadlocks (no CPU burn).
    wall_clock_grace: int = 5


@dataclass
class ExecutionConfig:
    max_concurrent: int = 4
    default_time_limit_ms: int = 5000     # Max CPU-ms budget per test case (clamps request)
    default_memory_limit: int = 128       # MB per sandbox (clamps request)
    max_output_bytes: int = 262144        # 256 KB output cap
    max_output_lines: int = 5000
    max_testcases: int = 50               # Worker backstop on job duration
    temp_dir: str = "/tmp/codinglemons"

    # --- Sandboxed compilation (NEW in worker2) ---
    # The compiler runs inside a jail with only the toolchain + code dir
    # visible and no network, so a malicious source can't read host files at
    # compile time or exhaust host RAM. These bound that jail.
    compile_timeout: int = 30             # CPU-seconds for the compile step
    compile_memory_limit: int = 512       # MB for the compile jail (g++/javac are hungry)

    # Re-warm runtimes after this long idle (0 disables). Boot warmup always runs.
    warmup_idle_seconds: int = 1800

    # --- CALIBRATE task ---
    calibration_runs: int = 5
    calibration_time_limit: int = 30      # Per-run CPU-seconds cap
    calibration_memory_limit: int = 1024  # Per-run memory cap (MB)
    calibration_time_margin: float = 3.0
    calibration_time_floor_ms: int = 500
    calibration_memory_margin: float = 2.0
    calibration_memory_floor_mb: int = 64


@dataclass
class WorkerConfig:
    redis: RedisConfig = field(default_factory=RedisConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    max_consecutive_errors: int = 5       # Shut down after this many back-to-back loop errors


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def _float(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


def load_config(env_file: str) -> WorkerConfig:
    """
    Build a WorkerConfig from an env file + os.environ (real env wins).

    Env var names match worker1, plus:
        COMPILE_TIMEOUT, COMPILE_MEMORY_LIMIT  — sandboxed-compile budgets
        NSJAIL_RUN_CONFIG_PATH                 — runtime jail profile
        NSJAIL_COMPILE_CONFIG_PATH             — compile jail profile
    NSJAIL_CONFIG_PATH (worker1's single profile) is still accepted as a
    fallback for the run profile.
    """
    if not os.path.isfile(env_file):
        raise SystemExit(
            f"[config] Required env file '{env_file}' not found. "
            f"Copy .env.example to {env_file} and fill in your values."
        )
    load_dotenv(env_file, override=False)

    c = WorkerConfig()

    # --- Redis ---
    r = c.redis
    r.host = os.environ.get("REDIS_HOST", r.host)
    r.port = _int("REDIS_PORT", r.port)
    r.username = os.environ.get("REDIS_USERNAME", r.username)
    r.password = os.environ.get("REDIS_PASSWORD", r.password)
    r.stream_key = os.environ.get("REDIS_STREAM_KEY", r.stream_key)
    r.consumer_group = os.environ.get("REDIS_CONSUMER_GROUP", r.consumer_group)
    r.consumer_name = os.environ.get("REDIS_CONSUMER_NAME", r.consumer_name)
    if not r.consumer_name:
        r.consumer_name = f"{socket.gethostname()}:{os.getpid()}"
    r.block_ms = _int("REDIS_BLOCK_MS", r.block_ms)
    r.autoclaim_min_idle_ms = _int("REDIS_AUTOCLAIM_MIN_IDLE_MS", r.autoclaim_min_idle_ms)
    r.result_stream_key = os.environ.get("REDIS_RESULT_STREAM_KEY", r.result_stream_key)
    r.result_stream_maxlen = _int("REDIS_RESULT_STREAM_MAXLEN", r.result_stream_maxlen)
    r.heartbeat_key = os.environ.get("REDIS_HEARTBEAT_KEY", r.heartbeat_key)
    r.heartbeat_interval = _int("REDIS_HEARTBEAT_INTERVAL", r.heartbeat_interval)
    r.heartbeat_ttl = _int("REDIS_HEARTBEAT_TTL", r.heartbeat_ttl)

    # --- Sandbox ---
    s = c.sandbox
    s.nsjail_path = os.environ.get("NSJAIL_PATH", s.nsjail_path)
    # Prefer the explicit run profile; fall back to worker1's NSJAIL_CONFIG_PATH.
    s.run_config_path = os.environ.get(
        "NSJAIL_RUN_CONFIG_PATH",
        os.environ.get("NSJAIL_CONFIG_PATH", s.run_config_path),
    )
    s.compile_config_path = os.environ.get("NSJAIL_COMPILE_CONFIG_PATH", s.compile_config_path)
    s.java_path = os.environ.get("JAVA_PATH", s.java_path)
    s.wall_clock_grace = _int("WALL_CLOCK_GRACE", s.wall_clock_grace)

    # --- Execution ---
    e = c.execution
    e.max_concurrent = _int("MAX_CONCURRENT", e.max_concurrent)
    e.default_time_limit_ms = _int("DEFAULT_TIME_LIMIT_MS", e.default_time_limit_ms)
    e.default_memory_limit = _int("DEFAULT_MEMORY_LIMIT", e.default_memory_limit)
    e.max_output_bytes = _int("MAX_OUTPUT_BYTES", e.max_output_bytes)
    e.max_output_lines = _int("MAX_OUTPUT_LINES", e.max_output_lines)
    e.max_testcases = _int("MAX_TESTCASES", e.max_testcases)
    e.temp_dir = os.environ.get("TEMP_DIR", e.temp_dir)
    e.compile_timeout = _int("COMPILE_TIMEOUT", _int("COMPILATION_TIMEOUT", e.compile_timeout))
    e.compile_memory_limit = _int("COMPILE_MEMORY_LIMIT", e.compile_memory_limit)
    e.warmup_idle_seconds = _int("WARMUP_IDLE_SECONDS", e.warmup_idle_seconds)
    e.calibration_runs = _int("CALIBRATION_RUNS", e.calibration_runs)
    e.calibration_time_limit = _int("CALIBRATION_TIME_LIMIT", e.calibration_time_limit)
    e.calibration_memory_limit = _int("CALIBRATION_MEMORY_LIMIT", e.calibration_memory_limit)
    e.calibration_time_margin = _float("CALIBRATION_TIME_MARGIN", e.calibration_time_margin)
    e.calibration_time_floor_ms = _int("CALIBRATION_TIME_FLOOR_MS", e.calibration_time_floor_ms)
    e.calibration_memory_margin = _float("CALIBRATION_MEMORY_MARGIN", e.calibration_memory_margin)
    e.calibration_memory_floor_mb = _int("CALIBRATION_MEMORY_FLOOR_MB", e.calibration_memory_floor_mb)

    c.max_consecutive_errors = _int("MAX_CONSECUTIVE_ERRORS", c.max_consecutive_errors)
    return c
