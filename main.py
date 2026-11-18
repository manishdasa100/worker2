"""
Entry point for the consumer, the host side of the worker (consumer.py).

Usage:
    python main.py --env dev     # reads .env.dev
    python main.py --env prod    # reads .env.prod
    python main.py               # reads .env

Runs on the host from the venv and holds the Redis credentials. Judging
happens in the executors (executor.py), reached through EXECUTOR_SOCKETS.
"""
import argparse
import asyncio
import logging
import logging.handlers
import os
import sys

import redis as redis_client
from redis.exceptions import AuthenticationError, ConnectionError as RedisConnectionError

from config import WorkerConfig, load_config
from consumer import Consumer


def setup_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_dir = os.environ.get("LOG_DIR", "/var/log/codinglemons")
    fmt = logging.Formatter("[%(asctime)s] %(levelname)-7s %(name)-14s — %(message)s", "%Y-%m-%d %H:%M:%S")

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(fmt)
    handlers = [stdout_handler]

    file_error = None
    try:
        os.makedirs(log_dir, exist_ok=True)
        fh = logging.handlers.TimedRotatingFileHandler(
            os.path.join(log_dir, "worker.log"), when="midnight", backupCount=10, encoding="utf-8")
        fh.setFormatter(fmt)
        handlers.insert(0, fh)
    except OSError as e:
        file_error = e

    logging.basicConfig(level=getattr(logging, level, logging.INFO), handlers=handlers)
    if file_error is not None:
        logging.getLogger(__name__).warning(
            "Cannot write logs to %s (%s) — stdout only. Set LOG_DIR to a writable dir.", log_dir, file_error)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def validate_config(config: WorkerConfig) -> None:
    errors = []
    if not config.redis.host:
        errors.append("REDIS_HOST is required")
    if not config.executor_sockets:
        errors.append("EXECUTOR_SOCKETS needs at least one executor socket")
    for label, val in (("REDIS_STREAM_KEY", config.redis.stream_key),
                       ("REDIS_CONSUMER_GROUP", config.redis.consumer_group),
                       ("REDIS_RESULT_STREAM_KEY", config.redis.result_stream_key),
                       ("REDIS_HEARTBEAT_KEY", config.redis.heartbeat_key)):
        if not val:
            errors.append(f"{label} is required")

    # TTL must span two beat cycles (a cycle = interval + a full blocking read),
    # else one slow cycle lapses the key and the backend stops enqueuing.
    beat_cycle = config.redis.heartbeat_interval + config.redis.block_ms / 1000
    if config.redis.heartbeat_interval <= 0:
        errors.append("REDIS_HEARTBEAT_INTERVAL must be > 0")
    elif config.redis.heartbeat_ttl < 2 * beat_cycle:
        errors.append(f"REDIS_HEARTBEAT_TTL ({config.redis.heartbeat_ttl}s) must be >= "
                      f"2 x (interval + block) = {2 * beat_cycle:g}s")

    if not errors:
        try:
            probe = redis_client.Redis(host=config.redis.host, port=config.redis.port,
                                       username=config.redis.username or None,
                                       password=config.redis.password or None, socket_timeout=5)
            probe.ping()
            probe.close()
        except AuthenticationError as e:
            errors.append(f"Redis auth failed ({e}). Check REDIS_USERNAME / REDIS_PASSWORD against the server's ACL.")
        except RedisConnectionError as e:
            errors.append(f"Cannot reach Redis at {config.redis.host}:{config.redis.port} ({e})")

    if errors:
        for err in errors:
            logging.getLogger(__name__).error("Config error: %s", err)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="CodingLemons worker2")
    parser.add_argument("--env", default=None, help="Environment name (dev -> .env.dev). Defaults to .env")
    args = parser.parse_args()

    env_file = f".env.{args.env}" if args.env else ".env"
    config = load_config(env_file=env_file)

    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Loaded configuration from '%s'", env_file)

    validate_config(config)

    logger.info("=== CodingLemons worker2 consumer ===")
    logger.info("  Redis:           %s:%d", config.redis.host, config.redis.port)
    logger.info("  Submit stream:   %s (group %s)", config.redis.stream_key, config.redis.consumer_group)
    logger.info("  Result stream:   %s (maxlen=%s)", config.redis.result_stream_key,
                config.redis.result_stream_maxlen or "unbounded")
    logger.info("  Heartbeat:       %s (every %ds, ttl %ds)", config.redis.heartbeat_key,
                config.redis.heartbeat_interval, config.redis.heartbeat_ttl)
    logger.info("  Executors:       %s", ", ".join(config.executor_sockets))
    logger.info("=====================================")

    asyncio.run(Consumer(config).start())


if __name__ == "__main__":
    main()
