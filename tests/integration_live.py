"""
Live end-to-end test against the real Redis, exercising the full dispatcher
loop and the backend contract. Uses ISOLATED test stream keys so production
streams are untouched.

    systemd-run --user --scope -p Delegate=yes .venv/bin/python tests/integration_live.py
"""
import asyncio
import base64
import dataclasses
import json
import logging
import os
import sys
import time

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s — %(message)s")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import redis as redis_client
from cgroups import CgroupDelegation
from config import load_config
from dispatcher import Dispatcher
from redis_io import RedisTransport

SUF = f":w2test:{os.getpid()}"


def b64(s): return base64.b64encode(s.encode()).decode()


def print_checks(checks):
    for name, passed in checks.items():
        print(f"  {'OK ' if passed else 'XX '} {name}")
    return all(checks.values())


def job_body(job_id, driver=b64("from solution import add\na,b=map(int,input().split())\nprint(add(a,b))\n")):
    return json.dumps({
        "jobId": job_id, "language": "python",
        "userCode": b64("def add(a,b):\n    return a+b\n"), "driverCode": driver,
        "task": "SUBMIT_CODE", "timeLimit": 2000, "memoryLimit": 128,
        "testCases": [{"input": "3 4", "expectedOutput": "7"}],
    })


def check_transport_limits(config, r):
    """Reads and reclaims take no more than they are asked for (real Redis, no jails)."""
    key = config.redis.stream_key + ":limits"
    reader_config = dataclasses.replace(config.redis, stream_key=key, consumer_name="reader", block_ms=100)
    rescuer_config = dataclasses.replace(reader_config, consumer_name="rescuer", autoclaim_min_idle_ms=0)
    reader, rescuer = RedisTransport(reader_config), RedisTransport(rescuer_config)
    reader.ensure_group()
    try:
        for i in range(5):
            r.xadd(key, {"body": job_body(f"limit-{i}")})
        first, _ = reader.consume(2)
        second, _ = reader.consume(1)
        reclaimed, _ = rescuer.consume(2)
        return print_checks({
            "read of 2 takes 2": len(first) == 2,
            "read of 1 takes 1": len(second) == 1,
            "reclaim of 2 takes 2 of the 3 pending": len(reclaimed) == 2,
            "two entries never read": r.xlen(key) - r.xpending(key, reader_config.consumer_group)["pending"] == 2,
        })
    finally:
        r.delete(key)
        reader.close()
        rescuer.close()


def check_reclaim_scans_whole_pending_list(config, r):
    """At one free slot, a crashed consumer's entry is found wherever it sits among in-flight ones."""
    key = config.redis.stream_key + ":scan"
    rescuer_config = dataclasses.replace(config.redis, stream_key=key, consumer_name="rescuer",
                                         autoclaim_min_idle_ms=1000, block_ms=100)
    group = rescuer_config.consumer_group
    transport = RedisTransport(rescuer_config)
    transport.ensure_group()

    def only_stale(stale_id):
        time.sleep(1.2)
        r.xclaim(key, group, "other", min_idle_time=0, justid=True,
                 message_ids=[i for i in ids if i != stale_id])

    def reclaim():
        return [job.job_id for _ in range(3) for job in transport.consume(1)[0]]

    try:
        ids = [r.xadd(key, {"body": job_body(f"scan-{i}")}) for i in range(12)]
        r.xreadgroup(group, "other", {key: ">"}, count=12)
        assert transport.consume(1)[0] == []    # nothing idle yet; the cursor moves past the first 10
        only_stale(ids[0])
        behind_cursor = reclaim()
        only_stale(ids[11])
        behind_live = reclaim()
        return print_checks({
            "stale entry behind the cursor reclaimed": behind_cursor == ["scan-0"],
            "stale entry behind 11 live ones reclaimed": behind_live == ["scan-11"],
        })
    finally:
        r.delete(key)
        transport.close()


async def check_burst_stays_in_stream(config, r, burst=8):
    """With every slot busy, a burst stays claimable by other workers, and all of it still runs."""
    sleeping_driver = b64("import time\nfrom solution import add\na,b=map(int,input().split())\n"
                          "time.sleep(1)\nprint(add(a,b))\n")
    key, group = config.redis.stream_key, config.redis.consumer_group
    slots = config.execution.max_concurrent
    pipe = r.pipeline()
    for i in range(burst):
        pipe.xadd(key, {"body": job_body(f"burst-{i}", driver=sleeping_driver)})
    pipe.execute()

    claimed_max, unclaimed_when_full = 0, None
    done = {}
    deadline = time.time() + 60
    while time.time() < deadline and len(done) < burst:
        await asyncio.sleep(0.1)
        pending = r.xpending(key, group)["pending"]
        claimed_max = max(claimed_max, pending)
        if pending == slots and unclaimed_when_full is None:
            unclaimed_when_full = r.xlen(key) - pending
        for _, fields in r.xrange(config.redis.result_stream_key):
            result = json.loads(fields["body"])
            if result["job_id"].startswith("burst-"):
                done[result["job_id"]] = result["status"]
    print(f"burst: {burst} jobs, {slots} slots, most claimed {claimed_max}, "
          f"unclaimed when full {unclaimed_when_full}")
    return print_checks({
        f"never more than {slots} claimed": claimed_max <= slots,
        f"{burst - slots} unclaimed while slots are busy": unclaimed_when_full == burst - slots,
        "every burst job completed": len(done) == burst and set(done.values()) == {"COMPLETED"},
    })


async def main():
    config = load_config(env_file=".env.dev")
    # Isolate onto throwaway keys.
    config.redis.stream_key += SUF
    config.redis.consumer_group = "workers-test"
    config.redis.result_stream_key += SUF
    config.redis.heartbeat_key += SUF
    config.redis.block_ms = 1000
    config.execution.max_concurrent = 2

    delegation = CgroupDelegation.try_setup()
    if delegation is None:
        print("No delegated cgroup subtree — run via systemd-run"); sys.exit(2)

    r = redis_client.Redis(host=config.redis.host, port=config.redis.port,
                           password=config.redis.password or None, decode_responses=True)

    ok = check_transport_limits(config, r)
    ok = check_reclaim_scans_whole_pending_list(config, r) and ok

    job = json.loads(job_body("live-test-1"))
    job["testCases"].append({"input": "20 22", "expectedOutput": "42"})

    dispatcher = Dispatcher(config, delegation)
    runner = asyncio.create_task(dispatcher.start())
    await asyncio.sleep(0)

    try:
        # Wait for warmup + group creation, then push a job.
        await asyncio.sleep(8)
        if runner.done():   # surface an early crash instead of silently timing out
            print("runner exited early:", runner.exception())
        r.xadd(config.redis.stream_key, {"body": json.dumps(job)})
        print(f"pushed job to {config.redis.stream_key}")

        # Poll the result stream for up to 30s.
        loop = asyncio.get_running_loop()
        deadline = time.time() + 30
        last_id = "0"
        result = None
        while time.time() < deadline and result is None:
            resp = await loop.run_in_executor(
                None, lambda: r.xread({config.redis.result_stream_key: last_id}, block=1000))
            for _, entries in (resp or []):
                for eid, fields in entries:
                    last_id = eid
                    result = json.loads(fields["body"])
        if result is None:
            print("FAIL: no result within 30s"); ok = False
        else:
            print("result payload:", json.dumps(result)[:200])
            checks = {
                "job_id == live-test-1": result.get("job_id") == "live-test-1",
                "status == COMPLETED": result.get("status") == "COMPLETED",
                "worker_type == NSJAIL_WORKER": result.get("worker_type") == "NSJAIL_WORKER",
                "execution_report present": "execution_report" in result,
            }
            rep = json.loads(result["execution_report"]) if "execution_report" in result else {}
            checks["report status_code == ACC"] = rep.get("status_code") == "ACC"
            checks["report 2/2 correct"] = rep.get("total_correct") == 2
            checks["heartbeat key exists"] = r.exists(config.redis.heartbeat_key) == 1
            ok = print_checks(checks) and ok

        ok = await check_burst_stays_in_stream(config, r) and ok
    finally:
        dispatcher._handle_shutdown()
        try:
            await asyncio.wait_for(runner, timeout=20)
        except asyncio.TimeoutError:
            pass
        # cleanup throwaway keys
        r.delete(config.redis.stream_key, config.redis.result_stream_key, config.redis.heartbeat_key)
        r.close()

    print("\n" + ("LIVE INTEGRATION PASS" if ok else "LIVE INTEGRATION FAIL"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
