"""
Live end-to-end test against the real Redis, exercising the full dispatcher
loop and the backend contract. Uses ISOLATED test stream keys so production
streams are untouched.

    systemd-run --user --scope -p Delegate=yes .venv/bin/python tests/integration_live.py
"""
import asyncio
import base64
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

SUF = f":w2test:{os.getpid()}"


def b64(s): return base64.b64encode(s.encode()).decode()


async def main():
    config = load_config(env_file=".env.dev")
    # Isolate onto throwaway keys.
    config.redis.stream_key += SUF
    config.redis.consumer_group = "workers-test"
    config.redis.result_stream_key += SUF
    config.redis.heartbeat_key += SUF
    config.redis.block_ms = 1000

    delegation = CgroupDelegation.try_setup()
    if delegation is None:
        print("No delegated cgroup subtree — run via systemd-run"); sys.exit(2)

    r = redis_client.Redis(host=config.redis.host, port=config.redis.port,
                           password=config.redis.password or None, decode_responses=True)

    submission = {
        "jobId": "live-test-1", "language": "python",
        "userCode": b64("def add(a,b):\n    return a+b\n"),
        "driverCode": b64("from solution import add\na,b=map(int,input().split())\nprint(add(a,b))\n"),
        "task": "SUBMIT_CODE", "timeLimit": 2000, "memoryLimit": 128,
        "testCases": [{"input": "3 4", "expectedOutput": "7"}, {"input": "20 22", "expectedOutput": "42"}],
    }

    dispatcher = Dispatcher(config, delegation)
    runner = asyncio.create_task(dispatcher.start())
    await asyncio.sleep(0)

    ok = True
    try:
        # Wait for warmup + group creation, then push a submission.
        await asyncio.sleep(8)
        if runner.done():   # surface an early crash instead of silently timing out
            print("runner exited early:", runner.exception())
        r.xadd(config.redis.stream_key, {"body": json.dumps(submission)})
        print(f"pushed submission to {config.redis.stream_key}")

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
            for name, passed in checks.items():
                print(f"  {'OK ' if passed else 'XX '} {name}")
                ok = ok and passed
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
