"""Verify real PID-1 signals against a packaged mobile worker in disposable Docker.

The child uses the production entry point and polling loop with a gated fake
work item. SQLite phase/lease behavior is covered by the worker's unit tests.
No API, production registry, secrets or media volumes are accessed.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4


def child(mode):
    """Gate one claimed operation so the parent can signal while it is in flight."""
    import logging
    from functools import partial
    import threading

    sys.path.insert(0, "/app")
    import mobile_upload_worker as module

    worker = module.MobileUploadWorker.__new__(module.MobileUploadWorker)
    worker._stop = threading.Event()
    worker.logger = logging.getLogger("signal-probe")
    calls = 0

    def once():
        nonlocal calls
        calls += 1
        Path("/tmp/ready").touch()
        if mode == "active":
            deadline = time.monotonic() + 30
            while not Path("/tmp/release").exists():
                if time.monotonic() > deadline:
                    raise RuntimeError("parent did not release the test operation")
                time.sleep(0.02)
            Path("/tmp/completed").touch()
            return True
        return False

    worker.run_once = once
    worker.run_forever = partial(worker.run_forever, idle_seconds=60)
    module.MobileUploadWorker.from_environment = classmethod(lambda cls: worker)
    module.main()
    Path("/tmp/result.json").write_text(
        json.dumps({"calls": calls, "completed": Path("/tmp/completed").exists()})
    )


def docker(*args, timeout=30):
    """Run a bounded Docker command and return only its expected output."""
    return subprocess.check_output(
        ["docker", *args], text=True, timeout=timeout
    ).strip()


def verify(image):
    """Check idle stop and active TERM/INT drain without additional claims."""
    results = []
    for mode, signal in [
        ("idle", "SIGTERM"),
        ("active", "SIGTERM"),
        ("active", "SIGINT"),
    ]:
        name = "oldap-mobile-drain-" + uuid4().hex[:10]
        try:
            docker(
                "run",
                "-d",
                "--name",
                name,
                "--platform",
                "linux/amd64",
                "--network",
                "none",
                "--mount",
                f"type=bind,src={Path(__file__).resolve()},dst=/probe.py,readonly",
                "--entrypoint",
                "python",
                image,
                "/probe.py",
                "--child",
                mode,
            )
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                result = subprocess.run(
                    ["docker", "exec", name, "test", "-f", "/tmp/ready"],
                    capture_output=True,
                )
                if result.returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("worker did not become ready")
            docker("kill", "--signal", signal, name)
            if mode == "active":
                time.sleep(0.2)
                assert (
                    docker("inspect", "--format", "{{.State.Running}}", name) == "true"
                )
                docker("exec", name, "touch", "/tmp/release")
            assert docker("wait", name) == "0"
            # Read stopped-container output without starting it again.
            import tempfile

            with tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / "result.json"
                docker("cp", name + ":/tmp/result.json", str(target))
                result = json.loads(target.read_text())
            assert result["calls"] == 1
            assert result["completed"] == (mode == "active")
            results.append({"mode": mode, "signal": signal, "exit_code": 0, **result})
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    return {"status": "passed", "image": image, "cases": results}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image")
    parser.add_argument("--child", choices=["idle", "active"])
    args = parser.parse_args()
    if args.child:
        child(args.child)
    elif args.image:
        print(json.dumps(verify(args.image), indent=2))
    else:
        parser.error("--image is required")
