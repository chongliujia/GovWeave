#!/usr/bin/env python3
"""Run the trusted benchmark image on a disposable disk-backed Docker volume."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import uuid


def docker(*args, check=True, timeout=30):
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          check=check, timeout=timeout)


def inspect_json(*args):
    return json.loads(docker(*args).stdout)


def save(path, value):
    temporary = path.with_suffix(".partial")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def cleanup_command(*args, timeout=30):
    try:
        return docker(*args, check=False, timeout=timeout).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="govweave-gateway-bench:local")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--timeout", type=int, default=1800,
                        help="benchmark execution deadline in seconds (1..21600), followed by cleanup")
    parser.add_argument("benchmark_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    bench = args.benchmark_args
    if bench[:1] == ["--"]:
        bench = bench[1:]
    allowed = {"requests", "warmup", "rounds", "concurrency", "sizes", "protocols",
               "provider-delay-ms", "gomaxprocs", "seed", "profile"}
    # Keep worker mode, source and report paths under the runner's control.
    for value in bench:
        if value.startswith("-") and not value.lstrip("-").isdigit():
            if value.lstrip("-").split("=", 1)[0] not in allowed:
                parser.error("unsupported benchmark option: " + value.split("=", 1)[0])
    if not 1 <= args.timeout <= 21600:
        parser.error("timeout must be 1..21600 seconds")
    os.umask(0o077)
    out = (args.out or Path("dist/gateway-benchmark") /
           (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + "-docker")).resolve()
    try:
        out.mkdir(parents=True, exist_ok=False, mode=0o700)
    except OSError:
        parser.error("output directory must be new and writable")
    name = "govweave-bench-" + uuid.uuid4().hex
    volume = name + "-work"
    metadata = {"schema_version": 1, "state": "initializing", "image_requested": args.image,
                "container_name": name, "volume_name": volume,
                "benchmark_args": bench, "parent_gomaxprocs": 4,
                "limits": {"cpus": 4, "memory_bytes": 1073741824, "pids": 256},
                "storage": "fresh local Docker volume at /work; not tmpfs or a host bind mount",
                "limitations": ["Docker Desktop includes a Linux VM and a host-backed virtual disk; it is not bare-metal Linux.",
                                "CPU/memory limits cover the provider, clients and gateway children together.",
                                "Other containers and host workloads are not stopped; shared resource interference remains possible.",
                                "Sync/readback does not prove survival of host or VM power loss."]}
    created = False
    volume_created = False
    process = None
    exit_code = 1

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        # Pin the inspected immutable local image ID for this run, even if its
        # tag moves. No image pull, host port, Docker socket or source bind mount.
        metadata["image"] = inspect_json("image", "inspect", args.image, "--format",
            '{"id":{{json .Id}},"digests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}')
        if metadata["image"]["os"] != "linux":
            raise ValueError("a Linux benchmark image is required")
        metadata["engine"] = inspect_json("info", "--format",
            '{"version":{{json .ServerVersion}},"os":{{json .OperatingSystem}},"kernel":{{json .KernelVersion}},"architecture":{{json .Architecture}},"driver":{{json .Driver}},"cpus":{{.NCPU}},"memory_bytes":{{.MemTotal}}}')
        metadata["other_running_containers_before"] = len(docker("ps", "-q").stdout.split())
        docker("volume", "create", "--driver", "local", "--label", "govweave.benchmark=true", volume)
        volume_created = True
        docker("create", "--name", name, "--label", "govweave.benchmark=true",
               "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", "--user", "65532:65532",
               "--cpus", "4", "--memory", "1g", "--memory-swap", "1g", "--pids-limit", "256",
               "--env", "GOMAXPROCS=4", "--env", "TMPDIR=/work/tmp",
               "--mount", "type=volume,source=" + volume + ",target=/work",
               metadata["image"]["id"], "-source-root", "/src", "-out", "/work/report", *bench)
        created = True
        metadata["container_config"] = inspect_json("inspect", name, "--format",
            '{"network":{{json .HostConfig.NetworkMode}},"readonly_rootfs":{{.HostConfig.ReadonlyRootfs}},"user":{{json .Config.User}},"nano_cpus":{{.HostConfig.NanoCpus}},"memory_bytes":{{.HostConfig.Memory}},"memory_swap_bytes":{{.HostConfig.MemorySwap}},"pids_limit":{{.HostConfig.PidsLimit}},"cap_drop":{{json .HostConfig.CapDrop}},"security_opt":{{json .HostConfig.SecurityOpt}}}')
        metadata["state"] = "running"
        save(out / "docker-environment.json", metadata)
        print("Running isolated Linux benchmark; output: " + str(out), flush=True)
        with (out / "container.log").open("w") as log:
            process = subprocess.Popen(["docker", "start", "--attach", name], stdout=log, stderr=log)
            process.wait(timeout=args.timeout)
        status = inspect_json("inspect", name, "--format",
            '{"exit_code":{{.State.ExitCode}},"oom_killed":{{.State.OOMKilled}}}')
        metadata["container_exit"] = status
        exit_code = status["exit_code"]
        metadata["state"] = "completed" if exit_code == 0 and not status["oom_killed"] else "failed"
    except (KeyboardInterrupt, subprocess.TimeoutExpired) as error:
        metadata["state"] = "interrupted"
        metadata["interruption_reason"] = "deadline" if isinstance(error, subprocess.TimeoutExpired) else "signal"
        exit_code = 1
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        metadata["state"] = "failed"
        metadata["failure_type"] = type(error).__name__
        print("Container benchmark failed: " + type(error).__name__, file=sys.stderr)
    finally:
        # A handled interruption asks the benchmark to checkpoint before kill.
        # Remove only this run's UUID-named resources; never prune other work.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup = {"container_removed": not created, "volume_removed": not volume_created}
        if created:
            cleanup_command("stop", "--time", "10", name, timeout=20)
            if process is not None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            metadata["report_copied"] = cleanup_command("cp", name + ":/work/report", str(out / "result"))
            cleanup["container_removed"] = cleanup_command("rm", "-f", name)
        if volume_created:
            cleanup["volume_removed"] = cleanup_command("volume", "rm", volume)
        metadata["cleanup"] = cleanup
        if not all(cleanup.values()) or (exit_code == 0 and not metadata.get("report_copied")):
            exit_code = 1
            metadata["state"] = "failed"
        save(out / "docker-environment.json", metadata)
    print("State: " + metadata["state"] + "; artifacts: " + str(out), flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
