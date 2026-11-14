"""Generate an additive, internal-only 20–50 worker Docker Compose lab.

Usage: python -m orglab.composegen --nodes 20 --output compose.orglab.generated.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SERVICES = ("docs", "crm", "mail")


def build_compose(nodes: int = 20, topology: str = "flat") -> dict:
    if topology not in ("flat", "departmental"):
        raise ValueError("--topology must be flat or departmental")
    employee_networks = ["employees_internal"] if topology == "flat" else [f"dept_{k}_internal" for k in ("sales", "engineering", "hr", "finance")]
    if not 20 <= nodes <= 50:
        raise ValueError("--nodes must be between 20 and 50")
    common = {
        "image": "python:3.12-slim",
        "working_dir": "/app",
        "volumes": ["./orglab:/app:ro"],
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "pids_limit": 64,
        "mem_limit": "128m",
        "cpus": "0.20",
        "tmpfs": ["/tmp:size=16m"],
    }
    services = {}
    for name in SERVICES:
        services[name] = {
            **common,
            "command": ["python", "-u", "runtime.py", "service", "--name", name],
            "networks": ["services_internal"],
        }
    services["gateway"] = {
        **common,
        "command": ["python", "-u", "runtime.py", "gateway"],
        "networks": employee_networks + ["services_internal"],
        "volumes": ["./orglab:/app:ro", "./outputs/orglab/${ORG_RUN_ID:?set_ORG_RUN_ID}:/results"],
        "user": "${ORG_UID:?set_ORG_UID}:${ORG_GID:?set_ORG_GID}",
    }
    departments = ("sales", "engineering", "hr", "finance")
    for k in range(1, nodes + 1):
        name = f"employee_{k:03d}"
        services[name] = {
            **common,
            "command": ["python", "-u", "runtime.py", "employee", "--name", name],
            "networks": [employee_networks[(k - 1) % len(employee_networks)]],
            "environment": {"ORG_DEPARTMENT": departments[(k - 1) % 4]},
            "user": "${ORG_UID:?set_ORG_UID}:${ORG_GID:?set_ORG_GID}",
        }
    services["controller"] = {
        **common,
        "command": ["python", "-u", "runtime.py", "controller"],
        "networks": employee_networks,
        "volumes": ["./orglab:/app:ro", "./outputs/orglab/${ORG_RUN_ID:?set_ORG_RUN_ID}:/results"],
        "user": "${ORG_UID:?set_ORG_UID}:${ORG_GID:?set_ORG_GID}",
        "profiles": ["experiment"],
        "environment": {
            "ORG_RUN_ID": "${ORG_RUN_ID:?set_ORG_RUN_ID}",
            "ORG_NODES": str(nodes),
            "ORG_ROUNDS": "${ORG_ROUNDS:-3}",
            "ORG_TEST_ROUNDS": "${ORG_TEST_ROUNDS:-3}",
            "ORG_SEED": "${ORG_SEED:-20261114}",
            "ORG_STEP_SECONDS": "${ORG_STEP_SECONDS:-0.6}",
            "ORG_TOPOLOGY": topology,
        },
    }
    services["capture"] = {
        "build": {"context": ".", "dockerfile": "orglab/Dockerfile.capture"},
        "command": ["tcpdump", "-Z", "root", "-i", "any", "-p", "-nn", "-s", "0", "-U", "-w", "/captures/orglab.pcap", "tcp", "port", "8080"],
        "network_mode": "service:gateway",
        "depends_on": ["gateway"],
        "volumes": ["./outputs/orglab/${ORG_RUN_ID:?set_ORG_RUN_ID}/captures:/captures"],
        "read_only": True,
        "cap_drop": ["ALL"],
        "cap_add": ["NET_RAW"],
        "security_opt": ["no-new-privileges:true"],
        "pids_limit": 32,
        "mem_limit": "96m",
        "cpus": "0.20",
        "tmpfs": ["/tmp:size=16m"],
        "user": "0:0",
        "profiles": ["capture"],
    }
    return {
        "services": services,
        "networks": {name: {"internal": True, "driver": "bridge"} for name in employee_networks + ["services_internal"]},
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--nodes", type=int, default=20)
    p.add_argument("--topology", choices=["flat", "departmental"], default="flat")
    p.add_argument("--output", type=Path, default=Path("compose.orglab.generated.json"))
    args = p.parse_args()
    obj = build_compose(args.nodes, args.topology)
    content = json.dumps(obj, indent=2) + "\n"
    if args.output.exists() and args.output.read_text(encoding="utf-8") != content:
        raise FileExistsError(f"refusing to overwrite a different Compose file: {args.output}")
    args.output.write_text(content, encoding="utf-8")
    print(f"CREATED {args.output} employees={args.nodes} topology={args.topology} "
          f"internal_networks={len(obj['networks'])} published_ports=0")


if __name__ == "__main__":
    main()
