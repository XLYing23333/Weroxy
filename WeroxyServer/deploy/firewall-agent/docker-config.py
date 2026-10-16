#!/usr/bin/env python3
"""Generate a reviewable agent scope from Docker inspection; never apply rules."""
import argparse
import ipaddress
import json
import subprocess
import sys


def inspect(kind, name):
    raw = subprocess.check_output(["docker", "inspect", "--type=" + kind, name], timeout=10)
    if len(raw) > 1024 * 1024:
        raise RuntimeError("Docker inspection exceeds budget")
    items = json.loads(raw)
    if len(items) != 1:
        raise RuntimeError("one Docker object required")
    return items[0]


def address(value):
    result = ipaddress.ip_address(value)
    if result.is_unspecified or result.is_multicast or getattr(result, "ipv4_mapped", None):
        raise RuntimeError("explicit unicast IP required")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--network", required=True, help="Explicit Docker bridge network")
    parser.add_argument("--public-ip", required=True, action="append", help="Approved local host IP; repeat for each family")
    parser.add_argument("--management-source", required=True, action="append")
    parser.add_argument("--management-port", type=int, default=9415, help="Actual published management port")
    parser.add_argument("--client-uid", type=int, default=10001, help="Host UID after any namespace mapping")
    parser.add_argument("--backend", choices=["nft", "iptables"], required=True)
    parser.add_argument("--listen-host", default="0.0.0.0", help="Actual Server listener host inside container")
    args = parser.parse_args()
    hosts = [address(value) for value in args.public_ip]
    sources = [str(address(value)) for value in args.management_source]
    listen = ipaddress.ip_address(args.listen_host)
    if not 1 <= args.management_port <= 65535 or not 1 <= args.client_uid <= 2**31 - 1:
        raise RuntimeError("invalid management port or client UID")
    if len(hosts) > 16 or len(sources) > 16:
        raise RuntimeError("address budget exceeded")
    # Verify approved IPs are assigned locally; avoid protecting a wrong host.
    local_raw = subprocess.check_output(["ip", "-j", "address", "show"], timeout=5)
    if len(local_raw) > 1024 * 1024:
        raise RuntimeError("host address inventory exceeds budget")
    local = {row["local"] for interface in json.loads(local_raw)
             for row in interface.get("addr_info", [])}
    if any(str(host) not in local for host in hosts):
        raise RuntimeError("public IP must be assigned on this Docker host")
    container = inspect("container", args.container)
    if not container.get("State", {}).get("Running"):
        raise RuntimeError("running container required")
    network = inspect("network", args.network)
    if network.get("Driver") != "bridge":
        raise RuntimeError("only an explicit Docker bridge is supported")
    attached = container.get("NetworkSettings", {}).get("Networks", {}).get(args.network)
    if not attached or attached.get("NetworkID") != network["Id"]:
        raise RuntimeError("container is not attached to selected network")
    bridge = network.get("Options", {}).get("com.docker.network.bridge.name")
    if not bridge:
        bridge = "docker0" if network.get("Name") == "bridge" else "br-" + network["Id"][:12]
    if not 1 <= len(bridge) <= 15 or any(not (ch.isalnum() or ch in "_-." ) for ch in bridge):
        raise RuntimeError("invalid bridge interface")
    destinations = {4: attached.get("IPAddress"), 6: attached.get("GlobalIPv6Address")}
    endpoints = []
    seen = set()
    for key, bindings in (container.get("NetworkSettings", {}).get("Ports") or {}).items():
        port, protocol = key.split("/", 1)
        if protocol != "tcp":
            continue
        target = int(port)
        if not 1 <= target <= 65535:
            raise RuntimeError("invalid target port")
        for binding in bindings or []:
            bind = ipaddress.ip_address(binding["HostIp"])
            public = int(binding["HostPort"])
            if not 1 <= public <= 65535:
                raise RuntimeError("invalid public port")
            for host in hosts:
                if host.version != bind.version or (not bind.is_unspecified and host != bind):
                    continue
                destination = destinations[host.version]
                if not destination:
                    raise RuntimeError("published family lacks a matching container IP; proxy path unsupported")
                destination = address(destination)
                if destination.version != host.version:
                    raise RuntimeError("cross-family Docker proxy path unsupported")
                identity = (str(host), public)
                if identity in seen:
                    continue
                seen.add(identity)
                if public == args.management_port and not any(address(source).version == host.version for source in sources):
                    raise RuntimeError("management source required for each published family")
                endpoints.append({"mode": "bridge", "bridge": bridge,
                                  "host_ip": str(host), "listen_host": str(listen),
                                  "destination_ip": str(destination),
                                  "public_port": public, "target_port": target})
                if len(endpoints) > 512:
                    raise RuntimeError("endpoint budget exceeded")
    if not endpoints:
        raise RuntimeError("no matching published TCP endpoints")
    cfg = {"backend": args.backend, "client_uid": args.client_uid,
           "allow_apply": False, "management_port": args.management_port,
           "management_sources": sources,
           "endpoints": sorted(endpoints, key=lambda row: (row["host_ip"], row["public_port"]))}
    print(json.dumps(cfg, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("Scope generation failed: " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        raise SystemExit(1)
