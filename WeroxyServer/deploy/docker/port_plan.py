"""Bounded host-side publication plan for the Docker deployment manager."""
import datetime
import ipaddress
import json
import os
import pathlib
import socket
import shutil
import sqlite3
import subprocess


def configured_pool(dbfile):
    with sqlite3.connect(f"file:{dbfile}?mode=ro", uri=True, timeout=5) as db:
        row = db.execute("SELECT forward_first,forward_last,data_first,data_last,bind_host FROM port_settings WHERE id=1").fetchone()
    if not row or row[0]<1 or row[1]>65535 or row[2]<1 or row[3]>65535 or row[1]<row[0] or row[3]<row[2]:
        raise RuntimeError("invalid stored port pools")
    if row[1]-row[0]>1023 or row[3]-row[2]>1023:
        raise RuntimeError("port pool publication exceeds 1024 candidates")
    return row


def host_port_free(host, port):
    family=socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family,socket.SOCK_STREAM) as sock:
        # Docker listeners use address reuse. Closed connections in TIME_WAIT
        # must not block an upgrade; a live listener still rejects this bind.
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        if family==socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        try:
            sock.bind((host,port))
            return True
        except OSError as error:
            if error.errno in (98, 48): return False
            raise RuntimeError(f"cannot inspect host TCP port {port}: {error.strerror}") from error


def plan(dbfile, host, own_ports=()):
    first,last,data_first,data_last,_=configured_pool(dbfile)
    own=set(own_ports)
    keys=[(int(os.environ.get("WERXY_LEGACY_HOST_PORT","4900")),4900),
          (int(os.environ.get("WERXY_CONTROL_HOST_PORT","29999")),29999),
          (int(os.environ.get("WERXY_WEB_HOST_PORT","9415")),9415)]
    for host_port,_ in keys:
        if not 1<=host_port<=65535 or (host_port not in own and not host_port_free(host,host_port)):
            raise RuntimeError(f"required host TCP port {host_port} is occupied")
    unavailable_forward=[port for port in range(first,last+1) if port not in own and not host_port_free(host,port)]
    unavailable_data=[port for port in range(data_first,data_last+1) if port not in own and not host_port_free(host,port)]
    published=keys+[(port,port) for port in range(first,last+1) if port not in unavailable_forward]+[(port,port) for port in range(data_first,data_last+1) if port not in unavailable_data]
    if len({left for left,_ in published})!=len(published):
        raise RuntimeError("host publication has duplicate TCP ports")
    return {"checked_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"host_ip":host,
            "forward_first":first,"forward_last":last,"data_first":data_first,"data_last":data_last,
            "unavailable_forward":unavailable_forward,"unavailable_data":unavailable_data,
            "ports":published}


def preserved_plan(dbfile, publication):
    """Use verified prior Docker bindings exactly; never rescan into new ports."""
    first,last,data_first,data_last,_ = configured_pool(dbfile)
    host = publication['host_ip']
    if not isinstance(host,str):
        raise RuntimeError('Invalid preserved host')
    ipaddress.ip_address(host)
    pairs = publication['ports']
    if not isinstance(pairs,list) or not 3 <= len(pairs) <= 2051:
        raise RuntimeError('Invalid preserved publication')
    if any(not isinstance(pair,(list,tuple)) or len(pair)!=2 for pair in pairs):
        raise RuntimeError('Invalid preserved port pair')
    pairs = [tuple(pair) for pair in pairs]
    if any(len(pair)!=2 or any(type(p)!=int or not 1<=p<=65535 for p in pair) for pair in pairs):
        raise RuntimeError('Invalid preserved port')
    entries = {4900,29999,9415}
    if len({p[0] for p in pairs})!=len(pairs) or len({p[1] for p in pairs})!=len(pairs) or not entries <= {p[1] for p in pairs}:
        raise RuntimeError('Ambiguous preserved publication')
    for outside,inside in pairs:
        if inside not in entries and (outside!=inside or not (first<=inside<=last or data_first<=inside<=data_last)):
            raise RuntimeError('Stored pool differs from preserved publication')
    return {'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'host_ip':host,
            'forward_first':first,'forward_last':last,'data_first':data_first,'data_last':data_last,
            'unavailable_forward':[p for p in range(first,last+1) if (p,p) not in pairs],
            'unavailable_data':[p for p in range(data_first,data_last+1) if (p,p) not in pairs],
            'ports':pairs}


def write_plan(value, data_dir, compose_file):
    data_dir.mkdir(parents=True,exist_ok=True)
    host=value["host_ip"]
    entries=[f"{host}:{external}:{internal}" for external,internal in value["ports"]]
    compose_file.write_text(json.dumps({"services":{"weroxy":{"ports":entries}}},indent=2)+"\n")
    (data_dir/"host-port-plan.json").write_text(json.dumps(value,separators=(",",":"))+"\n")


def spans(ports):
    values=sorted(set(ports))
    if not values:return []
    out=[];start=end=values[0]
    for port in values[1:]:
        if port==end+1:end=port
        else:out.append(str(start) if start==end else f"{start}:{end}");start=end=port
    out.append(str(start) if start==end else f"{start}:{end}")
    return out


def check_firewall():
    if shutil.which("ufw") is None:
        return False
    info=pathlib.Path("/etc/os-release").read_text()
    if not any(token in info for token in ('ID=debian','ID=ubuntu','ID_LIKE=debian')):
        raise RuntimeError("automatic firewall requires a Debian-family host")
    status=subprocess.run(["ufw","status"],check=True,capture_output=True,text=True,env={**os.environ,"LC_ALL":"C"}).stdout
    if "Status: active" not in status:raise RuntimeError("The host firewall must be active before starting Weroxy")
    return True


def open_firewall(value):
    if not check_firewall():
        print("Automatic firewall configuration skipped: manager not installed.", flush=True)
        return []
    rules=spans([outside for outside,_ in value["ports"]])
    added=[]
    try:
        for rule in rules:
            result=subprocess.run(["ufw","allow",f"{rule}/tcp","comment","Weroxy"],check=True,capture_output=True,text=True,env={**os.environ,"LC_ALL":"C"})
            if "Rule added" in result.stdout:added.append(rule)
        status=subprocess.run(["ufw","status"],check=True,capture_output=True,text=True,env={**os.environ,"LC_ALL":"C"}).stdout
        for rule in rules:
            if f"{rule}/tcp" not in status:raise RuntimeError(f"Firewall rule verification failed: {rule}")
    except Exception:
        for rule in reversed(added):
            subprocess.run(["ufw","--force","delete","allow",f"{rule}/tcp"],capture_output=True)
        raise
    return added


def verify_ingress(value, data_dir):
    """Check Docker's live bindings and exercise each active host TCP entry."""
    snapshot = json.loads((data_dir / "deployment-publication.json").read_text())
    published = {(int(row["host_port"]), int(row["container_port"]), row["host_ip"])
                 for row in snapshot["ports"]}
    host = value["host_ip"]
    for outside, inside in value["ports"]:
        if (outside, inside, host) not in published:
            raise RuntimeError(f"Container ingress mapping missing for TCP {outside}")
    active = {outside for outside, inside in value["ports"] if inside in (4900, 29999, 9415)}
    with sqlite3.connect(f"file:{data_dir / 'weroxy.db'}?mode=ro", uri=True, timeout=5) as db:
        for table in ("legacy_forwards", "weroxy_forwards"):
            for (listen,) in db.execute(f"SELECT listen FROM {table}"):
                active.add(int(listen.rsplit(":", 1)[1]))
        for (port,) in db.execute("SELECT DISTINCT port FROM data_assignments WHERE state='serving'"):
            active.add(int(port))
    dial_host = "127.0.0.1" if host == "0.0.0.0" else host
    for port in sorted(active):
        if port not in {outside for outside, _ in value["ports"]}:
            raise RuntimeError(f"active TCP port {port} is not published")
        try:
            with socket.create_connection((dial_host, port), timeout=2):
                pass
        except OSError as error:
            raise RuntimeError(f"Container ingress TCP {port} did not accept a host connection") from error


def close_firewall(rules):
    for rule in reversed(rules):
        subprocess.run(["ufw", "--force", "delete", "allow", f"{rule}/tcp"],
                       check=True, capture_output=True, text=True,
                       env={**os.environ, "LC_ALL": "C"})
