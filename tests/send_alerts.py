#!/usr/bin/env python3
"""
Send realistic Wazuh alerts to the SOC Platform ingestion endpoint.

Phase 1 development driver: until the live Wazuh + Kali agent setup is wired
up for the final demo, this reproduces genuine Wazuh alert JSON over curl so
the whole pipeline (ingestion -> Redis -> worker -> MongoDB, and later
correlation / enrichment / agents) can be built and regression-tested against
deterministic input.

Scenarios
---------
  alice   Benign: one failed SSH login immediately followed by a success from
          the same "normal" user/IP. Should end up a false positive.
  bob     Attack: a burst of N failed SSH logins from one attacker IP, then a
          successful login, then a sudo privilege escalation — same srcip/user,
          tightly spaced timestamps. This is the pattern the Phase 2 correlation
          engine ("brute_force_then_login" + priv-esc) is built to catch.
  fixture Send one raw fixture file verbatim (tests/fixtures/*.json).
  file    Send an arbitrary JSON file verbatim.

Stdlib only — no dependencies, runs anywhere Python 3 is installed.

Examples
--------
  python tests/send_alerts.py alice
  python tests/send_alerts.py bob --count 6
  python tests/send_alerts.py bob --srcip 185.220.101.1   # public IP -> OTX hit
  python tests/send_alerts.py fixture sudo_privesc
  python tests/send_alerts.py file ./tests/fixtures/fim_change.json
  python tests/send_alerts.py bob --url http://localhost:8000/api/v1/alerts/wazuh
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
DEFAULT_URL = "http://localhost:8000/api/v1/alerts/wazuh"
DEFAULT_TOKEN = os.environ.get("SOC_INGESTION_AUTH_TOKEN", "soc-ingest-token-dev")


# ---------------------------------------------------------------------------
# Wazuh timestamp helpers
# ---------------------------------------------------------------------------

def _wazuh_ts(dt: datetime) -> str:
    """Format a datetime the way Wazuh does: 2026-07-10T14:23:11.482+0000."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+0000"


def _syslog_ts(dt: datetime) -> str:
    """Format like a syslog line prefix: 'Jul 10 14:23:11'."""
    return dt.strftime("%b %d %H:%M:%S")


# ---------------------------------------------------------------------------
# Alert builders — mirror genuine Wazuh decoder output
# ---------------------------------------------------------------------------

def build_ssh_failed(dt, srcip, user, host, agent_ip, port):
    return {
        "timestamp": _wazuh_ts(dt),
        "rule": {
            "level": 5,
            "description": "sshd: authentication failed.",
            "id": "5716",
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
            "groups": ["syslog", "sshd", "authentication_failed"],
        },
        "agent": {"id": "001", "name": host, "ip": agent_ip},
        "manager": {"name": "wazuh-manager"},
        "id": f"{dt.timestamp():.6f}",
        "full_log": (
            f"{_syslog_ts(dt)} {host} sshd[{port}]: Failed password for "
            f"{user} from {srcip} port {port} ssh2"
        ),
        "predecoder": {"program_name": "sshd", "timestamp": _syslog_ts(dt), "hostname": host},
        "decoder": {"parent": "sshd", "name": "sshd"},
        "data": {"srcip": srcip, "srcport": str(port), "dstuser": user},
        "location": "/var/log/auth.log",
    }


def build_ssh_success(dt, srcip, user, host, agent_ip, port):
    return {
        "timestamp": _wazuh_ts(dt),
        "rule": {
            "level": 3,
            "description": "sshd: authentication success.",
            "id": "5715",
            "mitre": {"id": ["T1078"], "tactic": ["Initial Access"], "technique": ["Valid Accounts"]},
            "groups": ["syslog", "sshd", "authentication_success"],
        },
        "agent": {"id": "001", "name": host, "ip": agent_ip},
        "manager": {"name": "wazuh-manager"},
        "id": f"{dt.timestamp():.6f}",
        "full_log": (
            f"{_syslog_ts(dt)} {host} sshd[{port}]: Accepted password for "
            f"{user} from {srcip} port {port} ssh2"
        ),
        "predecoder": {"program_name": "sshd", "timestamp": _syslog_ts(dt), "hostname": host},
        "decoder": {"parent": "sshd", "name": "sshd"},
        "data": {"srcip": srcip, "srcport": str(port), "dstuser": user},
        "location": "/var/log/auth.log",
    }


def build_sudo_privesc(dt, user, host, agent_ip):
    return {
        "timestamp": _wazuh_ts(dt),
        "rule": {
            "level": 8,
            "description": "First time user executed sudo.",
            "id": "5402",
            "mitre": {
                "id": ["T1548.003"],
                "tactic": ["Privilege Escalation"],
                "technique": ["Sudo and Sudo Caching"],
            },
            "groups": ["syslog", "sudo", "privilege_escalation"],
        },
        "agent": {"id": "001", "name": host, "ip": agent_ip},
        "manager": {"name": "wazuh-manager"},
        "id": f"{dt.timestamp():.6f}",
        "full_log": (
            f"{_syslog_ts(dt)} {host} sudo: {user} : TTY=pts/1 ; PWD=/home/{user} ; "
            f"USER=root ; COMMAND=/bin/bash"
        ),
        "predecoder": {"program_name": "sudo", "timestamp": _syslog_ts(dt), "hostname": host},
        "decoder": {"parent": "sudo", "name": "sudo"},
        "data": {"srcuser": user, "dstuser": "root", "tty": "pts/1",
                 "pwd": f"/home/{user}", "command": "/bin/bash"},
        "location": "/var/log/auth.log",
    }


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def send(alert: dict, url: str, token: str) -> bool:
    """POST one alert; return True on 2xx, False otherwise. Never raises."""
    payload = json.dumps(alert).encode("utf-8")
    req = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    label = f"{alert['rule']['description']} (rule {alert['rule']['id']})"
    try:
        with urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            print(f"  [{resp.getcode()}] {label} -> {body.get('status')} "
                  f"alert_id={body.get('alert_id', '-')}")
            return 200 <= resp.getcode() < 300
    except HTTPError as e:
        print(f"  [HTTP {e.code}] {label} -> {e.read().decode('utf-8', 'replace')}")
    except URLError as e:
        print(f"  [ERR] {label} -> connection failed: {e.reason}")
        print(f"        Is the ingestion service up at {url}?")
    except Exception as e:  # noqa: BLE001
        print(f"  [ERR] {label} -> {e}")
    return False


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def scenario_alice(args) -> int:
    """Benign: one fail then a success from a normal user. Expect false positive."""
    now = datetime.now(timezone.utc)
    host, agent_ip, srcip, user = "prod-web-01", "10.0.0.20", "10.0.0.15", "alice"
    srcip = args.srcip or srcip
    print("Scenario: ALICE (benign single-fail-then-success)")
    alerts = [
        build_ssh_failed(now, srcip, user, host, agent_ip, 51000),
        build_ssh_success(now + timedelta(seconds=6), srcip, user, host, agent_ip, 51001),
    ]
    return _run(alerts, args)


def scenario_bob(args) -> int:
    """Attack: brute-force burst -> success -> priv-esc, all same attacker IP/user."""
    now = datetime.now(timezone.utc)
    host, agent_ip, srcip, user = "prod-db-01", "10.0.0.50", "10.0.0.99", "baduser"
    srcip = args.srcip or srcip
    n = args.count
    print(f"Scenario: BOB (brute force x{n} -> login -> sudo priv-esc)")
    alerts = []
    t = now
    for i in range(n):
        alerts.append(build_ssh_failed(t, srcip, user, host, agent_ip, 54321 + i))
        t += timedelta(seconds=3)
    alerts.append(build_ssh_success(t, srcip, user, host, agent_ip, 54999))
    t += timedelta(seconds=8)
    alerts.append(build_sudo_privesc(t, user, host, agent_ip))
    return _run(alerts, args)


def scenario_fixture(args) -> int:
    name = args.name
    path = FIXTURES_DIR / (name if name.endswith(".json") else f"{name}.json")
    return _send_file(path, args)


def scenario_file(args) -> int:
    return _send_file(Path(args.path), args)


def _send_file(path: Path, args) -> int:
    if not path.exists():
        print(f"File not found: {path}")
        if path.parent == FIXTURES_DIR:
            available = sorted(p.stem for p in FIXTURES_DIR.glob("*.json"))
            print(f"Available fixtures: {', '.join(available)}")
        return 1
    alert = json.loads(path.read_text())
    print(f"Sending: {path.name}")
    return _run([alert], args)


def _run(alerts: list[dict], args) -> int:
    ok = 0
    for alert in alerts:
        if send(alert, args.url, args.token):
            ok += 1
        if args.delay > 0:
            time.sleep(args.delay)
    print(f"Sent {ok}/{len(alerts)} alerts successfully.")
    return 0 if ok == len(alerts) else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=DEFAULT_URL, help=f"Ingestion endpoint (default: {DEFAULT_URL})")
    parser.add_argument("--token", default=DEFAULT_TOKEN, help="Bearer token (default: $SOC_INGESTION_AUTH_TOKEN)")
    parser.add_argument("--delay", type=float, default=0.3, help="Seconds between sends (default: 0.3)")

    # Shared options for the generated scenarios (must sit on the subparsers so
    # they can be passed *after* the subcommand, e.g. `bob --srcip ...`).
    scenario_opts = argparse.ArgumentParser(add_help=False)
    scenario_opts.add_argument(
        "--srcip",
        default=None,
        help="Override the source IP for the alice/bob scenarios. Use a public "
             "IP to exercise OTX threat-intel enrichment (the default 10.0.0.x "
             "addresses are private and won't resolve in OTX).",
    )

    sub = parser.add_subparsers(dest="scenario", required=True)
    sub.add_parser(
        "alice", parents=[scenario_opts],
        help="benign single-fail-then-success",
    ).set_defaults(func=scenario_alice)

    p_bob = sub.add_parser("bob", parents=[scenario_opts], help="brute force -> login -> priv-esc")
    p_bob.add_argument("--count", type=int, default=5, help="number of failed logins (default: 5)")
    p_bob.set_defaults(func=scenario_bob)

    p_fix = sub.add_parser("fixture", help="send a named fixture from tests/fixtures/")
    p_fix.add_argument("name", help="fixture name, e.g. ssh_failed_login")
    p_fix.set_defaults(func=scenario_fixture)

    p_file = sub.add_parser("file", help="send an arbitrary JSON file")
    p_file.add_argument("path", help="path to a JSON alert file")
    p_file.set_defaults(func=scenario_file)

    args = parser.parse_args()
    # bob is the only scenario with --count; default it for the shared _run signature
    if not hasattr(args, "count"):
        args.count = 5
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
