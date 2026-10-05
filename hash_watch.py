"""File-integrity watcher (SHA-256) with change/appear/disappear alerts.

Stores baseline hashes in a JSON db, then polls and reports:
changed file, new file appeared, or watched file disappeared.

Usage examples:
    python hash_watch.py --watch notes.txt --interval 60
    python hash_watch.py --watch a.dll b.conf --interval 30 --db hashes.json --once
    python hash_watch.py --watch data.db --interval 10 --alert-log alerts.log

Platform notes:
    Windows + Linux. Ctrl+C exits cleanly. Stdlib only.

Dependencies:
    Standard library only (argparse, sys, os, json, time, hashlib,
    datetime, pathlib).
"""

import argparse
import datetime
import hashlib
import json
import os
import sys
import time
from pathlib import Path

DEFAULT_DB = os.path.join(str(Path.home()), ".hash_watch.json")
CHUNK = 1024 * 1024  # hash 1 MiB at a time


def sha256_of(path):
    """Return hex SHA-256 of a file, or None if it cannot be read."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def load_db(path):
    """Load {filepath: hexdigest-or-None} mapping; empty dict if missing."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (ValueError, OSError) as e:
        print("warning: could not read db (%s); starting fresh." % e,
              file=sys.stderr)
        return {}


def save_db(path, data):
    """Write db mapping as JSON (creates parent dirs as needed)."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def alert(msg, log_path=None):
    """Print an alert line and optionally append it to a log file."""
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    line = "[%s] %s" % (stamp, msg)
    print(line, flush=True)
    if log_path:
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            print("warning: cannot write alert log: %s" % e, file=sys.stderr)


def check_once(targets, db):
    """Compare current state vs db; return list of event strings."""
    events = []
    for t in targets:
        exists = os.path.isfile(t)
        current = sha256_of(t) if exists else None
        previous = db.get(t, "NO-BASELINE")

        if previous == "NO-BASELINE":
            db[t] = current
            events.append("BASELINE %s (%s)" % (
                t, current[:12] if current else "missing"))
        elif previous is None and current is None:
            pass  # still missing, no news
        elif previous is None and current is not None:
            db[t] = current
            events.append("APPEARED %s (%s)" % (t, current[:12]))
        elif previous is not None and current is None:
            db[t] = None
            events.append("DISAPPEARED %s" % t)
        elif previous != current:
            db[t] = current
            events.append("CHANGED %s (%s -> %s)" % (
                t, previous[:12], current[:12]))
    return events


def build_parser(default_db=DEFAULT_DB):
    p = argparse.ArgumentParser(description="Watch files for SHA-256 changes.")
    p.add_argument("--watch", nargs="+", required=True,
                   help="Files to watch (one or more paths).")
    p.add_argument("--interval", type=float, default=60,
                   help="Poll interval in seconds (default: %(default)s).")
    p.add_argument("--db", default=default_db,
                   help="JSON hash database path (default: %(default)s).")
    p.add_argument("--alert-log", default=None,
                   help="Append alerts to this log file.")
    p.add_argument("--once", action="store_true",
                   help="Check once and exit (no polling loop).")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.interval <= 0:
        print("error: --interval must be > 0", file=sys.stderr)
        return 2

    # Normalize to absolute paths so the db is stable across cwd changes.
    targets = [os.path.abspath(t) for t in args.watch]
    db = load_db(args.db)

    def run_check():
        events = check_once(targets, db)
        save_db(args.db, db)
        for e in events:
            kind = e.split(" ", 1)[0]
            if kind == "BASELINE":
                print("%s" % e, flush=True)
            else:
                alert(e, args.alert_log)
        if not events:
            print("ok: no changes (%s)." % ", ".join(targets), flush=True)

    run_check()
    if args.once:
        return 0

    print("watching %d file(s) every %ss (Ctrl+C to stop)."
          % (len(targets), args.interval))
    try:
        while True:
            time.sleep(args.interval)
            run_check()
    except KeyboardInterrupt:
        print("\nstopped by user; db saved to %s" % args.db)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
