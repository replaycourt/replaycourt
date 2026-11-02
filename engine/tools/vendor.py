#!/usr/bin/env python3
"""Verify or re-fetch the vendored third-party Solidity files at their pinned upstream commits.

  python3 -I engine/tools/vendor.py verify          # compare engine/vendor/ with vendor/VENDOR.json
  python3 -I engine/tools/vendor.py fetch           # download missing/changed files, then verify
  python3 -I engine/tools/vendor.py fetch --dest D  # download into another directory (for a check)

Downloads come from raw.githubusercontent.com at the commit pinned in VENDOR.json and are
accepted only if their sha256 matches the pin. Standard library only.
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.normpath(os.path.join(HERE, "..", "vendor"))
LOCK = os.path.join(VENDOR, "VENDOR.json")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("action", choices=["verify", "fetch"])
    p.add_argument("--dest", default=VENDOR, help="vendor directory (default: engine/vendor)")
    args = p.parse_args(argv)
    with open(LOCK, encoding="utf-8") as fh:
        lock = json.load(fh)
    bad = 0
    for src in lock["sources"]:
        for rel, want in sorted(src["files"].items()):
            local = os.path.join(args.dest, src["dir"], rel)
            ok = os.path.isfile(local) and sha256_file(local) == want
            if not ok and args.action == "fetch":
                url = "https://raw.githubusercontent.com/%s/%s/%s" % (src["repo"], src["commit"], rel)
                with urllib.request.urlopen(url, timeout=60) as resp:
                    data = resp.read()
                if hashlib.sha256(data).hexdigest() != want:
                    print("HASH MISMATCH %s (%s)" % (rel, url))
                    bad += 1
                    continue
                os.makedirs(os.path.dirname(local), exist_ok=True)
                with open(local + ".part", "wb") as fh:
                    fh.write(data)
                os.replace(local + ".part", local)
                ok = True
                print("fetched  %s/%s" % (src["dir"], rel))
            if not ok:
                print("MISSING/CHANGED %s/%s" % (src["dir"], rel))
                bad += 1
    total = sum(len(s["files"]) for s in lock["sources"])
    print("%d of %d vendored files match their pinned sha256" % (total - bad, total))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
