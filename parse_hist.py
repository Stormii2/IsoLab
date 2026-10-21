#!/usr/bin/env python3
"""
M4 -> M7 bridge: turns bpftrace histogram output into tidy rows.

The collector aggregates in kernel space as log2 histograms, so percentiles
come out of the bucket distribution rather than from raw samples. That limits
resolution to a power of two, which is exactly why the deck says the
microbenchmark's userspace timing carries the headline number and eBPF carries
the per-syscall breakdown.

    ./parse_hist.py hist_L3-getpid-d1-r150-p.txt --run-id L3-getpid-d1-r150-p
    ./parse_hist.py 'hist_*.txt' --out syscall_stats.csv
"""
import argparse
import csv
import glob
import os
import re
import sys

# x86-64 syscall numbers we actually touch. Extend as workloads B and C land.
SYSCALLS = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
    8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk",
    13: "rt_sigaction", 14: "rt_sigprocmask", 16: "ioctl", 17: "pread64",
    21: "access", 22: "pipe", 32: "dup", 39: "getpid", 56: "clone",
    57: "fork", 59: "execve", 60: "exit", 61: "wait4", 63: "uname",
    72: "fcntl", 79: "getcwd", 87: "unlink", 89: "readlink", 96: "gettimeofday",
    102: "getuid", 104: "getgid", 107: "geteuid", 108: "getegid",
    110: "getppid", 137: "statfs", 157: "prctl", 158: "arch_prctl",
    202: "futex", 217: "getdents64", 218: "set_tid_address", 228: "clock_gettime",
    231: "exit_group", 257: "openat", 262: "newfstatat", 273: "set_robust_list",
    302: "prlimit64", 318: "getrandom", 334: "rseq",
}

SUF = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}
MAP_RE = re.compile(r"^@(\w+)\[(-?\d+)\]:\s*(\d+)?\s*$")
BUCKET_RE = re.compile(r"^\s*\[(\d+)([KMGT]?),?\s*(\d+)([KMGT]?)\)\s+(\d+)\s")
BUCKET0_RE = re.compile(r"^\s*\[(\d+)\]\s+(\d+)\s")


def _n(val, suf):
    return int(val) * SUF.get(suf, 1)


def parse(text):
    """Return {syscall_nr: {'buckets': [(lo, hi, count)], 'count': n, 'total_ns': n}}"""
    out = {}
    cur = None
    for line in text.splitlines():
        m = MAP_RE.match(line)
        if m:
            name, key, scalar = m.group(1), int(m.group(2)), m.group(3)
            rec = out.setdefault(key, {"buckets": [], "count": None, "total_ns": None})
            if name == "count" and scalar:
                rec["count"] = int(scalar)
                cur = None
            elif name == "total_ns" and scalar:
                rec["total_ns"] = int(scalar)
                cur = None
            else:
                cur = rec
            continue
        if cur is None:
            continue
        b = BUCKET_RE.match(line)
        if b:
            cur["buckets"].append((_n(b.group(1), b.group(2)),
                                   _n(b.group(3), b.group(4)), int(b.group(5))))
            continue
        b0 = BUCKET0_RE.match(line)
        if b0:
            lo = int(b0.group(1))
            cur["buckets"].append((lo, lo + 1, int(b0.group(2))))
    return out


def percentile(buckets, p):
    """Bucket midpoint containing the p-th percentile. Resolution is log2."""
    total = sum(c for _, _, c in buckets)
    if not total:
        return None
    target, seen = total * p, 0
    for lo, hi, c in buckets:
        seen += c
        if seen >= target:
            return (lo + hi) / 2.0
    return (buckets[-1][0] + buckets[-1][1]) / 2.0


def rows_for(path, run_id):
    with open(path) as f:
        data = parse(f.read())
    rows = []
    for nr, rec in sorted(data.items()):
        if not rec["buckets"]:
            continue
        n = rec["count"] or sum(c for _, _, c in rec["buckets"])
        total = rec["total_ns"]
        rows.append({
            "run_id": run_id,
            "syscall_nr": nr,
            "syscall": SYSCALLS.get(nr, f"syscall_{nr}"),
            "count": n,
            "mean_ns": round(total / n, 2) if total and n else "",
            "p50_ns": percentile(rec["buckets"], 0.50),
            "p95_ns": percentile(rec["buckets"], 0.95),
            "p99_ns": percentile(rec["buckets"], 0.99),
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", help="bpftrace output file(s), globs allowed")
    ap.add_argument("--run-id", help="override the run_id (default: from filename)")
    ap.add_argument("--out", default="syscall_stats.csv")
    args = ap.parse_args()

    files = []
    for p in args.paths:
        files.extend(sorted(glob.glob(p)) or ([p] if os.path.exists(p) else []))
    if not files:
        print("no input files matched", file=sys.stderr)
        return 1

    all_rows = []
    for path in files:
        stem = os.path.splitext(os.path.basename(path))[0]
        rid = args.run_id or (stem[5:] if stem.startswith("hist_") else stem)
        r = rows_for(path, rid)
        all_rows.extend(r)
        print(f"{path}: {len(r)} syscalls")

    if not all_rows:
        print("nothing parsed - check the bpftrace output format", file=sys.stderr)
        return 1

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        w.writeheader()
        w.writerows(all_rows)
    print(f"\n{len(all_rows)} rows -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
