#!/usr/bin/env python3
"""
M1 - Experiment Orchestrator, plus the M7 normalisation step.

Expands the configuration matrix, randomises run order, executes each run,
and appends one tidy long-format row per measurement to results.csv.

Run as root:
    sudo ./run_matrix.py --reps 30
    sudo ./run_matrix.py --reps 5 --syscalls getpid,write --levels L0,L3,L5

The calibration arm (M6) is implemented here as the `probes` column: every
configuration is run twice, once with the eBPF collector attached and once
without, so instrumentation cost can be subtracted rather than assumed zero.
"""
import argparse
import csv
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ISOLATE = os.path.join(HERE, "isolate")
BENCH = os.path.join(HERE, "bench_syscall")
COLLECTOR = os.path.join(HERE, "syscall_lat.bt")

LEVELS = ["L0", "L1", "L2", "L3", "L4", "L5"]
SYSCALLS = ["getpid", "close", "write", "read", "openclose", "stat", "mmap"]


def manifest():
    """Everything needed to decide whether two runs are comparable."""
    def read(path):
        try:
            with open(path) as f:
                return f.read().strip()
        except OSError:
            return "unknown"

    mit = {}
    vdir = "/sys/devices/system/cpu/vulnerabilities"
    if os.path.isdir(vdir):
        for name in sorted(os.listdir(vdir)):
            mit[name] = read(os.path.join(vdir, name))

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kernel": platform.release(),
        "governor": read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "smt": read("/sys/devices/system/cpu/smt/control"),
        "aslr": read("/proc/sys/kernel/randomize_va_space"),
        "cgroup_v2": os.path.exists("/sys/fs/cgroup/cgroup.controllers"),
        "nr_cpus": os.cpu_count(),
        "mitigations": mit,
    }


def preflight():
    problems = []
    if os.geteuid() != 0:
        problems.append("must run as root (namespaces and cgroup v2 writes)")
    for p in (ISOLATE, BENCH):
        if not os.path.exists(p):
            problems.append(f"missing {p} - run `make` first")
    if not os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
        problems.append("cgroup v2 unified hierarchy not mounted at /sys/fs/cgroup")
    gov = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
    if os.path.exists(gov):
        with open(gov) as f:
            if f.read().strip() != "performance":
                problems.append("CPU governor is not 'performance' - results will drift")
    return problems


def start_collector():
    if not shutil.which("bpftrace"):
        return None
    proc = subprocess.Popen(
        ["bpftrace", COLLECTOR],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    time.sleep(2.5)          # let the programs verify and attach
    return proc


def stop_collector(proc):
    if proc is None:
        return ""
    proc.terminate()
    try:
        out, _ = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return out


def one_run(level, syscall, iters, reps, rules, density, probes, taskset_cpu):
    cmd = []
    if taskset_cpu is not None:
        cmd += ["taskset", "-c", str(taskset_cpu)]
    cmd += [ISOLATE, "--quiet", "--level", level, "--seccomp-rules", str(rules),
            "--", BENCH, syscall, str(iters), str(reps)]

    collector = start_collector() if probes else None
    tenants = []
    try:
        # Co-tenants for the density arm: identical workload, unmeasured.
        for _ in range(density - 1):
            tenants.append(subprocess.Popen(
                [ISOLATE, "--quiet", "--level", level, "--seccomp-rules", str(rules),
                 "--", BENCH, syscall, str(iters * 50), "1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    finally:
        for t in tenants:
            t.terminate()
        collector_out = stop_collector(collector)

    if res.returncode != 0:
        sys.stderr.write(f"  FAILED {level}/{syscall}: {res.stderr.strip()[:200]}\n")
        return [], collector_out

    rows = []
    for line in res.stdout.strip().splitlines():
        parts = line.split(",")
        if len(parts) == 5:
            rows.append({"rep": int(parts[1]), "iterations": int(parts[2]),
                         "total_ns": int(parts[3]), "ns_per_call": float(parts[4])})
    return rows, collector_out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--iters", type=int, default=1000000)
    ap.add_argument("--levels", default=",".join(LEVELS))
    ap.add_argument("--syscalls", default=",".join(SYSCALLS))
    ap.add_argument("--densities", default="1,4,8")
    ap.add_argument("--rules", default="150")
    ap.add_argument("--cpu", type=int, default=2, help="pin the measured workload to this CPU")
    ap.add_argument("--out", default=os.path.join(HERE, "results.csv"))
    ap.add_argument("--skip-preflight", action="store_true")
    args = ap.parse_args()

    problems = preflight()
    if problems and not args.skip_preflight:
        print("Preflight failed:")
        for p in problems:
            print("  -", p)
        print("\nFix these, or pass --skip-preflight to run anyway (results not trustworthy).")
        return 1

    man = manifest()
    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(man, f, indent=2)
    print(f"kernel {man['kernel']}  governor {man['governor']}  cpus {man['nr_cpus']}")

    levels = args.levels.split(",")
    syscalls = args.syscalls.split(",")
    densities = [int(d) for d in args.densities.split(",")]
    rules = [int(r) for r in args.rules.split(",")]

    matrix = [(lv, sc, d, r, pr)
              for lv in levels for sc in syscalls
              for d in densities for r in rules for pr in (True, False)]
    random.shuffle(matrix)          # decorrelate thermal drift from configuration

    new = not os.path.exists(args.out)
    fh = open(args.out, "a", newline="")
    w = csv.writer(fh)
    if new:
        w.writerow(["run_id", "level", "syscall", "density", "seccomp_rules",
                    "probes", "rep", "iterations", "ns_per_call", "kernel"])

    print(f"{len(matrix)} configurations x {args.reps} reps\n")
    for n, (lv, sc, d, r, pr) in enumerate(matrix, 1):
        run_id = f"{lv}-{sc}-d{d}-r{r}-{'p' if pr else 'n'}"
        print(f"[{n}/{len(matrix)}] {run_id}")
        rows, cout = one_run(lv, sc, args.iters, args.reps, r, d, pr, args.cpu)
        for row in rows:
            w.writerow([run_id, lv, sc, d, r, int(pr), row["rep"],
                        row["iterations"], row["ns_per_call"], man["kernel"]])
        fh.flush()
        if cout.strip():
            with open(os.path.join(HERE, f"hist_{run_id}.txt"), "w") as hf:
                hf.write(cout)

    fh.close()
    print(f"\ndone -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
