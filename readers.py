#!/usr/bin/env python3
"""
M5 - Resource and counter readers.

Two sources, one dict out:
  perf stat      hardware and software counters for the measured process
  cgroup v2      cpu.stat, memory.current, io.stat and PSI pressure

NOTE: hardware counters (cycles, instructions, cache-misses) are unavailable
inside VirtualBox, which does not virtualise the PMU. The reader degrades to
software events and marks them unsupported rather than failing the run - but
say so in the validity-threats section if you collect data that way.

    ./readers.py --demo            # show what a single sample looks like
"""
import json
import os
import re
import shutil
import subprocess

CG = "/sys/fs/cgroup/isolab/run"

HW_EVENTS = ["cycles", "instructions", "cache-misses", "branch-misses"]
SW_EVENTS = ["context-switches", "page-faults", "task-clock"]


def perf_available():
    return shutil.which("perf") is not None


def perf_stat(cmd, events=None):
    """Run cmd under perf stat and return {event: value or None}."""
    if not perf_available():
        return {"_error": "perf not installed"}
    events = events or (HW_EVENTS + SW_EVENTS)
    out = {}
    proc = subprocess.run(
        ["perf", "stat", "-x,", "-e", ",".join(events), "--"] + cmd,
        capture_output=True, text=True)
    # -x, gives: value,unit,event,runtime,pct[,...]; "<not supported>" for no PMU
    for line in proc.stderr.strip().splitlines():
        parts = line.split(",")
        if len(parts) < 3:
            continue
        val, _unit, ev = parts[0], parts[1], parts[2]
        if val.startswith("<"):
            out[ev] = None                     # not supported (no PMU in this guest)
        else:
            try:
                out[ev] = float(val)
            except ValueError:
                out[ev] = None
    out["_pmu"] = any(out.get(e) is not None for e in HW_EVENTS)
    return out


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _kv(text):
    """Parse 'key value' lines (cpu.stat, memory.stat)."""
    d = {}
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) == 2:
            try:
                d[p[0]] = int(p[1])
            except ValueError:
                pass
    return d


def _psi(text):
    """Parse 'some avg10=0.00 ... total=1234' pressure lines."""
    d = {}
    for line in (text or "").splitlines():
        kind = line.split()[0] if line.split() else None
        if not kind:
            continue
        for m in re.finditer(r"(\w+)=([\d.]+)", line):
            d[f"{kind}_{m.group(1)}"] = float(m.group(2))
    return d


def cgroup_sample(path=CG):
    """Snapshot the run cgroup's accounting. Call before and after, then diff."""
    if not os.path.isdir(path):
        return {"_error": f"{path} does not exist"}
    cpu = _kv(_read(f"{path}/cpu.stat"))
    mem = _kv(_read(f"{path}/memory.stat"))
    io_raw = _read(f"{path}/io.stat") or ""
    io = {}
    for line in io_raw.splitlines():
        for m in re.finditer(r"(\w+)=(\d+)", line):
            io[m.group(1)] = io.get(m.group(1), 0) + int(m.group(2))
    return {
        "cpu_usage_usec": cpu.get("usage_usec"),
        "cpu_user_usec": cpu.get("user_usec"),
        "cpu_system_usec": cpu.get("system_usec"),
        "nr_throttled": cpu.get("nr_throttled"),
        "throttled_usec": cpu.get("throttled_usec"),
        "memory_current": int(_read(f"{path}/memory.current") or 0),
        "memory_anon": mem.get("anon"),
        "memory_file": mem.get("file"),
        "pgfault": mem.get("pgfault"),
        "pgmajfault": mem.get("pgmajfault"),
        "io_rbytes": io.get("rbytes"),
        "io_wbytes": io.get("wbytes"),
        "cpu_pressure": _psi(_read(f"{path}/cpu.pressure")),
        "io_pressure": _psi(_read(f"{path}/io.pressure")),
        "memory_pressure": _psi(_read(f"{path}/memory.pressure")),
    }


def delta(before, after):
    """Difference the two snapshots; PSI totals are cumulative so they diff too."""
    out = {}
    for k, v in after.items():
        b = before.get(k)
        if isinstance(v, dict) and isinstance(b, dict):
            out[k] = {kk: round(vv - b.get(kk, 0), 3) for kk, vv in v.items()
                      if isinstance(vv, (int, float))}
        elif isinstance(v, (int, float)) and isinstance(b, (int, float)):
            out[k] = v - b
        else:
            out[k] = v
    return out


if __name__ == "__main__":
    import sys
    if "--demo" in sys.argv:
        print("perf stat:")
        print(json.dumps(perf_stat(["/bin/true"]), indent=2))
        print("\ncgroup sample:")
        print(json.dumps(cgroup_sample(), indent=2, default=str))
