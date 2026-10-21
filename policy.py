#!/usr/bin/env python3
"""
M9 - Isolation policy engine (Review 3 prototype).

Turns the measured per-primitive cost table (summary.csv from analyze.py) into
a decision: given a tenant's syscall rate and threat profile, choose the set of
isolation primitives to enable, and emit the exact `isolate` command for it.

Idea
----
analyze.py showed that the primitives' costs are additive (ladder check, ~1.4%
gap) and that only seccomp has a cost distinguishable from noise. So the CPU
cost of ANY subset of primitives is just the sum of four measured numbers, and
a scheduler can price a security posture without re-benchmarking.

Decision rule
-------------
1. The tenant's threat profile fixes a REQUIRED set of primitives (a floor that
   is never traded away).
2. Remaining primitives are OPTIONAL hardening. Each is enabled only if the
   tenant's resulting overhead stays inside its CPU budget:
        overhead = syscall_rate * sum(cost_ns of enabled primitives) * 1e-9
3. Dynamic: Policy.decide() is stateful per tenant and uses hysteresis, so an
   optional primitive is dropped when overhead exceeds the budget, but only
   re-enabled once overhead falls below RESTORE_FRACTION * budget. This stops
   flapping when a tenant's rate hovers near the threshold.

    ./policy.py --rate 50000 --threat internal
    ./policy.py --rate 2000000 --threat internal --table summary.csv
    ./policy.py --demo
"""
import argparse
import csv
import sys

PRIMS = ["ns", "cgroups", "seccomp", "caps"]          # ladder order L1..L4
LADDER_LEVEL = {"ns": "L1", "cgroups": "L2", "seccomp": "L3", "caps": "L4"}
FLAG = {"ns": "--ns", "cgroups": "--cgroup", "seccomp": "--seccomp", "caps": "--caps"}

# Security floor per threat profile. This is a policy choice, not a measurement.
REQUIRED = {
    "trusted":   {"cgroups"},                          # fairness only
    "internal":  {"ns", "cgroups", "caps"},            # isolate + least privilege
    "untrusted": {"ns", "cgroups", "caps", "seccomp"}, # full lockdown
}
# Order in which optional primitives are considered (most attack-surface
# reduction first). Policy choice, not a measurement.
HARDENING_ORDER = ["seccomp", "ns", "caps", "cgroups"]

DEFAULT_BUDGET = 0.01      # max fraction of tenant CPU time spent on isolation
RESTORE_FRACTION = 0.8     # hysteresis: re-enable only below 80% of budget

# Fallback used if no summary.csv is given: the verified getpid / density-1 run
# (L0..L5 means 165.03, 164.84, 164.79, 227.25, 226.59, 227.47 ns/call).
# Only seccomp's delta was distinguishable from noise (non-overlapping CIs).
FALLBACK = {
    "ns":      (-0.19, False),
    "cgroups": (-0.05, False),
    "seccomp": (62.46, True),
    "caps":    (-0.66, False),
}


def load_cost_table(path=None):
    """Return {primitive: (marginal_ns, significant)}.

    From summary.csv: marginal = mean(level) - mean(previous level);
    significant only if the two levels' bootstrap CIs do not overlap.
    Not-significant deltas are priced at 0 (indistinguishable from noise);
    significant ones are floored at 0 (an isolation layer cannot speed up a
    syscall, a negative significant delta would be an artefact).
    """
    if not path:
        raw = FALLBACK
    else:
        rows = {}
        with open(path) as f:
            for r in csv.DictReader(f):
                rows[r["level"]] = (float(r["mean_ns"]), float(r["ci_lo"]), float(r["ci_hi"]))
        raw = {}
        prev = "L0"
        for p in PRIMS:
            lvl = LADDER_LEVEL[p]
            m0, lo0, hi0 = rows[prev]
            m1, lo1, hi1 = rows[lvl]
            raw[p] = (m1 - m0, lo1 > hi0 or hi1 < lo0)
            prev = lvl
    return {p: (max(d, 0.0) if sig else 0.0, sig) for p, (d, sig) in raw.items()}


def overhead_fraction(prims, rate, table):
    """Fraction of one CPU-second spent on isolation at `rate` syscalls/s."""
    return rate * sum(table[p][0] for p in prims) * 1e-9


def nearest_level(prims):
    """Ladder label if the set is a ladder prefix, else 'custom'."""
    for lvl, s in [("L0", set()), ("L1", {"ns"}), ("L2", {"ns", "cgroups"}),
                   ("L3", {"ns", "cgroups", "seccomp"}),
                   ("L4", {"ns", "cgroups", "seccomp", "caps"})]:
        if set(prims) == s:
            return "L4/L5" if lvl == "L4" else lvl
    return "custom"


def isolate_cmd(prims, workload="./bench_syscall getpid 2000000 5"):
    flags = " ".join(FLAG[p] for p in PRIMS if p in prims)
    return f"sudo ./isolate {flags} --quiet -- {workload}".replace("  ", " ")


class Policy:
    def __init__(self, table, budget=DEFAULT_BUDGET):
        self.table = table
        self.budget = budget
        self.state = {}                 # tenant -> set of enabled primitives

    def decide(self, tenant, rate, threat, budget=None):
        budget = self.budget if budget is None else budget
        req = REQUIRED[threat]
        prev = self.state.get(tenant, set())
        enabled = set(req)
        for p in HARDENING_ORDER:
            if p in enabled:
                continue
            was_on = p in prev
            limit = budget if was_on else budget * RESTORE_FRACTION   # hysteresis
            if overhead_fraction(enabled | {p}, rate, self.table) <= limit:
                enabled.add(p)
        self.state[tenant] = enabled
        over = overhead_fraction(enabled, rate, self.table)
        return {
            "tenant": tenant, "rate": rate, "threat": threat,
            "enabled": [p for p in PRIMS if p in enabled],
            "dropped": [p for p in PRIMS if p not in enabled],
            "level": nearest_level(enabled),
            "overhead_pct": over * 100,
            "within_budget": over <= budget,
            "command": isolate_cmd(enabled),
        }


def show(d, budget):
    print(f"tenant={d['tenant']}  rate={d['rate']:,.0f}/s  threat={d['threat']}")
    print(f"  enable : {', '.join(d['enabled']) or '(none)'}   [{d['level']}]")
    if d["dropped"]:
        print(f"  dropped: {', '.join(d['dropped'])}")
    flag = "ok" if d["within_budget"] else "OVER BUDGET (required floor exceeds budget)"
    print(f"  cost   : {d['overhead_pct']:.3f}% of a CPU (budget {budget*100:.1f}%) {flag}")
    print(f"  run    : {d['command']}\n")


def demo(table, budget):
    pol = Policy(table, budget)
    print("Cost table (ns/call added; * = distinguishable from noise):")
    for p in PRIMS:
        c, sig = table[p]
        note = "*" if (sig and c > 0) else ("(significant but negative; priced 0)" if sig else "")
        print(f"  {p:8s} {c:7.2f} {note}")
    print(f"CPU budget per tenant: {budget*100:.1f}%\n")
    print("--- static examples ---")
    for t, r, th in [("trading-bot", 500_000, "trusted"),
                     ("billing-svc", 20_000, "internal"),
                     ("etl-job", 2_000_000, "internal"),
                     ("user-code-fn", 3_000_000, "untrusted")]:
        show(pol.decide(t, r, th), budget)
    print("--- dynamic: one 'internal' tenant whose syscall rate changes ---")
    for r in [10_000, 100_000, 200_000, 150_000, 120_000, 100_000, 10_000]:
        d = pol.decide("web-api", r, "internal")
        print(f"  rate={r:>9,}/s  seccomp={'ON ' if 'seccomp' in d['enabled'] else 'off'}"
              f"  overhead={d['overhead_pct']:.3f}%")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--table", help="summary.csv from analyze.py (default: built-in verified values)")
    ap.add_argument("--rate", type=float, help="tenant syscalls per second")
    ap.add_argument("--threat", choices=sorted(REQUIRED))
    ap.add_argument("--budget", type=float, default=DEFAULT_BUDGET,
                    help="max fraction of CPU spent on isolation (default 0.01)")
    ap.add_argument("--demo", action="store_true")
    a = ap.parse_args()
    table = load_cost_table(a.table)
    if a.demo:
        demo(table, a.budget)
    elif a.rate is not None and a.threat:
        show(Policy(table, a.budget).decide("tenant", a.rate, a.threat), a.budget)
    else:
        ap.error("give --demo, or both --rate and --threat")


if __name__ == "__main__":
    sys.exit(main())
