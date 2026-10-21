#!/usr/bin/env python3
"""
M9 enforcement + evaluation: apply the policy to real tenants and test it.

policy.py DECIDES. This script ENFORCES and CHECKS:
  1. For each tenant (name, syscall rate, threat) it asks the policy for a
     posture and launches the tenant's workload under exactly that posture via
     ./isolate (a rate-limited getpid workload, ./rate_workload).
  2. It also runs the same workload with no isolation (baseline) and with full
     lockdown (the static alternative a cloud would use without a policy).
  3. It compares MEASURED added CPU with the policy's PREDICTION, and the
     policy's posture with full lockdown.

Run on the VM (needs root, cgroup delegation done, `make` built):
    sudo ./apply_policy.py --table summary.csv                # 4 example tenants
    sudo ./apply_policy.py --table summary.csv --dynamic      # rate changes over time
    ./apply_policy.py --table summary.csv --dry-run           # decisions only, runs nothing
    sudo ./apply_policy.py --tenants tenants.json             # your own tenants

tenants.json: [{"name": "api", "rate": 50000, "threat": "internal"}, ...]

Measurement: for each configuration the workload reports busy nanoseconds per
call (time inside the syscall bursts only, so sleeping and wake-up noise are
excluded). Added cost per call = median(config) - median(L0). Measured
overhead = added_ns x achieved_rate. Trials are interleaved across
configurations in shuffled order so drift in the VM does not line up with one
configuration.

Verdicts are noise-aware. noise% = (max-min of busy_ns across trials) x rate.
A prediction counts as consistent when |measured - predicted| <= noise%, and a
tenant is only called OVER budget when measured - noise% exceeds the budget.
Where noise% is larger than the effect itself the result is reported as such,
not as a pass or a fail.
"""
import argparse
import csv
import json
import os
import random
import statistics as st
import subprocess
import sys

import policy as P

WORKLOAD = "./rate_workload"
ALL = set(P.PRIMS)

DEFAULT_TENANTS = [
    {"name": "trading-bot", "rate": 500_000, "threat": "trusted"},
    {"name": "billing-svc", "rate": 20_000, "threat": "internal"},
    {"name": "etl-job", "rate": 2_000_000, "threat": "internal"},
    {"name": "user-code-fn", "rate": 3_000_000, "threat": "untrusted"},
]
DYNAMIC_RATES = [10_000, 100_000, 200_000, 150_000, 120_000, 100_000, 10_000]


def build_cmd(prims, rate, secs):
    """The exact process the enforcer launches for a posture."""
    flags = [P.FLAG[p] for p in P.PRIMS if p in prims]
    return ["./isolate", *flags, "--quiet", "--", WORKLOAD, str(int(rate)), str(secs)]


def real_runner(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}\n  exit {r.returncode}\n  {r.stderr.strip()}")
    return r.stdout


def parse(out):
    """rate_workload line -> dict. Takes the last CSV line (isolate may print a banner)."""
    line = [l for l in out.strip().splitlines() if l.count(",") == 6][-1]
    t, calls, wall, cpu, achieved, cpu_call, busy_call = line.split(",")
    return {"target": float(t), "calls": int(calls), "wall_s": float(wall),
            "cpu_s": float(cpu), "achieved": float(achieved),
            "cpu_ns": float(cpu_call), "busy_ns": float(busy_call)}


def measure(configs, rate, secs, trials, runner):
    """configs: {label: set(prims)}. Returns {label: {'cpu_ns': median, 'achieved': median}}."""
    got = {k: [] for k in configs}
    for _ in range(trials):
        order = list(configs)
        random.shuffle(order)
        for label in order:
            got[label].append(parse(runner(build_cmd(configs[label], rate, secs))))
    return {k: {"busy_ns": st.median(r["busy_ns"] for r in v),
                "achieved": st.median(r["achieved"] for r in v),
                "spread": max(r["busy_ns"] for r in v) - min(r["busy_ns"] for r in v)}
            for k, v in got.items()}


def evaluate(decision, table, budget, secs, trials, runner):
    """Run baseline / policy / full lockdown for one decision and score it."""
    rate = decision["rate"]
    chosen = set(decision["enabled"])
    cfgs = {"base": set(), "policy": chosen, "full": ALL}
    m = measure(cfgs, rate, secs, trials, runner)
    rate_eff = m["policy"]["achieved"]
    base = m["base"]["busy_ns"]
    row = {
        "tenant": decision["tenant"], "threat": decision["threat"], "rate": rate,
        "achieved_rate": round(rate_eff),
        "policy_enabled": "+".join(decision["enabled"]) or "none",
        "seccomp": "ON" if "seccomp" in chosen else "off",
        "policy_added_ns": m["policy"]["busy_ns"] - base,
        "full_added_ns": m["full"]["busy_ns"] - base,
        "noise_ns": max(v["spread"] for v in m.values()),
    }
    row["policy_pred_pct"] = P.overhead_fraction(chosen, rate, table) * 100
    row["policy_meas_pct"] = row["policy_added_ns"] * rate_eff * 1e-7   # ns*calls/s*1e-9*100
    row["full_pred_pct"] = P.overhead_fraction(ALL, rate, table) * 100
    row["full_meas_pct"] = row["full_added_ns"] * rate_eff * 1e-7
    row["saved_pct"] = row["full_meas_pct"] - row["policy_meas_pct"]
    row["budget_pct"] = budget * 100
    row["floor_ok"] = P.REQUIRED[decision["threat"]] <= chosen      # security floor honoured
    row["noise_pct"] = row["noise_ns"] * rate_eff * 1e-7
    err = abs(row["policy_meas_pct"] - row["policy_pred_pct"])
    row["prediction"] = "consistent" if err <= max(row["noise_pct"], 0.005) else "MISMATCH"
    row["resolvable"] = row["noise_pct"] < row["policy_pred_pct"] or row["noise_pct"] < 0.05
    if row["policy_meas_pct"] - row["noise_pct"] > budget * 100:
        row["budget_verdict"] = "OVER"
    elif row["policy_meas_pct"] <= budget * 100:
        row["budget_verdict"] = "ok"
    else:
        row["budget_verdict"] = "marginal"      # over the line only by less than the noise
    row["within_budget_measured"] = row["budget_verdict"] != "OVER"
    return row


def show_row(r):
    print(f"{r['tenant']:13s} {r['threat']:9s} {r['rate']:>9,}/s  -> {r['policy_enabled']}")
    print(f"    policy : predicted {r['policy_pred_pct']:6.3f}%  measured {r['policy_meas_pct']:6.3f}%"
          f"  (+{r['policy_added_ns']:.1f} ns/call)   budget {r['budget_pct']:.1f}%"
          f"  {r['budget_verdict']}")
    print(f"    full   : predicted {r['full_pred_pct']:6.3f}%  measured {r['full_meas_pct']:6.3f}%"
          f"  (+{r['full_added_ns']:.1f} ns/call)")
    print(f"    saved by policy vs full lockdown: {r['saved_pct']:.3f}% of a CPU;"
          f" security floor honoured: {'yes' if r['floor_ok'] else 'NO'};"
          f" noise +/-{r['noise_pct']:.3f}% ({r['noise_ns']:.1f} ns); prediction {r['prediction']}\n")


COLS = ["tenant", "threat", "rate", "achieved_rate", "policy_enabled", "seccomp",
        "policy_added_ns", "policy_pred_pct", "policy_meas_pct",
        "full_added_ns", "full_pred_pct", "full_meas_pct", "saved_pct",
        "budget_pct", "floor_ok", "budget_verdict", "noise_ns", "noise_pct", "prediction"]


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()})


def run_tenants(tenants, table, budget, secs, trials, runner):
    pol = P.Policy(table, budget)
    rows = []
    for t in tenants:
        d = pol.decide(t["name"], t["rate"], t["threat"])
        rows.append(evaluate(d, table, budget, secs, trials, runner))
        show_row(rows[-1])
    return rows


def run_dynamic(table, budget, secs, trials, runner, rates=None, threat="internal"):
    """One tenant whose syscall rate changes; the policy re-decides and the new
    posture is actually launched each phase (stateful, with hysteresis)."""
    pol = P.Policy(table, budget)
    rows = []
    print(f"{'phase':>5} {'rate/s':>9}  seccomp  predicted%  measured%  noise%   prediction  (full lockdown measured%)")
    for i, rate in enumerate(rates or DYNAMIC_RATES, 1):
        d = pol.decide("web-api", rate, threat)
        r = evaluate(d, table, budget, secs, trials, runner)
        r["phase"] = i
        rows.append(r)
        print(f"{i:>5} {rate:>9,}  {r['seccomp']:>7}  {r['policy_pred_pct']:9.3f}  "
              f"{r['policy_meas_pct']:9.3f}  {r['noise_pct']:6.3f}  {r['prediction']:>10}  ({r['full_meas_pct']:.3f})")
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--table", help="summary.csv from analyze.py (default: built-in verified values)")
    ap.add_argument("--tenants", help="JSON list of {name, rate, threat}")
    ap.add_argument("--dynamic", action="store_true", help="one tenant, changing rate")
    ap.add_argument("--budget", type=float, default=P.DEFAULT_BUDGET)
    ap.add_argument("--secs", type=float, default=3.0, help="seconds per workload run")
    ap.add_argument("--trials", type=int, default=5, help="interleaved trials per configuration")
    ap.add_argument("--out", default="policy_eval.csv")
    ap.add_argument("--dry-run", action="store_true", help="show decisions and commands, run nothing")
    a = ap.parse_args()

    table = P.load_cost_table(a.table)
    tenants = json.load(open(a.tenants)) if a.tenants else DEFAULT_TENANTS

    if a.dry_run:
        pol = P.Policy(table, a.budget)
        items = ([("web-api", r, "internal") for r in DYNAMIC_RATES] if a.dynamic
                 else [(t["name"], t["rate"], t["threat"]) for t in tenants])
        for name, rate, threat in items:
            d = pol.decide(name, rate, threat)
            print(f"{name:13s} {threat:9s} {rate:>9,}/s -> {'+'.join(d['enabled']) or 'none'}")
            print("   would run:", " ".join(build_cmd(set(d["enabled"]), rate, a.secs)))
        return 0

    if os.geteuid() != 0:
        sys.exit("run with sudo (isolate needs root), or use --dry-run")
    for need in ("./isolate", WORKLOAD):
        if not os.path.exists(need):
            sys.exit(f"{need} missing - run `make` first")

    rows = (run_dynamic(table, a.budget, a.secs, a.trials, real_runner) if a.dynamic
            else run_tenants(tenants, table, a.budget, a.secs, a.trials, real_runner))
    write_csv(a.out, rows)
    ok = all(r["floor_ok"] for r in rows)
    print(f"wrote {a.out}   security floor honoured for every tenant: {'yes' if ok else 'NO'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
