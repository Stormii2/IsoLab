#!/usr/bin/env python3
"""
M8 - Analysis and attribution.

Reads results.csv, subtracts the probe-cost baseline (M6), computes marginal
cost per primitive with bootstrap confidence intervals, and tests the additive
ladder assumption.

    ./analyze.py                              # defaults to results.csv
    ./analyze.py --syscall getpid --plot
    ./analyze.py --out summary.csv --plot marginal_cost.png

The printed "FOR SLIDE 11" block is the six numbers to paste into the deck's
bar chart.
"""
import argparse
import csv
import random
import statistics as st
import sys
from collections import defaultdict

LEVELS = ["L0", "L1", "L2", "L3", "L4", "L5"]
LABELS = {"L0": "L0 baseline", "L1": "L1 +namespaces", "L2": "L2 +cgroups",
          "L3": "L3 +seccomp", "L4": "L4 +capabilities", "L5": "L5 combined"}


def bootstrap_ci(vals, n=2000, conf=0.95):
    """Percentile bootstrap CI on the mean. No scipy dependency."""
    if len(vals) < 2:
        return (float("nan"), float("nan"))
    means = []
    k = len(vals)
    for _ in range(n):
        means.append(sum(random.choices(vals, k=k)) / k)
    means.sort()
    lo = means[int((1 - conf) / 2 * n)]
    hi = means[int((1 + conf) / 2 * n) - 1]
    return (lo, hi)


def load(path):
    rows = []
    with open(path) as f:
        for r in csv.DictReader(f):
            try:
                r["ns_per_call"] = float(r["ns_per_call"])
                r["probes"] = int(r["probes"])
                r["density"] = int(r["density"])
                r["seccomp_rules"] = int(r["seccomp_rules"])
            except (KeyError, ValueError):
                continue
            rows.append(r)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="results.csv")
    ap.add_argument("--syscall", default="getpid")
    ap.add_argument("--density", type=int, default=1)
    ap.add_argument("--rules", type=int, default=None,
                    help="restrict to one seccomp filter length")
    ap.add_argument("--out", default="summary.csv")
    ap.add_argument("--plot", nargs="?", const="marginal_cost.png", default=None)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.seed)

    try:
        rows = load(args.csv)
    except FileNotFoundError:
        print(f"{args.csv} not found - run run_matrix.py first.", file=sys.stderr)
        return 1
    if not rows:
        print(f"{args.csv} has no usable rows.", file=sys.stderr)
        return 1

    sel = [r for r in rows if r["syscall"] == args.syscall
           and r["density"] == args.density
           and (args.rules is None or r["seccomp_rules"] == args.rules)]
    if not sel:
        print(f"no rows for syscall={args.syscall} density={args.density}", file=sys.stderr)
        return 1

    # ---- M6: probe cost, measured rather than assumed -------------------
    by = defaultdict(lambda: defaultdict(list))
    for r in sel:
        by[r["level"]][r["probes"]].append(r["ns_per_call"])

    probe_costs = [st.mean(p[1]) - st.mean(p[0])
                   for p in by.values() if p.get(0) and p.get(1)]
    probe_cost = st.mean(probe_costs) if probe_costs else 0.0

    print(f"\nsyscall={args.syscall}  density={args.density}  "
          f"rows={len(sel)}  kernel={sel[0].get('kernel', '?')}")
    print(f"probe cost (traced - untraced): {probe_cost:+.2f} ns/call "
          f"over {len(probe_costs)} levels")
    if probe_cost > 5:
        print("  -> non-trivial: report isolation overhead from untraced runs only")

    # ---- per-level statistics on untraced runs --------------------------
    stats, order = {}, []
    for lv in LEVELS:
        vals = by.get(lv, {}).get(0) or by.get(lv, {}).get(1)
        if not vals:
            continue
        lo, hi = bootstrap_ci(vals)
        stats[lv] = {"n": len(vals), "mean": st.mean(vals),
                     "median": st.median(vals),
                     "sd": st.pstdev(vals) if len(vals) > 1 else 0.0,
                     "ci_lo": lo, "ci_hi": hi}
        order.append(lv)

    print("\nLevel              n      mean      median        95% CI")
    print("-" * 62)
    for lv in order:
        s = stats[lv]
        print(f"{LABELS[lv]:<18}{s['n']:>3}  {s['mean']:>8.2f}  {s['median']:>10.2f}"
              f"   [{s['ci_lo']:.2f}, {s['ci_hi']:.2f}]")

    # ---- marginal cost per primitive ------------------------------------
    print("\nMarginal cost (ns/call)")
    print("-" * 62)
    deltas, prev = {}, None
    for lv in order:
        if lv == "L5":
            continue
        if prev is not None:
            d = stats[lv]["mean"] - stats[prev]["mean"]
            deltas[lv] = d
            overlap = not (stats[lv]["ci_lo"] > stats[prev]["ci_hi"]
                           or stats[prev]["ci_lo"] > stats[lv]["ci_hi"])
            flag = "  (CIs overlap - not distinguishable)" if overlap else ""
            print(f"{prev} -> {lv:<4} {d:+9.2f}{flag}")
        prev = lv

    # ---- additive model check -------------------------------------------
    if "L5" in stats and "L0" in stats and deltas:
        summed = sum(deltas.values())
        measured = stats["L5"]["mean"] - stats["L0"]["mean"]
        gap = measured - summed
        print("\nAdditive model check")
        print("-" * 62)
        print(f"sum of L1-L4 deltas : {summed:8.2f} ns")
        print(f"measured L5 - L0    : {measured:8.2f} ns")
        rel = abs(gap) / measured * 100 if measured else 0
        print(f"gap                 : {gap:+8.2f} ns  ({rel:.1f}% of total)")
        print("  -> additive model holds; primitives do not interact"
              if rel < 10 else
              "  -> gap is large: primitives interact, report this as a finding")

    # ---- outputs ---------------------------------------------------------
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["level", "label", "n", "mean_ns", "median_ns", "sd_ns",
                    "ci_lo", "ci_hi", "marginal_ns", "probe_cost_ns"])
        for lv in order:
            s = stats[lv]
            w.writerow([lv, LABELS[lv], s["n"], round(s["mean"], 2),
                        round(s["median"], 2), round(s["sd"], 2),
                        round(s["ci_lo"], 2), round(s["ci_hi"], 2),
                        round(deltas.get(lv, 0), 2), round(probe_cost, 2)])
    print(f"\nwrote {args.out}")

    print("\n" + "=" * 62)
    print("FOR SLIDE 11 - paste these into the deck's bar chart")
    print("=" * 62)
    print("labels: " + ", ".join(f'"{LABELS[lv]}"' for lv in order))
    print("values: " + ", ".join(f"{stats[lv]['mean']:.1f}" for lv in order))
    print("=" * 62)

    if args.plot:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            print("\nmatplotlib not installed: pip3 install matplotlib", file=sys.stderr)
            return 0
        xs = [LABELS[lv] for lv in order]
        ys = [stats[lv]["mean"] for lv in order]
        err = [[stats[lv]["mean"] - stats[lv]["ci_lo"] for lv in order],
               [stats[lv]["ci_hi"] - stats[lv]["mean"] for lv in order]]
        cols = ["#1E2761" if stats[lv]["mean"] < min(ys) * 1.05 else "#F96167"
                for lv in order]
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.bar(xs, ys, yerr=err, capsize=4, color=cols, edgecolor="none")
        ax.set_ylabel("ns per call")
        ax.set_title(f"Marginal cost per isolation primitive - {args.syscall}, "
                     f"density {args.density}")
        ax.set_ylim(min(ys) * 0.92, max(ys) * 1.08)
        ax.grid(axis="y", color="#DCE3F0", linewidth=0.8)
        ax.set_axisbelow(True)
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
        plt.xticks(rotation=15, ha="right")
        plt.tight_layout()
        plt.savefig(args.plot, dpi=150)
        print(f"wrote {args.plot}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
