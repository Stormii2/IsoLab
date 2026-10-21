#!/usr/bin/env python3
"""Tests for policy.py.  Run:  python3 test_policy.py"""
import csv
import os
import tempfile

import policy as P

T = P.load_cost_table()          # built-in verified table
pol = lambda: P.Policy(T)


def test_only_seccomp_costs():
    assert T["seccomp"][0] > 50
    assert all(T[p][0] == 0 for p in ("ns", "cgroups", "caps"))


def test_floor_never_dropped():
    # Even at an absurd rate, the required set stays on.
    d = pol().decide("t", 1e9, "untrusted")
    assert set(d["enabled"]) == P.REQUIRED["untrusted"]
    assert not d["within_budget"]            # and it is flagged, not hidden


def test_low_rate_gets_everything():
    d = pol().decide("t", 1_000, "trusted")
    assert set(d["enabled"]) == set(P.PRIMS)


def test_internal_drops_seccomp_at_high_rate():
    assert "seccomp" in pol().decide("t", 10_000, "internal")["enabled"]
    d = pol().decide("t", 5_000_000, "internal")
    assert "seccomp" not in d["enabled"] and d["within_budget"]


def test_hysteresis():
    p = pol()
    assert "seccomp" in p.decide("a", 10_000, "internal")["enabled"]
    # budget 1%, cost 62.46ns -> drop above ~160k/s, restore only below ~128k/s
    assert "seccomp" not in p.decide("a", 200_000, "internal")["enabled"]
    assert "seccomp" not in p.decide("a", 140_000, "internal")["enabled"]  # inside band: stays off
    assert "seccomp" in p.decide("a", 100_000, "internal")["enabled"]


def test_tenants_independent():
    p = pol()
    p.decide("a", 5_000_000, "internal")
    assert "seccomp" in p.decide("b", 1_000, "internal")["enabled"]


def test_csv_noise_priced_zero_and_significant_kept():
    rows = [("L0", 165.0, 164, 166), ("L1", 164.8, 163.8, 165.8), ("L2", 164.8, 163.9, 165.7),
            ("L3", 227.2, 226, 228), ("L4", 226.6, 225.6, 227.6), ("L5", 227.5, 226.5, 228.5)]
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as f:
        w = csv.writer(f)
        w.writerow(["level", "label", "n", "mean_ns", "median_ns", "sd_ns", "ci_lo", "ci_hi"])
        for l, m, lo, hi in rows:
            w.writerow([l, l, 30, m, m, 0, lo, hi])
        path = f.name
    try:
        t = P.load_cost_table(path)
        assert t["seccomp"] == (227.2 - 164.8, True)
        assert t["ns"][0] == t["cgroups"][0] == t["caps"][0] == 0
    finally:
        os.unlink(path)


def test_command_uses_real_isolate_flags():
    cmd = pol().decide("t", 1_000, "untrusted")["command"]
    for f in ("--ns", "--cgroup", "--seccomp", "--caps"):
        assert f in cmd


if __name__ == "__main__":
    n = 0
    for k, v in sorted(globals().items()):
        if k.startswith("test_"):
            v(); n += 1; print("PASS", k)
    print(f"{n} tests passed")
