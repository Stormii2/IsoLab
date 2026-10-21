#!/usr/bin/env python3
"""Tests for apply_policy.py (no root needed: the process launcher is faked).

The fake launcher behaves like the real system in one controlled way: a run
costs BASE ns/call, plus the table's seccomp cost if (and only if) the launched
command line contains --seccomp. So these tests check that the enforcer
launches what the policy decided and that its measured-vs-predicted arithmetic
is right. They do NOT replace running it on the VM.

    python3 test_apply.py
"""
import random

import apply_policy as A
import policy as P

T = P.load_cost_table()
SECCOMP_NS = T["seccomp"][0]
BASE = 1200.0


def fake_runner(log):
    def run(cmd):
        log.append(cmd)
        rate = float(cmd[-2])
        cpu_ns = BASE + (SECCOMP_NS if "--seccomp" in cmd else 0.0)
        return (f"isolate banner line\n{rate:.0f},{int(rate*3)},3.0000,{cpu_ns*rate*3*1e-9:.6f},"
                f"{rate:.1f},{cpu_ns+900:.2f},{cpu_ns:.2f}\n")
    return run


def decide(name, rate, threat):
    return P.Policy(T).decide(name, rate, threat)


def test_build_cmd():
    cmd = A.build_cmd({"ns", "cgroups", "caps"}, 20000, 3)
    assert cmd == ["./isolate", "--ns", "--cgroup", "--caps", "--quiet", "--", "./rate_workload", "20000", "3"]


def test_parse_real_output_line():
    # line copied from a real ./rate_workload run
    r = A.parse("20000,40000,2.0001,0.048904,19999.0,1222.61,168.63\n")
    assert r["calls"] == 40000 and abs(r["busy_ns"] - 168.63) < 1e-9


def test_enforcer_launches_exactly_the_decision():
    for name, rate, threat in [("a", 20_000, "internal"), ("b", 2_000_000, "internal"),
                               ("c", 3_000_000, "untrusted"), ("d", 500_000, "trusted")]:
        d = decide(name, rate, threat)
        log = []
        A.measure({"policy": set(d["enabled"])}, rate, 3, 1, fake_runner(log))
        flags = {c for c in log[0] if c.startswith("--") and c != "--quiet" and c != "--"}
        want = {A.P.FLAG[p] for p in d["enabled"]}
        assert flags == want, (name, flags, want)


def test_low_rate_internal_runs_with_seccomp_high_rate_without():
    log = []
    A.evaluate(decide("a", 20_000, "internal"), T, 0.01, 3, 3, fake_runner(log))
    assert any("--seccomp" in c for c in log)
    pol_runs = [c for c in log if "--ns" in c and "--caps" in c and "--cgroup" in c]
    log2 = []
    A.evaluate(decide("b", 2_000_000, "internal"), T, 0.01, 3, 3, fake_runner(log2))
    # policy run for the busy tenant must not use seccomp; the 'full' comparator still does
    no_sec = [c for c in log2 if "--seccomp" not in c and "--ns" in c]
    assert no_sec, "busy internal tenant should have a run without seccomp"


def test_measured_matches_predicted_when_system_behaves_as_modelled():
    random.seed(1)
    r = A.evaluate(decide("a", 20_000, "internal"), T, 0.01, 3, 5, fake_runner([]))
    assert abs(r["policy_added_ns"] - SECCOMP_NS) < 1e-6
    assert abs(r["policy_meas_pct"] - r["policy_pred_pct"]) < 1e-6
    assert r["floor_ok"] and r["within_budget_measured"]


def test_policy_saves_cpu_against_full_lockdown_for_busy_tenant():
    r = A.evaluate(decide("b", 2_000_000, "internal"), T, 0.01, 3, 5, fake_runner([]))
    assert r["policy_added_ns"] == 0 and r["full_added_ns"] > 50
    assert r["saved_pct"] > 0.5            # ~2M/s x 62 ns = 12.5% of a CPU


def test_noise_swamping_the_effect_is_not_called_a_violation():
    # busy_ns jitters by ~1500 ns between trials: at 20k/s that is 3% of a CPU,
    # far above the 0.14% effect, so the verdict must not be OVER.
    jitter = iter([0, 1500, 0, 1500, 0, 1500] * 20)
    def noisy(cmd):
        rate = float(cmd[-2])
        cpu_ns = BASE + (SECCOMP_NS if "--seccomp" in cmd else 0.0) + next(jitter)
        return f"{rate:.0f},{int(rate*3)},3.0,0.1,{rate:.1f},{cpu_ns+900:.2f},{cpu_ns:.2f}\n"
    r = A.evaluate(decide("a", 20_000, "internal"), T, 0.01, 3, 3, noisy)
    assert r["noise_pct"] > r["policy_pred_pct"]
    assert r["budget_verdict"] != "OVER"


def test_untrusted_over_budget_is_flagged_not_weakened():
    r = A.evaluate(decide("c", 3_000_000, "untrusted"), T, 0.01, 3, 3, fake_runner([]))
    assert r["floor_ok"] and r["seccomp"] == "ON"
    assert not r["within_budget_measured"]


def test_dynamic_sequence_applies_hysteresis_to_real_launches():
    log = []
    rows = A.run_dynamic(T, 0.01, 3, 1, fake_runner(log))
    seq = [r["seccomp"] for r in rows]
    # budget 1%, seccomp 62.46 ns: drop above ~160k/s, restore below ~128k/s
    assert seq == ["ON", "ON", "off", "off", "ON", "ON", "ON"], seq


if __name__ == "__main__":
    n = 0
    for k, v in sorted(globals().items()):
        if k.startswith("test_"):
            v(); n += 1; print("PASS", k)
    print(f"{n} tests passed")
