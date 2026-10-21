# isolab — execution plan

Measurement harness for *Performance–Security Trade-off in Linux Isolation for Cloud Workloads*.

Target for Review 2: **M1, M2, M3 complete; M4, M5 working; M6, M7 partial.**
That is roughly 70% of the build, and it is achievable in about two weeks of
focused work by two people.

---

## Phase 0 — Environment (day 1)

**Do not use WSL2 or a shared cloud VM for measurement.** WSL2 has a
virtualised clock and does not give you honest cgroup v2 delegation; a cloud VM
has noisy neighbours, which is the exact thing you are trying to measure. Use a
bare-metal Ubuntu 24.04 install (dual boot is fine). A local VirtualBox/VMware
VM is an acceptable fallback, but declare it as a validity threat in the report.

```bash
sudo apt update
sudo apt install -y build-essential bpftrace linux-tools-common \
     linux-tools-$(uname -r) python3 python3-pip stress-ng nginx redis-tools
```

Verify the three things the whole project depends on:

```bash
# 1. cgroup v2 unified hierarchy (must print a list including cpu and memory)
cat /sys/fs/cgroup/cgroup.controllers

# 2. bpftrace can attach
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); exit(); }'

# 3. perf works
sudo perf stat -e cycles,instructions true
```

Then fix the machine in place, once, and record it:

```bash
sudo cpupower frequency-set -g performance     # or write scaling_governor directly
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
sudo systemctl stop unattended-upgrades snapd packagekit    # background noise
nproc                                          # reserve CPU 2 for the workload
```

---

## Phase 1 — Vertical slice first (days 2–4)

Build the *narrowest thing that produces a real number*, then widen. Do not
build all eight modules before running anything.

```bash
make
./bench_syscall getpid 1000000 5          # workload A alone, no isolation
sudo ./isolate --level L0 -- ./bench_syscall getpid 1000000 5
sudo ./isolate --seccomp --seccomp-rules 150 -- ./bench_syscall getpid 1000000 5
```

If the third command shows a higher `ns_per_call` than the second, **you have
your first result** — the marginal cost of seccomp on `getpid`. Everything
after this is widening the matrix and tightening the error bars.

`make smoke` walks all six levels and tells you which ones fail.

---

## Phase 2 — Verification (day 5)

A level that silently fails to apply corrupts every downstream number. Run
`isolate` without `--quiet` and confirm each claim:

| Level | What to check | Expected |
|---|---|---|
| L1 | `readlink /proc/self/ns/pid` inside vs outside | different inode numbers |
| L2 | `cat /sys/fs/cgroup/isolab/run/cgroup.procs` | contains the workload PID |
| L3 | `Seccomp:` line in `/proc/PID/status` | `2` (filter mode) |
| L4 | `CapBnd:` line in `/proc/PID/status` | `0000000000000000` |

Write these into a script and run it before every data collection session.

---

## Phase 3 — eBPF collector (days 6–8)

```bash
sudo bpftrace syscall_lat.bt          # terminal 1
sudo ./isolate --level L2 -- ./bench_syscall getpid 2000000 5   # terminal 2
# Ctrl-C terminal 1 to print the histograms
```

If bpftrace rejects `args.id`, your build is older — use `args->id`.

### The ordering experiment (do this before collecting real data)

Seccomp is evaluated in `syscall_trace_enter()` *before* the
`raw_syscalls:sys_enter` tracepoint fires. If that holds on your kernel, eBPF
cannot see seccomp cost at all. Test it directly:

1. Run L2 (no seccomp) under the collector; record median `getpid` latency.
2. Run L3 (seccomp, 150 rules) under the collector; record it again.
3. Compare against the *userspace* `ns_per_call` from `bench_syscall` for the
   same two levels.

If userspace shows a delta and eBPF shows roughly none, the ordering is
confirmed. Put that in the report — it is a methodological finding, and it
justifies using two instruments instead of one.

### Expect the seccomp cache

Linux 5.11+ caches per-syscall allow decisions in a bitmap, so a filter that
unconditionally permits a syscall regardless of arguments is evaluated once and
then short-circuited. **Your filter-length sweep may come back flat.** That is a
real result, not a broken experiment — but you must say *why* it is flat, and
you should confirm the cache is active on your kernel before claiming it.

---

## Phase 4 — Readers and orchestrator (days 9–11)

Extend `run_matrix.py` to also capture, per run:

- `perf stat -e cycles,instructions,context-switches,cache-misses`
- `cpu.stat`, `memory.current`, `io.stat` from the run cgroup
- `cpu.pressure` (PSI) — stall time is the cleanest interference signal you have

Then start collecting:

```bash
sudo ./run_matrix.py --reps 5 --levels L0,L3 --syscalls getpid --densities 1
sudo ./run_matrix.py --reps 30                                # full matrix
```

The `probes` column is the M6 calibration arm: every configuration runs twice,
once traced and once not. Overhead attributable to isolation is
`(traced − untraced)` subtracted out, not assumed to be zero.

---

## Phase 5 — First dataset and plots (days 12–14)

You need four figures for Review 3, and two of them are enough for Review 2:

1. `ns_per_call` by level, per syscall, with 95% CIs — **the headline result**
2. Marginal cost of each primitive (L1−L0, L2−L1, L3−L2, L4−L3)
3. L5 vs the sum of those deltas — tests whether the additive model holds
4. p99 latency vs tenant density, isolated curve minus the C0 control curve

---

## What 70% looks like at Review 2

| Module | State to demonstrate |
|---|---|
| M1 Orchestrator | Matrix expansion, randomised order, `manifest.json` written |
| M2 Isolation Controller | All six levels build and verify |
| M3 Workload Runner | Workload A complete; B and C wired but not tuned |
| M4 eBPF Collector | Attaches, filters by cgroup, prints histograms |
| M5 Readers | `readers.py` reads perf, cgroup accounting and PSI; wiring pending |
| M6 Calibrator | Probes-on/probes-off arm running; `analyze.py` subtracts it |
| M7 Store | `results.csv` populating; `parse_hist.py` folds in eBPF histograms |
| M8 Analysis | Marginal cost, CIs and additive check implemented and tested |

Bring a terminal. Run `make smoke` and one live `L0` vs `L3` comparison in
front of the panel. A working thirty-second demo is worth more than any slide.

---

## File map

| File | Module | What it is |
|---|---|---|
| `isolate.c` | M2 | Isolation controller — builds L0–L5, no external libraries |
| `bench_syscall.c` | M3 | Workload A — syscall microbenchmark, userspace timing |
| `verify.sh` | M2 QA | Proves each level actually applied; PASS/FAIL per check |
| `syscall_lat.bt` | M4 | eBPF collector — cgroup-scoped per-syscall histograms |
| `parse_hist.py` | M4→M7 | Turns bpftrace histograms into tidy rows with percentiles |
| `readers.py` | M5 | perf counters plus cgroup v2 accounting and PSI |
| `run_matrix.py` | M1, M6, M7 | Orchestrator, probe-cost arm, results.csv |
| `analyze.py` | M8 | Marginal cost, bootstrap CIs, additive-model check, chart |

Typical session once the environment is up:

```bash
make && sudo ./verify.sh                    # M2 proven
sudo ./run_matrix.py --reps 30              # collect
python3 parse_hist.py 'hist_*.txt'          # M4 histograms -> CSV
python3 analyze.py --plot                   # M8 -> summary.csv + chart
```

`analyze.py` prints a **FOR SLIDE 11** block — six numbers to paste straight
into the deck's bar chart.

## Known gaps in this scaffold

- Workloads B and C are not implemented — wire nginx/wrk and redis-benchmark
  into `one_run()`. Workload A carries the primary result either way.
- `readers.py` is written but not yet called from `run_matrix.py`; wire
  `cgroup_sample()` before and after each run and `delta()` them.
- The network namespace is created with only a loopback interface. Real
  container networking adds veth setup cost that this does not capture; say so
  rather than letting a reviewer find it.
- `analyze.py` and `parse_hist.py` were tested against synthetic and sample
  data. The C programs were compiled and smoke-tested at L0 and seccomp levels only. The namespace and
  cgroup paths need root and cgroup v2, so test them on your own machine first.

## M9 - Isolation policy engine (Review 3)

`policy.py` turns the measured cost table (summary.csv) into a per-tenant decision:
given syscall rate + threat profile (trusted / internal / untrusted) it returns the
primitives to enable and the exact `isolate` command. Threat sets a required floor;
optional hardening is added only while `rate x sum(cost_ns)` stays inside the CPU
budget, with hysteresis so a tenant near the threshold does not flap.

    python3 policy.py --demo
    python3 policy.py --rate 2000000 --threat internal --table summary.csv
    python3 test_policy.py

Limits: costs are for a ~48-rule seccomp allowlist on a VirtualBox VM, getpid
workload; the floors per threat profile are policy choices, not measurements.

### M9 enforcement and evaluation (apply_policy.py)

`apply_policy.py` applies the policy and checks it. For each tenant it asks the policy
for a posture, launches `./rate_workload` (getpid at the tenant's rate) under exactly
that posture with `./isolate`, and also runs it with no isolation and with full
lockdown. It reports measured added CPU against the policy's prediction, the CPU saved
against full lockdown, and whether the security floor was honoured.

    make                                     # builds isolate, bench_syscall, rate_workload
    make policy-test                         # unit tests, no root
    python3 apply_policy.py --dry-run        # decisions + commands only
    sudo ./apply_policy.py --table summary.csv            # 4 example tenants -> policy_eval.csv
    sudo ./apply_policy.py --table summary.csv --dynamic  # rate changes, posture re-applied

Needs the cgroup delegation lines from the setup steps (lost on reboot).
