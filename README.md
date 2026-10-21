# isolab

Performance–Security Trade-off in Linux Isolation for Cloud Workloads.

isolab measures what each Linux isolation primitive costs per system call, removes the
cost of the measuring tool itself, and uses the measured costs to choose an isolation
setup for each tenant. The primitives are namespaces, cgroups v2, seccomp-BPF and
capabilities.

## How it fits together

```
M1 Orchestrator ──► M3 Workload ──runs inside──► M2 Isolation controller
        │                                                ▲
        │              M4 eBPF collector + M5 Readers    │
        ▼                       (observe)                │
M7 Store ──► M8 Analysis (+ M6 Calibrator) ──► M9 Policy engine ┘
                                          cost table      posture (flags)
```

The isolation ladder used throughout: L0 baseline, L1 +namespaces, L2 +cgroups,
L3 +seccomp, L4 +capabilities, L5 all combined.

## Modules

### M1 — Orchestrator (`run_matrix.py`)
Expands the configuration matrix (level × syscall × tenant density × traced/untraced),
shuffles the run order so drift does not line up with one configuration, runs each
configuration, and writes `manifest.json` (kernel, governor, SMT, ASLR, cgroup mode,
mitigations).
```bash
sudo ./run_matrix.py --reps 30
```

### M2 — Isolation controller (`isolate.c`, `verify.sh`)
Builds each primitive with raw kernel interfaces and no libraries: namespaces with
`unshare`, a cgroup v2 group with `cpu.max` and `memory.max`, the capability bounding
set, and a hand-assembled seccomp-BPF allowlist (about 48 syscalls). Seccomp is installed
last. After setup it reads back `/proc/self/status` and the namespace links so a primitive
that failed to apply is caught. `verify.sh` gives PASS/FAIL for each primitive.
```bash
sudo ./isolate --ns --cgroup --seccomp --caps --quiet -- ./bench_syscall getpid 1000000 5
sudo ./verify.sh
```

### M3 — Workload runner (`bench_syscall.c`, `rate_workload.c`)
- `bench_syscall`: times a tight loop of one syscall with `clock_gettime`, using raw
  `syscall()` so the C library cannot use a vDSO fast path. Discards a warm-up pass.
- `rate_workload`: issues `getpid` at a target rate in 1 ms ticks and times only the
  syscall bursts (`busy_ns_per_call`), so sleep and wake-up noise are excluded. This is
  the tenant model used by the policy tests.
```bash
./bench_syscall getpid 1000000 5
./rate_workload 100000 3
```

### M4 — eBPF collector (`syscall_lat.bt`, `parse_hist.py`)
A bpftrace program on `raw_syscalls:sys_enter` and `sys_exit`, filtered by cgroup ID,
that builds log2 latency histograms inside the kernel. `parse_hist.py` turns the
histograms into rows with percentiles. Seccomp runs before the `sys_enter` tracepoint,
so this collector cannot see seccomp's cost; it is used for tail-latency evidence.
```bash
sudo bpftrace syscall_lat.bt
python3 parse_hist.py 'hist_*.txt'
```

### M5 — Counter readers (`readers.py`)
Reads perf counters, cgroup v2 accounting (`cpu.stat`, `memory.stat`, `io.stat`) and
pressure stall information (PSI). The module is written but not yet called from
`run_matrix.py`. Hardware counters are unavailable inside a VirtualBox guest.

### M6 — Calibrator (`run_matrix.py`, `analyze.py`)
Measures the cost of the measuring instrument. Every configuration runs twice, traced and
untraced. The difference is the probe cost, and `analyze.py` keeps it out of the isolation
numbers.

### M7 — Store (`run_matrix.py`, `parse_hist.py`)
Holds the raw data: `results.csv` (one row per run) plus the eBPF histograms folded in by
`parse_hist.py`.

### M8 — Analysis (`analyze.py`)
Computes per-level means with 95% bootstrap confidence intervals (2000 resamples), the
marginal cost of each primitive with an interval-overlap check, the probe cost, and the
additivity check (L5 against the sum of the deltas). Writes `summary.csv`.
```bash
python3 analyze.py --plot
```

### M9 — Policy engine (`policy.py`, `apply_policy.py`)
Uses `summary.csv` to choose each tenant's isolation setup.

`policy.py` decides. Given a syscall rate and a threat profile (trusted, internal or
untrusted) it returns the primitives to enable and the exact `isolate` command.
- The threat profile fixes a required floor that is never dropped.
- Optional primitives are added, in order (seccomp, ns, caps, cgroups), only while
  `rate × sum(cost_ns) × 1e-9` stays within the CPU budget (default 1%).
- Hysteresis: a dropped primitive is restored only below 0.8 × budget.
```bash
python3 policy.py --demo --table summary.csv
python3 policy.py --rate 200000 --threat internal --table summary.csv
python3 policy.py --rate 200000 --threat internal --budget 0.02
```

`apply_policy.py` enforces and checks. For each tenant it launches `rate_workload` under
the chosen setup, under no isolation and under full lockdown, as interleaved shuffled
trials. It reports measured against predicted overhead, CPU saved against full lockdown,
whether the security floor was honoured, and noise-aware verdicts.
```bash
python3 apply_policy.py --dry-run
sudo ./apply_policy.py --table summary.csv                 # four example tenants
sudo ./apply_policy.py --table summary.csv --dynamic       # changing rate, setup re-decided
```
Flags: `--budget`, `--secs`, `--trials`, `--tenants tenants.json`, `--out`.

## Setup and run

Requirements: Ubuntu with cgroup v2, root access, and
```bash
sudo apt install -y build-essential bpftrace linux-tools-common \
     linux-tools-$(uname -r) python3 python3-pip
```
cgroup controllers must be delegated at every level of the hierarchy
(`subtree_control`), otherwise `cpu.max` and `memory.max` cannot be written.

```bash
make                       # builds isolate, bench_syscall, rate_workload
make policy-test           # unit tests for policy.py and apply_policy.py (no root)
./run_from_scratch.sh      # setup, build, verify, collect, analyze in one go
```

## Files

| File | Module |
|---|---|
| `run_matrix.py` | M1, M6, M7 |
| `isolate.c`, `verify.sh` | M2 |
| `bench_syscall.c`, `rate_workload.c` | M3 |
| `syscall_lat.bt`, `parse_hist.py` | M4 |
| `readers.py` | M5 |
| `analyze.py` | M6, M8 |
| `policy.py`, `apply_policy.py` | M9 |
| `test_policy.py`, `test_apply.py` | M9 tests |
| `run_from_scratch.sh`, `Makefile` | build and run |

## Limits

- Costs come from one syscall (`getpid`), a roughly 48-rule seccomp allowlist and one
  VirtualBox guest, with no hardware counters.
- The CPU governor, ASLR and core pinning were not controlled.
- Only seccomp shows a cost that repeats across runs; the other primitives are below the
  measurement noise in this setup.
- The threat floors are policy choices, and security benefit is not quantified.
- The network namespace has only a loopback interface, so real container networking costs
  are not captured.
- Workloads B (nginx) and C (redis) are not implemented, and `readers.py` is not yet wired
  into the orchestrator.
