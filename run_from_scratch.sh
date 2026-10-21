#!/usr/bin/env bash
#
# run_from_scratch.sh
# One-shot setup + build + verify + data-collection + analysis for the
# isolab OS isolation-overhead project.
#
# Usage:
#   cd ~/isolab
#   chmod +x run_from_scratch.sh
#   sudo ./run_from_scratch.sh
#
# Must be run as root (sudo) from inside the isolab project directory.

set -euo pipefail

# ---------- helpers ----------
step() { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; exit 1; }

# ---------- 0. sanity checks ----------
if [[ $EUID -ne 0 ]]; then
    fail "Must be run with sudo: sudo ./run_from_scratch.sh"
fi

if [[ ! -f "isolate.c" || ! -f "run_matrix.py" ]]; then
    fail "Run this from inside the isolab/ project directory (isolate.c, run_matrix.py not found here)."
fi

REAL_USER="${SUDO_USER:-$(whoami)}"

# ---------- 1. cgroup v2 delegation (one-time per boot) ----------
step "Setting up cgroup v2 delegation"

if [[ ! -d /sys/fs/cgroup ]] || ! grep -q cgroup2 /proc/filesystems; then
    fail "cgroup v2 not available on this system."
fi

echo "+cpu +memory +io" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
mkdir -p /sys/fs/cgroup/isolab
echo "+cpu +memory +io" > /sys/fs/cgroup/isolab/cgroup.subtree_control 2>/dev/null || true

if grep -q cpu /sys/fs/cgroup/isolab/cgroup.controllers 2>/dev/null; then
    ok "cgroup delegation active (root + isolab parent)"
else
    fail "cgroup delegation failed — check /sys/fs/cgroup/isolab/cgroup.controllers manually"
fi

# ---------- 2. build ----------
step "Building isolate + bench_syscall"
make clean
make
ok "Build complete"

# ---------- 3. smoke test + verification ----------
step "Running make smoke"
make smoke
ok "make smoke passed"

step "Running verify.sh"
./verify.sh
ok "verify.sh passed"

# ---------- 4. quick single-level check before the full run ----------
step "Sanity-checking L2 (cgroups) applies cleanly"
L2_OUT=$(./isolate --level L2 -- true 2>&1 || true)
if echo "$L2_OUT" | grep -qi "not writable"; then
    fail "L2 cgroup limits not writable — delegation did not take effect. Aborting before data collection."
fi
ok "L2 applies cleanly, no 'not writable' warnings"

# ---------- 5. collect the clean dataset ----------
step "Collecting clean dataset (L0-L5, getpid, density 1, 30 reps)"
rm -f results.csv
./run_matrix.py --reps 30 --levels L0,L1,L2,L3,L4,L5 --syscalls getpid --densities 1
ROWS=$(wc -l < results.csv)
ok "results.csv written with $ROWS lines (expect ~361)"

# ---------- 6. analyze ----------
step "Running analyze.py"
python3 analyze.py

# ---------- 7. parse eBPF histograms (optional, supporting evidence) ----------
step "Parsing eBPF histogram files"
python3 parse_hist.py || echo "(no hist_*.txt files found — skipping, this is fine if you only ran the targeted getpid dataset)"

# ---------- 8. hand ownership back to the normal user ----------
chown -R "$REAL_USER":"$REAL_USER" . 2>/dev/null || true

step "Done"
echo "results.csv, summary.csv, and hist_*.txt (if present) are ready in $(pwd)"
echo "Copy the 'FOR SLIDE 11' block above into your deck."
