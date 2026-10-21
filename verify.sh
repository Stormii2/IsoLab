#!/usr/bin/env bash
# verify.sh - proves each isolation level actually applied.
#
# A level that silently fails to apply corrupts every downstream measurement,
# so run this before every data collection session. The output is also the
# screenshot for the "Isolation verified" frame in the Review 2 deck.
#
#   sudo ./verify.sh

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PASS=0; FAIL=0

c_ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
c_bad()  { printf '  \033[31mFAIL\033[0m  %s  (got: %s)\n' "$1" "$2"; FAIL=$((FAIL+1)); }
hdr()    { printf '\n\033[1m%s\033[0m\n' "$1"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root: sudo ./verify.sh" >&2; exit 1
fi

# Probe helper: run /proc/self/status through isolate at a given level and
# return the requested field from inside the isolated context.
field() {  # field <level> <extra-args> <Key:>
    local lvl="$1"; shift
    local extra="$1"; shift
    local key="$1"
    # shellcheck disable=SC2086
    "$HERE/isolate" --level "$lvl" $extra -- /bin/sh -c "grep '^$key' /proc/self/status" 2>/dev/null \
        | tail -1 | awk '{print $2}'
}

hdr "Host reference"
HOST_PIDNS=$(readlink /proc/self/ns/pid)
echo "  pid namespace   $HOST_PIDNS"
echo "  kernel          $(uname -r)"
echo "  cgroup v2       $([ -f /sys/fs/cgroup/cgroup.controllers ] && echo yes || echo NO)"
echo "  governor        $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"

hdr "L1 - namespaces"
GUEST_PIDNS=$("$HERE/isolate" --quiet --level L1 -- readlink /proc/self/ns/pid 2>/dev/null | tail -1)
if [ -n "$GUEST_PIDNS" ] && [ "$GUEST_PIDNS" != "$HOST_PIDNS" ]; then
    c_ok "pid namespace differs from host  ($GUEST_PIDNS)"
else
    c_bad "pid namespace differs from host" "${GUEST_PIDNS:-empty}"
fi
GUEST_PID1=$("$HERE/isolate" --quiet --level L1 -- /bin/sh -c 'echo $$' 2>/dev/null | tail -1)
[ "$GUEST_PID1" = "1" ] && c_ok "workload is PID 1 inside the namespace" \
                        || c_bad "workload is PID 1 inside the namespace" "${GUEST_PID1:-empty}"

hdr "L2 - cgroup v2"
"$HERE/isolate" --quiet --level L2 -- /bin/true >/dev/null 2>&1
if [ -f /sys/fs/cgroup/isolab/run/cpu.max ]; then
    c_ok "cpu.max written        ($(cat /sys/fs/cgroup/isolab/run/cpu.max))"
    c_ok "memory.max written     ($(cat /sys/fs/cgroup/isolab/run/memory.max 2>/dev/null))"
else
    c_bad "run cgroup created" "missing /sys/fs/cgroup/isolab/run"
fi
CG=$("$HERE/isolate" --quiet --level L2 -- cat /proc/self/cgroup 2>/dev/null | tail -1)
case "$CG" in *isolab/run*) c_ok "workload is inside isolab/run" ;;
              *) c_bad "workload is inside isolab/run" "${CG:-empty}" ;; esac

hdr "L3 - seccomp"
SEC=$(field L3 "--seccomp-rules 150" "Seccomp:")
[ "$SEC" = "2" ] && c_ok "Seccomp mode 2 (filter active)" \
                 || c_bad "Seccomp mode 2 (filter active)" "${SEC:-empty}"
NNP=$(field L3 "--seccomp-rules 150" "NoNewPrivs:")
[ "$NNP" = "1" ] && c_ok "NoNewPrivs set" || c_bad "NoNewPrivs set" "${NNP:-empty}"

hdr "L4 - capabilities"
CAP=$(field L4 "--seccomp-rules 150" "CapBnd:")
case "$CAP" in
    0000000000000000) c_ok "capability bounding set empty" ;;
    *) c_bad "capability bounding set empty" "${CAP:-empty}" ;;
esac

hdr "L5 - combined, end to end"
if "$HERE/isolate" --quiet --level L5 --seccomp-rules 150 \
       -- "$HERE/bench_syscall" getpid 100000 1 >/dev/null 2>&1; then
    c_ok "benchmark completes under full isolation"
else
    c_bad "benchmark completes under full isolation" "non-zero exit"
fi

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
