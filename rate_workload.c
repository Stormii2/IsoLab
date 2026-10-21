/*
 * Workload for the policy engine: a tenant that issues system calls at a
 * TARGET RATE instead of flat out.
 *
 * bench_syscall measures cost per call. The policy engine reasons about a
 * different quantity: the fraction of a CPU a tenant spends on isolation at a
 * given syscall rate (rate x added_ns). To test that prediction we need a
 * workload with a controlled rate and a precise CPU-time reading.
 *
 * Build:  gcc -O2 -o rate_workload rate_workload.c
 * Run:    ./rate_workload <calls_per_sec> <seconds>
 *
 * Pacing: a 1 ms tick. Each tick issues rate/1000 getpid() calls (fractional
 * remainder carried), then sleeps to an absolute deadline. Only sleeping and
 * getpid use the kernel, and both are on the seccomp allowlist (raw
 * nanosleep, not the libc wrapper, which may call clock_nanosleep).
 *
 * Output: one CSV line on stdout
 *   target_rate,calls,wall_s,cpu_s,achieved_rate,cpu_ns_per_call,busy_ns_per_call
 * cpu_ns_per_call is total process CPU / calls and includes per-tick wake-up
 * cost, which is noisy when few calls are issued per tick (low rates).
 * busy_ns_per_call times only the bursts of syscalls (monotonic clock around
 * each burst), so it excludes sleeping and wake-up and stays clean at any rate.
 * The policy evaluation uses busy_ns_per_call; overhead fraction is then
 * rate x (busy_ns_isolated - busy_ns_baseline).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

static inline long long ns(clockid_t c)
{
    struct timespec ts;
    clock_gettime(c, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <calls_per_sec> <seconds>\n", argv[0]);
        return 2;
    }
    double rate = atof(argv[1]);
    double secs = atof(argv[2]);
    if (rate <= 0 || secs <= 0) {
        fprintf(stderr, "rate and seconds must be positive\n");
        return 2;
    }

    const long long TICK = 1000000LL;               /* 1 ms */
    double per_tick = rate / 1000.0;
    double debt = 0.0;
    long long calls = 0;
    long long busy = 0;                              /* ns spent inside bursts */

    long long wall0 = ns(CLOCK_MONOTONIC);
    long long cpu0 = ns(CLOCK_PROCESS_CPUTIME_ID);
    long long end = wall0 + (long long)(secs * 1e9);
    long long next = wall0;

    while (next < end) {
        next += TICK;
        debt += per_tick;
        long n = (long)debt;
        debt -= n;
        long long b0 = ns(CLOCK_MONOTONIC);
        for (long i = 0; i < n; i++)
            syscall(SYS_getpid);
        long long now = ns(CLOCK_MONOTONIC);
        busy += now - b0;
        calls += n;
        if (next > now) {
            struct timespec d = { 0, (long)(next - now) };
            syscall(SYS_nanosleep, &d, NULL);
        }
    }

    long long wall = ns(CLOCK_MONOTONIC) - wall0;
    long long cpu = ns(CLOCK_PROCESS_CPUTIME_ID) - cpu0;
    printf("%.0f,%lld,%.4f,%.6f,%.1f,%.2f,%.2f\n", rate, calls, wall / 1e9, cpu / 1e9,
           calls / (wall / 1e9), calls ? (double)cpu / calls : 0.0,
           calls ? (double)busy / calls : 0.0);
    return 0;
}
