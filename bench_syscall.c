/*
 * Workload A - system call microbenchmark.
 *
 * Userspace timing is the PRIMARY instrument for seccomp cost, because the
 * seccomp filter is evaluated before the raw_syscalls:sys_enter tracepoint
 * fires. An eBPF probe on sys_enter/sys_exit will therefore not see it.
 *
 * Build:  gcc -O2 -o bench_syscall bench_syscall.c
 * Run:    ./bench_syscall getpid 2000000 5
 *         ./bench_syscall <syscall> <iterations> <repetitions>
 *
 * Output: one CSV line per repetition on stdout
 *         syscall,rep,iterations,total_ns,ns_per_call
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static inline unsigned long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Each op performs exactly one system call. syscall() is used directly so the
 * C library cannot substitute a vDSO fast path (getpid is cached in some libcs). */
static void op_getpid(void)   { syscall(SYS_getpid); }
static void op_getppid(void)  { syscall(SYS_getppid); }
static void op_close(void)    { syscall(SYS_close, -1); }

static int devnull = -1;
static char iobuf[4096];
static void op_write(void)    { syscall(SYS_write, devnull, iobuf, sizeof(iobuf)); }
static void op_read(void)     { syscall(SYS_read, devnull, iobuf, sizeof(iobuf)); }

static void op_openclose(void)
{
    long fd = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY, 0);
    if (fd >= 0) syscall(SYS_close, fd);
}

static void op_stat(void)
{
    struct stat st;
    syscall(SYS_newfstatat, AT_FDCWD, "/dev/null", &st, 0);
}

static void op_mmap(void)
{
    void *p = (void *)syscall(SYS_mmap, NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) syscall(SYS_munmap, p, 4096);
}

struct op { const char *name; void (*fn)(void); };
static struct op ops[] = {
    { "getpid",    op_getpid    },
    { "getppid",   op_getppid   },
    { "close",     op_close     },
    { "write",     op_write     },
    { "read",      op_read      },
    { "openclose", op_openclose },
    { "stat",      op_stat      },
    { "mmap",      op_mmap      },
    { NULL, NULL }
};

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <syscall> <iterations> [repetitions]\n", argv[0]);
        fprintf(stderr, "syscalls:");
        for (int i = 0; ops[i].name; i++) fprintf(stderr, " %s", ops[i].name);
        fprintf(stderr, "\n");
        return 2;
    }

    const char *want = argv[1];
    long iters = atol(argv[2]);
    int reps = (argc > 3) ? atoi(argv[3]) : 1;

    void (*fn)(void) = NULL;
    for (int i = 0; ops[i].name; i++)
        if (!strcmp(ops[i].name, want)) fn = ops[i].fn;
    if (!fn) { fprintf(stderr, "unknown syscall: %s\n", want); return 2; }

    devnull = open("/dev/null", O_RDWR);
    memset(iobuf, 'x', sizeof(iobuf));

    /* Warm-up pass, discarded. Faults in pages, warms icache and branch
     * predictors, and forces the seccomp filter down its hot path once. */
    for (long i = 0; i < iters / 10 + 1000; i++) fn();

    for (int r = 0; r < reps; r++) {
        unsigned long long t0 = now_ns();
        for (long i = 0; i < iters; i++) fn();
        unsigned long long t1 = now_ns();
        double per = (double)(t1 - t0) / (double)iters;
        printf("%s,%d,%ld,%llu,%.2f\n", want, r, iters, t1 - t0, per);
        fflush(stdout);
    }

    if (devnull >= 0) close(devnull);
    return 0;
}
