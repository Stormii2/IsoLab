/*
 * M2 - Isolation Controller.
 *
 * Builds one isolation configuration and execs a workload inside it.
 * No external libraries: raw seccomp BPF instead of libseccomp (so filter
 * length is under our control, not the optimiser's), and PR_CAPBSET_DROP
 * instead of libcap.
 *
 * Build:  gcc -O2 -o isolate isolate.c
 * Run as root.
 *
 *   ./isolate --level L0 -- ./bench_syscall getpid 2000000 5
 *   ./isolate --level L3 --seccomp-rules 150 -- ./bench_syscall getpid 2000000 5
 *   ./isolate --level L5 --seccomp-rules 150 -- ./bench_syscall getpid 2000000 5
 *
 * Levels (cumulative, matching the deck):
 *   L0  baseline, nothing applied
 *   L1  + namespaces (PID, mount, UTS, IPC, net)
 *   L2  + cgroup v2 limits
 *   L3  + seccomp allowlist
 *   L4  + capability bounding set dropped
 *   L5  all of the above
 *
 * Individual switches (--ns --cgroup --seccomp --caps) override --level, so
 * you can also run a factorial design later if you want interaction terms.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define CGROOT "/sys/fs/cgroup"
#define CGPARENT CGROOT "/isolab"
#define CGRUN CGPARENT "/run"

static int opt_ns, opt_cgroup, opt_seccomp, opt_caps;
static int opt_rules = 150;
static const char *opt_cpu_max = "200000 100000";   /* 2 CPUs per 100ms period */
static const char *opt_mem_max = "2147483648";      /* 2 GiB */
static int opt_verify = 1;

static void die(const char *what) { fprintf(stderr, "isolate: %s: %s\n", what, strerror(errno)); exit(1); }

/* ------------------------------------------------------------------ cgroup */

static int write_file(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, val, strlen(val));
    close(fd);
    return n < 0 ? -1 : 0;
}

static void cgroup_setup(void)
{
    /* Delegate the controllers we need from the root cgroup down. */
    if (write_file(CGROOT "/cgroup.subtree_control", "+cpu +memory +io") < 0)
        fprintf(stderr, "isolate: warning: could not enable root subtree controllers\n");

    if (mkdir(CGPARENT, 0755) < 0 && errno != EEXIST) die("mkdir " CGPARENT);
    if (mkdir(CGRUN, 0755) < 0 && errno != EEXIST) die("mkdir " CGRUN);

    if (write_file(CGRUN "/cpu.max", opt_cpu_max) < 0)
        fprintf(stderr, "isolate: warning: cpu.max not writable\n");
    if (write_file(CGRUN "/memory.max", opt_mem_max) < 0)
        fprintf(stderr, "isolate: warning: memory.max not writable\n");

    /* Move ourselves in; the child inherits membership across fork and exec.
     * The eBPF collector filters on this cgroup's id, so this must happen
     * before the workload starts. */
    char pid[32];
    snprintf(pid, sizeof(pid), "%d", getpid());
    if (write_file(CGRUN "/cgroup.procs", pid) < 0) die("attach to " CGRUN);
}

/* ------------------------------------------------------------- capabilities */

static void caps_drop(void)
{
    for (int c = 0; c <= CAP_LAST_CAP; c++) {
        if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) < 0 && errno != EINVAL)
            fprintf(stderr, "isolate: warning: could not drop cap %d\n", c);
    }
}

/* ----------------------------------------------------------------- seccomp */

/* Syscalls the benchmark and the C runtime need. Generous on purpose:
 * a missing entry shows up as EPERM from a syscall you did not expect. */
static const int allowed[] = {
    SYS_read, SYS_write, SYS_openat, SYS_close, SYS_newfstatat, SYS_fstat,
    SYS_lseek, SYS_mmap, SYS_munmap, SYS_mprotect, SYS_brk, SYS_rt_sigaction,
    SYS_rt_sigprocmask, SYS_rt_sigreturn, SYS_ioctl, SYS_pread64, SYS_access,
    SYS_execve, SYS_exit, SYS_exit_group, SYS_arch_prctl, SYS_set_tid_address,
    SYS_set_robust_list, SYS_prlimit64, SYS_getrandom, SYS_clock_gettime,
    SYS_getpid, SYS_getppid, SYS_gettid, SYS_futex, SYS_readlink, SYS_statfs,
    SYS_dup, SYS_pipe2, SYS_clone, SYS_wait4, SYS_getdents64, SYS_madvise,
    SYS_sched_getaffinity, SYS_prctl, SYS_nanosleep, SYS_rseq, SYS_uname,
    SYS_getcwd, SYS_getuid, SYS_geteuid, SYS_getgid, SYS_getegid, SYS_setsid,
};
#define N_ALLOWED ((int)(sizeof(allowed) / sizeof(allowed[0])))

/*
 * Filter layout, deliberately a linear jump chain:
 *
 *   [arch guard]
 *   [load nr]
 *   [N padding comparisons against impossible syscall numbers]  <-- swept
 *   [real allowlist comparisons]
 *   [default: ERRNO(EPERM)]
 *
 * Padding sits BEFORE the allowlist so every permitted syscall traverses all
 * N comparisons. That makes filter length the independent variable rather
 * than an artefact of where a syscall happens to sit in the chain.
 */
static void seccomp_install(int pad_rules)
{
    int n = 4 + pad_rules + N_ALLOWED + 2;
    struct sock_filter *f = calloc(n, sizeof(*f));
    if (!f) die("calloc filter");
    int i = 0;

    /* Guard against a mismatched architecture ABI. */
    f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                          offsetof(struct seccomp_data, arch));
    f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                          AUDIT_ARCH_X86_64, 1, 0);
    f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                          offsetof(struct seccomp_data, nr));

    int allow_at = 4 + pad_rules + N_ALLOWED + 1;   /* index of the ALLOW return */

    for (int p = 0; p < pad_rules; p++) {
        int jt = allow_at - (i + 1);
        f[i] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                            0x40000000 + p, jt, 0);
        i++;
    }
    for (int a = 0; a < N_ALLOWED; a++) {
        int jt = allow_at - (i + 1);
        f[i] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                            allowed[a], jt, 0);
        i++;
    }

    f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                          SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = { .len = (unsigned short)i, .filter = f };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) die("PR_SET_NO_NEW_PRIVS");
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0)
        die("seccomp(SECCOMP_SET_MODE_FILTER)");
}

/* ------------------------------------------------------------ verification */

static void verify(void)
{
    char buf[256];
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return;
    while (fgets(buf, sizeof(buf), fp)) {
        if (!strncmp(buf, "Seccomp:", 8) || !strncmp(buf, "CapBnd:", 7) ||
            !strncmp(buf, "NoNewPrivs:", 11))
            fprintf(stderr, "isolate: verify %s", buf);
    }
    fclose(fp);

    ssize_t r = readlink("/proc/self/ns/pid", buf, sizeof(buf) - 1);
    if (r > 0) { buf[r] = 0; fprintf(stderr, "isolate: verify pid_ns %s\n", buf); }

    int fd = open("/proc/self/cgroup", O_RDONLY);
    if (fd >= 0) {
        r = read(fd, buf, sizeof(buf) - 1);
        if (r > 0) { buf[r] = 0; fprintf(stderr, "isolate: verify cgroup %s", buf); }
        close(fd);
    }
}

/* ------------------------------------------------------------------- main */

static void apply_level(const char *lvl)
{
    if (!strcmp(lvl, "L0")) return;
    if (!strcmp(lvl, "L1")) { opt_ns = 1; return; }
    if (!strcmp(lvl, "L2")) { opt_ns = 1; opt_cgroup = 1; return; }
    if (!strcmp(lvl, "L3")) { opt_ns = 1; opt_cgroup = 1; opt_seccomp = 1; return; }
    if (!strcmp(lvl, "L4")) { opt_ns = 1; opt_cgroup = 1; opt_seccomp = 1; opt_caps = 1; return; }
    if (!strcmp(lvl, "L5")) { opt_ns = opt_cgroup = opt_seccomp = opt_caps = 1; return; }
    fprintf(stderr, "isolate: unknown level %s (use L0..L5)\n", lvl);
    exit(2);
}

int main(int argc, char **argv)
{
    int i = 1;
    char **cmd = NULL;

    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { cmd = &argv[i + 1]; break; }
        else if (!strcmp(argv[i], "--level") && i + 1 < argc) apply_level(argv[++i]);
        else if (!strcmp(argv[i], "--ns")) opt_ns = 1;
        else if (!strcmp(argv[i], "--cgroup")) opt_cgroup = 1;
        else if (!strcmp(argv[i], "--seccomp")) opt_seccomp = 1;
        else if (!strcmp(argv[i], "--caps")) opt_caps = 1;
        else if (!strcmp(argv[i], "--seccomp-rules") && i + 1 < argc) opt_rules = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cpu-max") && i + 1 < argc) opt_cpu_max = argv[++i];
        else if (!strcmp(argv[i], "--mem-max") && i + 1 < argc) opt_mem_max = argv[++i];
        else if (!strcmp(argv[i], "--quiet")) opt_verify = 0;
        else { fprintf(stderr, "isolate: unknown option %s\n", argv[i]); return 2; }
    }
    if (!cmd || !*cmd) {
        fprintf(stderr, "usage: %s [--level L0..L5] [--seccomp-rules N] -- <command> [args]\n", argv[0]);
        return 2;
    }

    if (opt_cgroup) cgroup_setup();

    if (opt_ns) {
        int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS |
                    CLONE_NEWIPC | CLONE_NEWNET;
        if (unshare(flags) < 0) die("unshare");
    }

    /* With CLONE_NEWPID the *child* is PID 1 of the new namespace, so the
     * fork is mandatory, not stylistic. */
    pid_t pid = fork();
    if (pid < 0) die("fork");

    if (pid == 0) {
        if (opt_ns) {
            /* Stop our /proc remount propagating back to the host. */
            if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
                fprintf(stderr, "isolate: warning: could not make mounts private\n");
            if (mount("proc", "/proc", "proc", 0, NULL) < 0)
                fprintf(stderr, "isolate: warning: could not remount /proc\n");
        }
        if (opt_verify) verify();

        /* Order matters: capabilities before seccomp, seccomp last of all,
         * because everything after this point runs under the filter. */
        if (opt_caps) caps_drop();
        if (opt_seccomp) seccomp_install(opt_rules);

        execvp(cmd[0], cmd);
        die("execvp");
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) die("waitpid");
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "isolate: child killed by signal %d%s\n", WTERMSIG(status),
                WTERMSIG(status) == SIGSYS ? " (SIGSYS - seccomp denied a syscall)" : "");
        return 128 + WTERMSIG(status);
    }
    return WEXITSTATUS(status);
}
