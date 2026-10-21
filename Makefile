CC      = gcc
CFLAGS  = -O2 -Wall -Wextra

all: isolate bench_syscall rate_workload

isolate: isolate.c
	$(CC) $(CFLAGS) -o $@ $<

bench_syscall: bench_syscall.c
	$(CC) $(CFLAGS) -o $@ $<

rate_workload: rate_workload.c
	$(CC) $(CFLAGS) -o $@ $<

# Quick sanity pass: does the controller build every level without dying?
smoke: all
	@for lv in L0 L1 L2 L3 L4 L5; do \
		printf "%-4s " $$lv; \
		sudo ./isolate --quiet --level $$lv -- ./bench_syscall getpid 200000 1 \
		  || echo "FAILED"; \
	done

clean:
	rm -f isolate bench_syscall rate_workload

# Policy engine: unit tests (no root needed)
policy-test:
	python3 test_policy.py && python3 test_apply.py

.PHONY: all smoke clean policy-test
