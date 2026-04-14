/*
 * futex-stress.c — FUTEX regression stress test for sotOS LUCAS → LKL
 *
 * Spawns NUM_THREADS pthreads that each hammer a single shared
 * pthread_mutex with ITERS lock/unlock cycles. If SYS_FUTEX is
 * correctly routed to LKL (A1 #118, A2 #123, A3 #126), this should
 * complete in well under the 60-second watchdog. Pre-A2, this
 * program deadlocks within seconds on the bridge_lock.
 *
 * Build (musl static, host):
 *   gcc -static -pthread -O2 -o futex-stress futex-stress.c
 *
 * Or via WSL:
 *   wsl -- gcc -static -pthread -O2 -o futex-stress futex-stress.c
 *
 * Expected output on PASS:
 *   FUTEX-STRESS: PASS (80000 ops in <N> ms)
 * On HUNG (watchdog trips):
 *   FUTEX-STRESS: HUNG
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#define NUM_THREADS 8
#define ITERS 10000
#define WATCHDOG_SECS 60

static pthread_mutex_t shared_mu = PTHREAD_MUTEX_INITIALIZER;
static long counter = 0;  /* protected by shared_mu; no volatile needed */

static void *worker(void *arg) {
    long tid = (long)arg;
    (void)tid;
    for (int i = 0; i < ITERS; i++) {
        pthread_mutex_lock(&shared_mu);
        counter++;
        pthread_mutex_unlock(&shared_mu);
    }
    return NULL;
}

static void watchdog_handler(int sig) {
    (void)sig;
    const char msg[] = "FUTEX-STRESS: HUNG\n";
    /* write(2) is async-signal-safe. fd 1 = stdout. */
    ssize_t r = write(1, msg, sizeof(msg) - 1);
    (void)r;
    _exit(2);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(void) {
    /* Arm watchdog: if the whole test doesn't finish in WATCHDOG_SECS,
     * assume we've deadlocked on the FUTEX path and report HUNG. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = watchdog_handler;
    sigaction(SIGALRM, &sa, NULL);
    alarm(WATCHDOG_SECS);

    pthread_t threads[NUM_THREADS];
    long t0 = now_ms();

    for (long i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) {
            fprintf(stderr, "FUTEX-STRESS: pthread_create failed on %ld\n", i);
            return 1;
        }
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    long elapsed = now_ms() - t0;
    long expected_ops = (long)NUM_THREADS * ITERS;
    if (counter != expected_ops) {
        printf("FUTEX-STRESS: FAIL (counter=%ld, expected=%ld)\n",
               counter, expected_ops);
        return 3;
    }
    printf("FUTEX-STRESS: PASS (%ld ops in %ld ms)\n", counter, elapsed);
    return 0;
}
