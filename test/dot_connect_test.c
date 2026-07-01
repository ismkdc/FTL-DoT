/*
 * dot_connect_test.c — minimal async-connect verification for DoT fix
 *
 * Tests that the non-blocking TCP connect + SO_ERROR path used by the
 * async DoT state machine (tls.c) behaves correctly:
 *
 *   1. connect() returns -1/EINPROGRESS (or -1/EAGAIN on some kernels)
 *   2. poll(POLLOUT) fires once TCP handshake completes
 *   3. getsockopt(SO_ERROR) returns 0 on success, or EAGAIN/EINPROGRESS
 *      on a spurious wakeup (Docker Desktop macOS quirk) — stay in
 *      CONNECTING state and loop, do NOT call dot_fail().
 *
 * Build:  gcc -O2 -o dot_connect_test dot_connect_test.c
 * Run:    ./dot_connect_test [host] [port]  (default: 8.8.8.8 853)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

static void fail(const char *msg)
{
    fprintf(stderr, "FAIL: %s: %s\n", msg, strerror(errno));
    exit(1);
}

int main(int argc, char *argv[])
{
    const char *host = (argc > 1) ? argv[1] : "8.8.8.8";
    int port         = (argc > 2) ? atoi(argv[2]) : 853;

    printf("=== DoT async-connect test: %s:%d ===\n\n", host, port);

    /* 1. Create non-blocking TCP socket */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) fail("socket");

    int flags = fcntl(fd, F_GETFL, 0);
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) fail("fcntl O_NONBLOCK");

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) fail("inet_pton");

    /* 2. Non-blocking connect() — expect EINPROGRESS or EAGAIN */
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0)
    {
        /* Rare: immediate connect (loopback, cached route) */
        printf("[connect] returned 0 immediately — already connected\n");
    }
    else if (errno == EINPROGRESS)
    {
        printf("[connect] returned -1/EINPROGRESS (115) — normal async path ✓\n");
    }
    else if (errno == EAGAIN)
    {
        /* Some Linux kernels inside Docker return EAGAIN instead of
         * EINPROGRESS for a non-blocking connect.  dot13 fix: treat
         * EAGAIN identical to EINPROGRESS (move to DOT_STATE_CONNECTING). */
        printf("[connect] returned -1/EAGAIN (11) — kernel quirk, treated as EINPROGRESS ✓\n");
    }
    else
    {
        fail("connect");
    }

    /* 3. Simulate the poll loop (max 5 iterations to catch spurious wakeups) */
    printf("\n[poll] waiting for POLLOUT (TCP handshake complete)...\n");

    int spurious = 0;
    for (int iter = 0; iter < 10; iter++)
    {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        rc = poll(&pfd, 1, 5000);  /* 5 s timeout */
        if (rc < 0)  fail("poll");
        if (rc == 0) { fprintf(stderr, "FAIL: poll timed out\n"); exit(1); }

        /* 4. Check SO_ERROR — the exact check in tls.c dot_advance() */
        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0) fail("getsockopt");

        printf("[iter %d] POLLOUT=%d  SO_ERROR=%d (%s)\n",
               iter,
               !!(pfd.revents & POLLOUT),
               err,
               err == 0 ? "success" :
               err == EAGAIN ? "EAGAIN — spurious, stay CONNECTING" :
               err == EINPROGRESS ? "EINPROGRESS — spurious, stay CONNECTING" :
               strerror(err));

        if (err == EAGAIN || err == EINPROGRESS)
        {
            /* dot14 fix: spurious wakeup, stay in CONNECTING state */
            spurious++;
            printf("         → dot14: returning early, staying in DOT_STATE_CONNECTING ✓\n");
            continue;
        }

        if (err != 0)
        {
            fprintf(stderr, "FAIL: connect to %s:%d failed: %s\n",
                    host, port, strerror(err));
            exit(1);
        }

        /* err == 0: TCP connected */
        printf("         → TCP connected! Spurious wakeups seen: %d\n\n", spurious);
        printf("[result] PASS: async connect to %s:%d succeeded ✓\n", host, port);

        if (spurious > 0)
            printf("[note]   dot14 EAGAIN guard triggered %d time(s) — fix was needed\n",
                   spurious);
        else
            printf("[note]   SO_ERROR was always 0 on first POLLOUT — "
                   "dot14 guard is a no-op here (correct kernel behaviour)\n");

        close(fd);
        return 0;
    }

    fprintf(stderr, "FAIL: too many spurious POLLOUT events (%d)\n", spurious);
    close(fd);
    return 1;
}
