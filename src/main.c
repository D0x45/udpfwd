#include "udpfwd.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <getopt.h>

static const char   *_opts_short = "d:p:64l?";
static struct option _opts_long[] = {
    {"destination", required_argument, NULL, 'd'},
    {"listen-port", required_argument, NULL, 'p'},
    {"no-ipv4",     no_argument,       NULL, '6'},
    {"no-ipv6",     no_argument,       NULL, '4'},
    {"loopback",    no_argument,       NULL, 'l'},
    {NULL, 0, NULL, 0}
};
static int          _keep_running = 1;

static void handle_signal(int signal) { _keep_running = 0; }

int main(int argc, char **argv)
{
    udpfwd_addrinfo addr_dst;
    udpfwd_conn sock4,
                sock6;
    udpfwd_wdata tdata4,
                 tdata6;
    int allow_ipv6 = 1,
        allow_ipv4 = 1,
        loopback_only = 0,  // listen on [::1] instead of [::]
        listen_port = 65535,
        status;

#ifdef _WIN32
    WSADATA _wsaData;
    if (0 != WSAStartup(MAKEWORD(2, 2), &_wsaData)) {
        fprintf(stderr, "WSAStartup() failed: %d\n", WSAGetLastError());
        return EXIT_FAILURE;
    }
#endif // _WIN32

    memset(&addr_dst, 0, sizeof(addr_dst));
    memset(&sock4, 0, sizeof(sock4));
    memset(&sock6, 0, sizeof(sock6));

    while (1) {
        int opt = getopt_long(argc, argv, _opts_short, _opts_long, NULL);

        if (opt == -1) break; // end of args
        if (opt == '?') return EXIT_FAILURE;
        if (opt == '4') allow_ipv6 = 0;
        if (opt == '6') allow_ipv4 = 0;
        if (opt == 'l') loopback_only = 1;
        if (opt == 'p') {
            listen_port = atoi(optarg);
            if (listen_port < 1 || listen_port > 65535) {
                fprintf(stderr, "invalid port number %d (%s)\n",
                        listen_port, optarg);
                return EXIT_FAILURE;
            }
        }
        if (opt == 'd') {
            if (udpfwd_pton(&addr_dst.sa, optarg)) {
                fprintf(stderr, "udpfwd_pton('%s') failed.\n", optarg);
                return EXIT_FAILURE;
            }
            udpfwd_ntop(addr_dst.str, &addr_dst.sa);
        }
    }

    // the last byte makes the difference
    *(((uint8_t*)&sock6.sa.v6.sin6_addr) + 15) = loopback_only;
    *((uint32_t*)&sock4.sa.v4.sin_addr) = htonl(loopback_only * INADDR_LOOPBACK);
    sock4.sa.v4.sin_port = sock6.sa.v6.sin6_port = htons(listen_port);
    sock6.sa.v6.sin6_family = AF_INET6;
    sock4.sa.v4.sin_family = AF_INET;

    if (0 == udpfwd_sa_is_valid((const struct sockaddr*)&addr_dst.sa)) {
        fputs("invalid destination address.\n", stderr);
        return EXIT_FAILURE;
    }

    puts("Binding sockets to:");
    printf("[%c] %s\n", ' ' + (11 * allow_ipv4), udpfwd_sa_str(&sock4.sa));
    printf("[%c] %s\n", ' ' + (11 * allow_ipv6), udpfwd_sa_str(&sock6.sa));
    printf("Forwarding to:\n%s\n", addr_dst.str);

    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        perror("signal(SIGINT, ...)");
        return EXIT_FAILURE;
    }

    if (allow_ipv4) {
        sock4.fd = socket(PF_INET, SOCK_DGRAM, 0);
        if (sock4.fd == INVALID_SOCKET) {
            udpfwd_perror("socket4 failed");
            return EXIT_FAILURE;
        }
        status = bind(sock4.fd, (const struct sockaddr*)&sock4.sa,
                        sizeof(struct sockaddr_in));
        if (status != 0) {
            udpfwd_perror("bind4 failed");
            return EXIT_FAILURE;
        }
        tdata4.listen = &sock4;
        tdata4.keep_running = &_keep_running;
        tdata4.dst = &addr_dst;
#ifdef _WIN32
        tdata4.handle = CreateThread(0, 0, udpfwd_worker_fn, &tdata4, 0,
                                     (unsigned long*)&tdata4.thread_id);
#else
        pthread_create(&tdata4.handle, 0, udpfwd_worker_fn, &tdata4);
        tdata4.thread_id = 4;
#endif
    }

    if (allow_ipv6) {
        sock6.fd = socket(PF_INET6, SOCK_DGRAM, 0);
        if (sock6.fd == INVALID_SOCKET) {
            udpfwd_perror("socket6 failed");
            return EXIT_FAILURE;
        }
        status = bind(sock6.fd, (const struct sockaddr*)&sock6.sa,
                        sizeof(struct sockaddr_in6));
        if (status != 0) {
            udpfwd_perror("bind6 failed");
            return EXIT_FAILURE;
        }
        tdata6.listen = &sock6;
        tdata6.keep_running = &_keep_running;
        tdata6.dst = &addr_dst;
#ifdef _WIN32
        tdata6.handle = CreateThread(0, 0, udpfwd_worker_fn, &tdata6, 0,
                                     (unsigned long*)&tdata6.thread_id);
#else
        pthread_create(&tdata6.handle, 0, udpfwd_worker_fn, &tdata6);
        tdata6.thread_id = 6;
#endif
    }

    if (allow_ipv4) {
#ifdef _WIN32
        WaitForSingleObject(tdata4.handle, INFINITE);
#else
        pthread_join(tdata4.handle, NULL);
#endif
    }

    if (allow_ipv6) {
#ifdef _WIN32
        WaitForSingleObject(tdata6.handle, INFINITE);
#else
        pthread_join(tdata6.handle, NULL);
#endif
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return EXIT_SUCCESS;
}
