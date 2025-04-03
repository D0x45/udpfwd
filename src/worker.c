#include "udpfwd.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

UDPFWD_THREAD_API udpfwd_worker_fn(void *param)
{
    // temporary variable to store recvfrom's sockaddr
    udpfwd_sa from;
    // worker data
    udpfwd_wdata *wd = (udpfwd_wdata*)param;
    // array of connections to maintain; the `ai` field is the sockaddr of the
    // owner, and the `fd` field is the file descriptor of the outbound socket
    // that is connected to `wd->dst`
    struct {
        udpfwd_addrinfo ai;
        udpfwd_sockfd   fd;
        time_t          trx_time;
    } *conns, *p = NULL;
    char *buffer;
    time_t t;
    int recv_len, i, j;
#ifdef _WIN32
    int from_len;
#else
    unsigned int from_len;
#endif

    conns  = calloc(UDPFWD_MAX_CONNS, sizeof(*conns));
    buffer = calloc(UDPFWD_PACKET_SIZE, 1);
    if (buffer == NULL || conns == NULL) {
        fputs("memory allocation failed.\n", stderr);
        return 0;
    }

    // invalidate socket file descriptors
    for (i = 0; i < UDPFWD_MAX_CONNS; i++)
        conns[i].fd = INVALID_SOCKET;

    udpfwd_nonblock(wd->listen->fd);

    while (*wd->keep_running) {
        memset(&from, 0, sizeof(udpfwd_sa));
        from_len = sizeof(udpfwd_sa);
        recv_len = recvfrom(wd->listen->fd, buffer, UDPFWD_PACKET_SIZE, 0,
                             (struct sockaddr*)&from, &from_len);

        if (recv_len <= 0)
            goto meow;

        // find the matching connection slot or create one
        for (i = 0, j = -1, p = NULL, t = time(0); i < UDPFWD_MAX_CONNS; i++) {
            if (conns[i].fd == INVALID_SOCKET) {
                if (j == -1) {
                    j = i;
                }
            } else {
                // free the used slot if connection is inactive
                if ((t - conns[i].trx_time) > UDPFWD_CONN_TTL) {
                    printf("[%d] conn #%d dropped due to inactivity. (owner: %s)\n",
                            wd->thread_id, i, conns[i].ai.str);
                    if (j == -1) {
                        j = i;
                    }
                    closesocket(conns[i].fd);
                    memset(&conns[i], 0, sizeof(*conns));
                    conns[i].fd = INVALID_SOCKET;
                }
                // found an existing connection
                if (0 == memcmp(&conns[i].ai.sa, &from, from_len)) {
                    p = &conns[i];
                    break;
                }
            }
        }

        // no existing connection for `from`, must create one at the advised
        // index `j` (if it's -1 then there is no free space left!)
        if (p == NULL) {
            if (j == -1) {
                printf("[%d] dropping new connection from %s\n", wd->thread_id, udpfwd_sa_str(&from));
                goto meow;
            }
            printf("[%d] allocating new connection at slot #%d\n", wd->thread_id, j);
            p = &conns[j];
            // outbound socket's family must match the destination's
            p->fd = socket(((struct sockaddr*)&wd->dst->sa)->sa_family,
                            SOCK_DGRAM, 0);
            if (p->fd == INVALID_SOCKET) {
                udpfwd_perror("creating outbound socket failed");
                goto meow;
            }
            // bind the socket to the destination address
            udpfwd_nonblock(p->fd);
            i = connect(p->fd, (struct sockaddr*)&wd->dst->sa, sizeof(wd->dst->sa));
            memcpy(&p->ai.sa, &from, from_len);
            udpfwd_ntop(p->ai.str, &p->ai.sa);
        }

        send(p->fd, buffer, recv_len, 0);
        p->trx_time = time(0);
        printf("[%d] [% 5d bytes] <-- %s\n", wd->thread_id, recv_len, p->ai.str);
        memset(buffer, 0, recv_len);
meow:
        for (i = 0; i < UDPFWD_MAX_CONNS; i++) {
            if (conns[i].fd == INVALID_SOCKET) continue;
            recv_len = recv(conns[i].fd, buffer, UDPFWD_PACKET_SIZE, 0);
            if (recv_len > 0) {
                printf("[%d] [% 5d bytes] --> %s\n", wd->thread_id, recv_len, conns[i].ai.str);
                sendto(wd->listen->fd, buffer, recv_len, 0,
                        (struct sockaddr*)&conns[i].ai.sa, sizeof(udpfwd_sa));
                conns[i].trx_time = time(0);
                memset(buffer, 0, recv_len);
            }
        }
    }

    // close the sockets
    for (i = 0; i < UDPFWD_MAX_CONNS; i++)
        closesocket(conns[i].fd);

    closesocket(wd->listen->fd);
    free(buffer);
    free(conns);
    printf("[%d] shutting down...\n", wd->thread_id);
    return 0;
}
