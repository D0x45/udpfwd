#include "udpfwd.h"

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netdb.h>
#  include <fcntl.h>
#endif

int udpfwd_sa_is_valid(const struct sockaddr *p)
{
    if (p->sa_family == AF_INET) {
        const struct sockaddr_in *f = (const struct sockaddr_in*)p;
        return (f->sin_port != 0);
    }

    if (p->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6*)p;
        return (s->sin6_port != 0);
    }

    return 0;
}

int udpfwd_pton(udpfwd_sa *dst, const char *src)
{
    struct addrinfo hints,
                   *servinfo = NULL,
                   *p = NULL;
    int a, b;
    char tmp[128]; // max len for domains

    memset(dst, 0, sizeof(udpfwd_sa));
    memset(tmp, 0, sizeof(tmp));

    a = strlen(src);
    for (b = a - 1; b >= 1 && src[b] != ':'; b--);

    // no port
    if (b == 0)
        return 2;

    a = atoi(src + b + 1);
    if (a < 1 || a > 65535) {
        fprintf(stderr, "invalid port number %d ('%s')\n", a, src + b + 1);
        return 5;
    }

    // ipv6
    if (src[0] == '[') {
        memcpy(tmp, src + 1, b - 2);
        if (0 == inet_pton(AF_INET6, tmp, &dst->v6.sin6_addr)) {
            fprintf(stderr, "inet_pton(AF_INET6, '%s') failed\n", tmp);
            return 3;
        }
        dst->v6.sin6_port = htons(a);
        dst->v6.sin6_family = AF_INET6;
    }
    // ipv4
    else if (src[0] > '0' && src[0] < '3') {
        memcpy(tmp, src, b);
        if (0 == inet_pton(AF_INET, tmp, &dst->v4.sin_addr)) {
            fprintf(stderr, "inet_pton(AF_INET, '%s') failed\n", tmp);
            return 4;
        }
        dst->v4.sin_port = htons(a);
        dst->v4.sin_family = AF_INET;
    }
    // probably a domain name?
    else {
        memset(&hints, 0, sizeof(hints));
        memcpy(tmp, src, b);

        hints.ai_family = AF_UNSPEC;
        a = getaddrinfo(tmp, src + b + 1, &hints, &servinfo);
        if (a != 0) {
            fprintf(stderr, "getaddrinfo('%s', '%s'): %s\n", tmp, src + b + 1,
                    gai_strerror(a));
            return 6;
        }

        for (p = servinfo; p != NULL; p = p->ai_next) {
            if (p->ai_family == AF_INET || p->ai_family == AF_INET6) {
                memcpy(dst, p->ai_addr, p->ai_addrlen);
                return 0;
            }
        }

        freeaddrinfo(servinfo);
        return 1; // no results?
    }

    return 0;
}

int udpfwd_ntop(char *dst, const udpfwd_sa *src)
{
    int i = 0;

    if (!udpfwd_sa_is_valid((const struct sockaddr*)src)) {
        fputs("udpfwd_ntop() failed. src is not a valid address!\n", stderr);
        return 1;
    }

    memset(dst, 0, UDPFWD_IPSTR_LEN);

    if (src->v4.sin_family == AF_INET) {
        if (0 == inet_ntop(AF_INET, &src->v4.sin_addr, dst, UDPFWD_IPSTR_LEN)) {
            perror("inet_ntop(AF_INET, ...):");
            return 2;
        }
    } else {
        i++;
        if (0 == inet_ntop(AF_INET6, &src->v6.sin6_addr, dst + 1, UDPFWD_IPSTR_LEN)) {
            perror("inet_ntop(AF_INET6, ...):");
            return 3;
        }
    }

    for (; dst[i] != 0; i++);

    if (src->v6.sin6_family == AF_INET6) {
        dst[0] = '[';
        dst[i++] = ']';
    }

    sprintf(dst + i, ":%u", ntohs(src->v4.sin_port));

    return 0;
}

const char *udpfwd_sa_str(const udpfwd_sa *src)
{
    static char tmp[UDPFWD_IPSTR_LEN];
    if (udpfwd_ntop(tmp, src))
        return NULL;
    return tmp;
}

void udpfwd_perror(const char* msg)
{
#ifdef _WIN32
    char tmp[256];
    int errcode = WSAGetLastError();
    memset(tmp, 0, sizeof(tmp));
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, errcode,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), tmp, 255, 0);
    fprintf(stderr, "%s: (%d) %s", msg, errcode, tmp);
#else
    perror(msg);
#endif
}

void udpfwd_nonblock(udpfwd_sockfd fd)
{
#ifdef _WIN32
    unsigned long nonblock = 1;
    ioctlsocket(fd, FIONBIO, &nonblock);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return;
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}
