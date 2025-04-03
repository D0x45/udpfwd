#ifndef __UDPFWD_H__
#define __UDPFWD_H__

#include <stdint.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2ipdef.h>
#  include <ws2tcpip.h>
#  include <processthreadsapi.h>
#  include <errhandlingapi.h>
#  include <synchapi.h>
#  define UDPFWD_THREAD_API DWORD WINAPI
typedef SOCKET udpfwd_sockfd;
typedef HANDLE udpfwd_thread;
#else
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <pthread.h>
#  define UDPFWD_THREAD_API void*
#  ifndef INVALID_SOCKET
#    define INVALID_SOCKET (-1)
#  endif
#  ifndef closesocket
#    define closesocket(fd) close(fd);
#  endif
typedef int udpfwd_sockfd;
typedef pthread_t udpfwd_thread;
#endif // _WIN32

enum {
    UDPFWD_MAX_CONNS   = 60,
    UDPFWD_PACKET_SIZE = 68608,
    UDPFWD_IPSTR_LEN   = 45 + 1 + 5 + 1,
    UDPFWD_CONN_TTL    = 10,
};

typedef union {
    struct sockaddr_in  v4;
    struct sockaddr_in6 v6;
} udpfwd_sa;

typedef struct {
    udpfwd_sa sa;
    char      str[UDPFWD_IPSTR_LEN];
} udpfwd_addrinfo;

typedef struct {
    udpfwd_sa     sa;
    udpfwd_sockfd fd;
} udpfwd_conn;

typedef struct {
    udpfwd_thread   handle;
    udpfwd_addrinfo *dst;
    udpfwd_conn     *listen;
    int             *keep_running;
    int              thread_id;
} udpfwd_wdata;

void udpfwd_perror(const char* msg);
void udpfwd_nonblock(udpfwd_sockfd fd);
int udpfwd_pton(udpfwd_sa *dst, const char *src);
int udpfwd_ntop(char *dst, const udpfwd_sa *src);

const char *udpfwd_sa_str(const udpfwd_sa *src);
int udpfwd_sa_is_valid(const struct sockaddr *p);

UDPFWD_THREAD_API udpfwd_worker_fn(void *param);

#endif // __UDPFWD_H__
