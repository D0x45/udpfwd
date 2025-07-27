#ifndef __UDPFWD_H__
#define __UDPFWD_H__

#include <time.h>
#include <winsock2.h>
#include <ws2ipdef.h>

#include <uv.h>

enum {
    UDPFWD_MAX_CONNS   = 60,
    UDPFWD_IPSTR_LEN   = 45 + 1 + 5 + 1,
    UDPFWD_CONN_TTL    = 15,
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
    uv_udp_t      handle;
} udpfwd_conn;

typedef struct {
    const uv_udp_t *srv_handle; // the server socket this connection is on
    udpfwd_addrinfo addr;       // origin client's address
    uv_udp_t        dst_handle; // the socket that is connected to destination
    time_t          last_trx;   // last transmission time
} udpfwd_inbound_info;

typedef struct {
    // this is not a deep copy. it's like a CoW. the inner buffer (->base)
    // must be freed separately
    uv_buf_t             buffer;
    udpfwd_inbound_info *origin;
    const char          *dst_addr_str;
} udpfwd_send_req_data;

#endif // __UDPFWD_H__
