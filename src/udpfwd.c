#include "udpfwd.h"

#include <getopt.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <stun.h>
#include <uv.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2ipdef.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#endif // _WIN32

static uv_signal_t gSignal;
static udpfwd_addrinfo gDestAddr;
static udpfwd_conn gSrv4, // udp server on ipv4 stack
                   gSrv6; // udp server on ipv6 stack
static unsigned int gMaxConns = UDPFWD_MAX_CONNS;
static int gTURNClientMode = 0;

/*
 The "optional value of an option" feature is only a GNU libc extension,
 not required by POSIX, and is probably simply unimplemented by the libc
 shipped with Mac OS X.
 The options argument is a string that specifies the option characters that are
 valid for this program. An option character in this string can be followed b
 a colon (‘:’) to indicate that it takes a required argument. If an option
 character is followed by two colons (‘::’), its argument is optional;
 this is a GNU extension.
*/
static const char *gOptsShort = "d:p:t::64lh?";
static struct option gOptsLong[] = {
    {"destination", required_argument, NULL, 'd'},
    {"listen-port", required_argument, NULL, 'p'},
    {"turn-client", optional_argument, NULL, 't'},
    {"no-ipv4", no_argument, NULL, '6'},
    {"no-ipv6", no_argument, NULL, '4'},
    {"loopback", no_argument, NULL, 'l'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}};

static int sa_pton(udpfwd_sa *dst, const char *src);
static int sa_ntop(char *dst, const udpfwd_sa *src);
static int sa_is_valid(const struct sockaddr *p);

static int socket_timeout_set(int fd, time_t seconds);

// find client info in the list or create one if not exists, or return null
static udpfwd_inbound_info *origin_find_in_list(udpfwd_inbound_info *list,
                                                const struct sockaddr *addr,
                                                const uv_udp_t *srv_handle);

static void buf_alloc(uv_handle_t *handle, size_t suggested_size,
                      uv_buf_t *buf);
static void buf_free(const uv_buf_t *buf);

static void srv_on_recv(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags);

static void dst_on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags);

static void on_send(uv_udp_send_t *req, int status);

static void on_close(uv_handle_t *handle) {
  if (handle->type == UV_UDP) {
    // all uv_udp_t handles are allocated by this program, so...
    free(handle);
    UDPFWD_TRACE("*** udp handle (%p) closed.\n", (void *)handle);
  } else {
    UDPFWD_TRACE("*** handle (%p) closed.\n", (void *)handle);
  }
}

static void on_uv_walk(uv_handle_t *handle, void *arg) {
  uv_close(handle, on_close);
}

// https://stackoverflow.com/questions/25615340/closing-libuv-handles-correctly
static void signal_handler(uv_signal_t *handle, int signum) {
  UDPFWD_TRACE("*** signal %d received. stopping event loop...\n", signum);

  if (gSrv4.handle) {
    UDPFWD_TRACE("*** stopping udp4 server (%p)...\n",
            (void *)gSrv4.handle);
    uv_udp_recv_stop(gSrv4.handle);
  }

  if (gSrv6.handle) {
    UDPFWD_TRACE("*** stopping udp6 server (%p)...\n",
            (void *)gSrv6.handle);
    uv_udp_recv_stop(gSrv6.handle);
  }

  if (UV_EBUSY == uv_loop_close(handle->loop)) {
    uv_walk(handle->loop, on_uv_walk, NULL);
  }
}

int main(int argc, char **argv) {
  char tmp_addr_str[UDPFWD_IPSTR_LEN] = {0};
  int allow_ipv6 = 1, allow_ipv4 = 1,
      loopback_only = 0, // listen on [::1] instead of [::]
      listen_port = 65535, tmp;

#ifdef _WIN32
  WSADATA wsa_data;
  if (0 != WSAStartup(MAKEWORD(2, 2), &wsa_data)) {
    printf("WSAStartup(2.2) failed: %d\n", WSAGetLastError());
    return EXIT_FAILURE;
  }
#endif // _WIN32

  // do not remove this: (a few lines later i use gDestAddr.str's zero buffer)
  memset(&gDestAddr, 0, sizeof(gDestAddr));
  memset(&gSrv4, 0, sizeof(gSrv4));
  memset(&gSrv6, 0, sizeof(gSrv6));
  memset(&gSignal, 0, sizeof(gSignal));

  while (1) {
    tmp = getopt_long(argc, argv, gOptsShort, gOptsLong, NULL);

    if (tmp == -1) {
      break; // end of args
    }

    if (tmp == '?' || tmp == 'h') {
      puts("udpfwd - yet another udp forwarder (just use socat :p)\n\n"
           "USAGE:\n"
           "--destination (-d)\t the destination address in `addr:port`\n"
           "\t\t\t format. note that ipv6 addresses must be wrapped in "
           "square\n"
           "\t\t\t brackets (e.g. `[::1]:1234`).\n"
           "\t\t\t this option also supports domain names.\n"
           "--listen-port (-p)\t the port to listen on\n"
           "--no-ipv4 (-6)\t\t listen on the ipv6 stack only.\n"
           "--no-ipv6 (-4)\t\t listen on the ipv4 stack only.\n"
           "--loopback (-l)\t\t listen on loopback only. (e.g. 127.0.0.1 "
           "and [::1])\n"
           "--turn-client (-t)\t makes this instance act as a turn "
           "client\n"
           "\t\t\t and send a STUN binding request to the "
           "[dest_ip]:[stun_port]\n"
           "\t\t\t and print the server-reflexive peer address. also "
           "limits\n"
           "\t\t\t the number of active connections to 1. disables ipv6 "
           "too.\n");
      return EXIT_FAILURE;
    }

    if (tmp == '4') {
      allow_ipv6 = 0;
      continue;
    }

    if (tmp == '6') {
      allow_ipv4 = 0;
      continue;
    }

    if (tmp == 'l') {
      loopback_only = 1;
      continue;
    }

    if (tmp == 't') {
      gTURNClientMode = (optarg == NULL) ? -1 : atoi(optarg);
      if (gTURNClientMode < 1 || gTURNClientMode > 65535) {
        // set the default port for stun/turn server
        gTURNClientMode = 3478;
      }
      continue;
    }

    if (tmp == 'p') {
      listen_port = atoi(optarg);
      if (listen_port < 1 || listen_port > 65535) {
        printf("invalid port number %d (%s)", listen_port, optarg);
        return EXIT_FAILURE;
      }
      continue;
    }

    if (tmp == 'd') {
      if (sa_pton(&gDestAddr.sa, optarg)) {
        printf("udpfwd_pton('%s') failed", optarg);
        return EXIT_FAILURE;
      }
      continue;
    }
  }

  if (0 == sa_is_valid((const struct sockaddr *)&gDestAddr.sa)) {
    puts("invalid destination address");
    return EXIT_FAILURE;
  }

  if (gDestAddr.sa.v4.sin_family == AF_INET &&
      gDestAddr.sa.v4.sin_addr.s_addr == 0) {
    puts("destination 0.0.0.0 is invalid\n");
    return EXIT_FAILURE;
  }

  // gDestAddr.str is zero'd a few lines before, so it's the perfect
  // zero buffer to compare against :)
  if (gDestAddr.sa.v6.sin6_family == AF_INET6 &&
      memcmp(gDestAddr.str, &gDestAddr.sa.v6.sin6_addr, 16) == 0) {
    puts("destination [::] is invalid");
    return EXIT_FAILURE;
  }
  sa_ntop(gDestAddr.str, &gDestAddr.sa);

  // the last byte makes the difference
  *(((uint8_t *)&gSrv6.sa.v6.sin6_addr) + 15) = loopback_only;
  *((uint32_t *)&gSrv4.sa.v4.sin_addr) = htonl(loopback_only * INADDR_LOOPBACK);
  gSrv4.sa.v4.sin_port = gSrv6.sa.v6.sin6_port = htons(listen_port);
  gSrv6.sa.v6.sin6_family = AF_INET6;
  gSrv4.sa.v4.sin_family = AF_INET;

  if (allow_ipv4 == 0 && allow_ipv6 == 0) {
    puts("both --no-ipv6 (-4) and --no-ipv4 (-6) used!");
    return EXIT_FAILURE;
  }

  if (gTURNClientMode) {
    // TURN server should not be on ipv6 address!
    if (((struct sockaddr *)&gDestAddr.sa)->sa_family == AF_INET6) {
      puts("using ipv6 turn server destination is not allowed");
      return EXIT_FAILURE;
    }

    // in turn mode this can't be local loopback!
    if (gDestAddr.sa.v4.sin_addr.s_addr == 0 ||
        ntohl(gDestAddr.sa.v4.sin_addr.s_addr) == INADDR_LOOPBACK) {
      puts("can't use 127.0.0.1 or 0.0.0.0 as destination in "
           "turn client mode");
      return EXIT_FAILURE;
    }

    if (allow_ipv4 && allow_ipv6) {
      puts("in turn client mode you can only listen on one net stack. "
           "(either --no-ipv4 or --no-ipv6)");
      return EXIT_FAILURE;
    }

    gMaxConns = 1; // only one active outbound connection!
  }

  puts("Binding sockets to:");

  sa_ntop(tmp_addr_str, &gSrv4.sa);
  printf("[%c] %s\n", ' ' + (11 * allow_ipv4), tmp_addr_str);

  sa_ntop(tmp_addr_str, &gSrv6.sa);
  printf("[%c] %s\n", ' ' + (11 * allow_ipv6), tmp_addr_str);

  printf("Forwarding to:\n%s\n", gDestAddr.str);

  tmp = uv_signal_init(uv_default_loop(), &gSignal);
  if (tmp) {
    printf("uv_signal_init(): %s\n", uv_strerror(tmp));
    uv_loop_close(uv_default_loop());
    uv_library_shutdown();
    return EXIT_FAILURE;
  }

  uv_signal_start(&gSignal, signal_handler, SIGINT);

  if (allow_ipv4) {
    gSrv4.handle = (uv_udp_t *)calloc(
        1, sizeof(uv_udp_t) + (sizeof(udpfwd_inbound_info) * gMaxConns));

    uv_udp_init(uv_default_loop(), gSrv4.handle);
    uv_udp_bind(gSrv4.handle, (const struct sockaddr *)&gSrv4.sa, 0);
    uv_udp_recv_start(gSrv4.handle, buf_alloc, srv_on_recv);

    gSrv4.handle->data =
        (void *)(((unsigned long long)(gSrv4.handle)) + sizeof(uv_udp_t));

    ((udpfwd_inbound_info *)gSrv4.handle->data)->srv_handle = gSrv4.handle;

    UDPFWD_TRACE("*** udp4 handle: %p\r\n", (void *)gSrv4.handle);
  }

  if (allow_ipv6) {
    gSrv6.handle = (uv_udp_t *)calloc(
        1, sizeof(uv_udp_t) + (sizeof(udpfwd_inbound_info) * gMaxConns));

    uv_udp_init(uv_default_loop(), gSrv6.handle);
    uv_udp_bind(gSrv6.handle, (const struct sockaddr *)&gSrv6.sa,
                UV_UDP_IPV6ONLY);
    uv_udp_recv_start(gSrv6.handle, buf_alloc, srv_on_recv);

    gSrv6.handle->data =
        (void *)(((unsigned long long)(gSrv6.handle)) + sizeof(uv_udp_t));

    ((udpfwd_inbound_info *)gSrv6.handle->data)->srv_handle = gSrv6.handle;

    UDPFWD_TRACE("*** udp6 handle: %p\r\n", (void *)gSrv6.handle);
  }

  // not proud of this
  if (gTURNClientMode) {
    // in turn mode, there's only one active socket!
    uv_udp_t *uv_server_handle = (allow_ipv4) ? gSrv4.handle : gSrv6.handle;
    udpfwd_inbound_info *the_single_conn_info =
        (udpfwd_inbound_info *)uv_server_handle->data;
    struct stun_header_s *stun_req, *stun_res;
    struct stun_attr_xor_mapped_address_ipv4_s *stun_attr = NULL;
    udpfwd_addrinfo stun_server, stun_socket, stun_srflx;
    unsigned int addr_size;
    int stun_socket_fd;

    // bind socket at 0.0.0.0:0
    memset(&stun_srflx, 0, sizeof(stun_srflx));
    memset(&stun_socket, 0, sizeof(stun_socket));
    memset(&stun_server, 0, sizeof(stun_server));
    stun_socket.sa.v4.sin_family = AF_INET;

    // stun server addr: [gDest.ip]:[gTURNClientMode]
    memcpy(&stun_server.sa, &gDestAddr.sa, sizeof(udpfwd_sa));
    stun_server.sa.v4.sin_port = htons((uint16_t)gTURNClientMode);

    stun_socket_fd = (int)socket(AF_INET, SOCK_DGRAM, 0);
    if (stun_socket_fd < 0) {
      perror("socket() stun_client");
      uv_close((uv_handle_t *)uv_server_handle, on_close);
      uv_loop_close(uv_default_loop());
      uv_library_shutdown();
      return EXIT_FAILURE;
    }

    // bind to the previously-specified address
    addr_size = sizeof(struct sockaddr_in);
    if (bind(stun_socket_fd, (struct sockaddr *)&stun_socket.sa, addr_size) <
        0) {
      perror("stun_socket_fd bind to 0.0.0.0:0 failed");
      close(stun_socket_fd);
      uv_close((uv_handle_t *)uv_server_handle, on_close);
      uv_loop_close(uv_default_loop());
      uv_library_shutdown();
      return EXIT_FAILURE;
    }

    // get the random port assigned to this socket by the os
    addr_size = sizeof(struct sockaddr_in);
    getsockname(stun_socket_fd, (struct sockaddr *)&stun_socket.sa, &addr_size);

    sa_ntop(stun_socket.str, &stun_socket.sa);
    sa_ntop(stun_server.str, &stun_server.sa);
    UDPFWD_TRACE("*** stun_socket= %s, stun_server= %s\n", stun_socket.str,
                 stun_server.str);

    stun_req = stun_header_new(STUN_HTYPE_BINDING_REQUEST, 0);

    socket_timeout_set(stun_socket_fd, 2);
    stun_res = stun_query(stun_socket_fd, stun_req,
                          (struct sockaddr *)&stun_server.sa);
    if (stun_res == NULL) {
      puts("stun_query() failed!");
      close(stun_socket_fd);
      stun_header_free(stun_req);
      uv_close((uv_handle_t *)uv_server_handle, on_close);
      uv_loop_close(uv_default_loop());
      uv_library_shutdown();
      return EXIT_FAILURE;
    }

    if (stun_attr_get((struct stun_attr_s **)&stun_attr,
                      STUN_ATTR_XOR_MAPPED_ADDR, stun_res)) {
      puts("STUN_ATTR_XOR_MAPPED_ADDR not found in stun response!");
      close(stun_socket_fd);
      stun_header_free(stun_req);
      stun_header_free(stun_res);
      uv_close((uv_handle_t *)uv_server_handle, on_close);
      uv_loop_close(uv_default_loop());
      uv_library_shutdown();
      return EXIT_FAILURE;
    }

    stun_attr_xor_mapped_addr_to_sa(
        (struct sockaddr *)&stun_srflx.sa,
        (const struct stun_attr_xor_mapped_address_s *)stun_attr, stun_res);

    sa_ntop(stun_srflx.str, &stun_srflx.sa);
    printf("STUN Server-Reflexive Address:\n%s\n", stun_srflx.str);

    stun_header_free(stun_req);
    stun_header_free(stun_res);

    the_single_conn_info->dst_handle = (uv_udp_t *)calloc(1, sizeof(uv_udp_t));

    UDPFWD_TRACE("*** stun client handle=%p\r\n", (void *)the_single_conn_info);

    if (the_single_conn_info->dst_handle == NULL) {
      perror("calloc() for udp_handle_t failed\n");
      close(stun_socket_fd);
      uv_close((uv_handle_t *)uv_server_handle, on_close);
      uv_loop_close(uv_default_loop());
      uv_library_shutdown();
      return EXIT_FAILURE;
    }

    // the ref to itself for callbacks
    the_single_conn_info->dst_handle->data = (void *)the_single_conn_info;

    uv_udp_init(the_single_conn_info->srv_handle->loop,
                the_single_conn_info->dst_handle);

    // bind this new destination socket to the same port used for stun query
    // so symmetric NAT won't assign a new public port to this one.
    // close(stun_socket_fd);
    uv_udp_bind(the_single_conn_info->dst_handle,
                (const struct sockaddr *)&stun_socket.sa, SO_REUSEPORT);

    // connect to the destination address which has the same ip
    // as the stun server. the ports are the only things that differ!
    uv_udp_connect(the_single_conn_info->dst_handle,
                   (const struct sockaddr *)&gDestAddr.sa);

    uv_udp_recv_start(the_single_conn_info->dst_handle, buf_alloc, dst_on_recv);

    // hmmm. closing it makes the allocated port go away?
    // close(stun_socket_fd);
  }

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  uv_loop_close(uv_default_loop());
  uv_library_shutdown();

#ifdef _WIN32
  WSACleanup();
#endif
  return EXIT_SUCCESS;
}

static void buf_alloc(uv_handle_t *handle, size_t suggested_size,
                      uv_buf_t *buf) {
  buf->base = (char *)malloc(suggested_size);
  buf->len = suggested_size;
}

static void buf_free(const uv_buf_t *buf) { free(buf->base); }

static udpfwd_inbound_info *origin_find_in_list(udpfwd_inbound_info *list,
                                                const struct sockaddr *addr,
                                                const uv_udp_t *srv_handle) {
  udpfwd_inbound_info *j = NULL;
  size_t addr_size = sizeof(struct sockaddr_in);
  time_t now = time(NULL);
  int i = 0, first_free_index = -1;

  if (addr->sa_family == AF_INET6) {
    addr_size = sizeof(struct sockaddr_in6);
  }

  if (gTURNClientMode) {
    if (list[0].addr.sa.v4.sin_family == 0) {
      // running in gTURNClientMode, causes udpfwd to create this single
      // outbound socket to also use for stun reflexive peer address
      // lookup therefore, this entry has no matching origin address but
      // every other field has a correct value.
      memcpy(&list[0].addr.sa, addr, addr_size);
      sa_ntop(list[0].addr.str, (const udpfwd_sa *)addr);
      UDPFWD_TRACE("*** setting the origin to %s\n", list[0].addr.str);
    }

    // don't ever expire
    list[0].last_trx = now;

    // reject other connections too
    if (memcmp(addr, &list[0].addr.sa, addr_size) == 0) {
      return &list[0];
    }

    // print "no more room" and return (j = NULL)
    goto origin_find_in_list_no_more;
  }

  for (; i < gMaxConns; ++i) {
    if ((now - list[i].last_trx) >= UDPFWD_CONN_TTL) {
      if (first_free_index == -1) {
        first_free_index = i;
      }

      // this handle is active but stale
      if (list[i].dst_handle != NULL) {
        UDPFWD_TRACE("*** udp_recv_stop(handle: %p) i=%d, origin=%s\r\n",
                     (void *)list[i].dst_handle, i, list[i].addr.str);
        uv_udp_recv_stop(list[i].dst_handle);
        uv_close((uv_handle_t *)list[i].dst_handle, on_close);
        // do not free the allocated memory for the handle here!
        // on_close() will take care of that.
        memset(&list[i], 0, sizeof(udpfwd_inbound_info));
      }
    }

    if (memcmp(addr, &list[i].addr.sa, addr_size) == 0) {
      return &list[i];
    }
  }

  if (first_free_index >= 0) {
    j = &list[first_free_index];
    memcpy(&j->addr.sa, addr, addr_size);
    sa_ntop(j->addr.str,
            // don't worry about addr_size here,
            // this function checks for correct sa_family and size
            (const udpfwd_sa *)addr);
    j->srv_handle = srv_handle;
    j->dst_handle = (uv_udp_t *)calloc(1, sizeof(uv_udp_t));

    UDPFWD_TRACE("*** new dest handle=%p, i=%d, origin=%s\r\n",
                 (void *)j->dst_handle, first_free_index, j->addr.str);

    // allocation failed!
    if (j->dst_handle == NULL) {
      return NULL;
    }

    j->dst_handle->data = (void *)j; // keep a ref to itself for callbacks
    uv_udp_init(srv_handle->loop, j->dst_handle);
    uv_udp_connect(j->dst_handle, (const struct sockaddr *)&gDestAddr.sa);
    uv_udp_recv_start(j->dst_handle, buf_alloc, dst_on_recv);
    j->last_trx = now;
  }

origin_find_in_list_no_more:
  if (j == NULL) {
    UDPFWD_TRACE("*** j=NULL; max active connections reached!\n");
  }

  return j;
}

static void dst_on_recv(uv_udp_t *this, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags) {
  uv_udp_send_t *send_req = NULL;
  udpfwd_send_req_data *req_data = NULL;
  udpfwd_inbound_info *origin = (udpfwd_inbound_info *)this->data;
  time_t now = time(0);

  if (nread < 0)
    goto dst_recv_print_err;

  if ((now - origin->last_trx) >= UDPFWD_CONN_TTL) {
    UDPFWD_TRACE("*** dst_on_rcv() ttl has reached!\n");
    // just ignore it, closing it here again causes some double close
    goto dst_recv_free_buf;
  }

  // empty packets
  if (nread == 0)
    goto dst_recv_free_buf;

  // activity on the connection makes it alive
  origin->last_trx = now;

  printf("<-- RECV %6ld BYTES FROM %s\n", nread, gDestAddr.str);

  // use one allocation and store the udpfwd_send_req_data at the end of first
  // struct.
  send_req = calloc(1, sizeof(uv_udp_send_t) + sizeof(udpfwd_send_req_data));
  req_data = (udpfwd_send_req_data *)(((unsigned long long)send_req) +
                                      sizeof(uv_udp_send_t));
  req_data->buffer.base = buf->base;
  req_data->buffer.len = nread; // actual size of the recv data
  req_data->dst_addr_str = (const char *)origin->addr.str;
  req_data->origin = origin;

  send_req->data = (void *)req_data;

  // send from [SERVER] -> [ORIGIN]
  nread =
      uv_udp_send(send_req, (uv_udp_t *)origin->srv_handle, &req_data->buffer,
                  1, (const struct sockaddr *)&origin->addr.sa, on_send);

  if (nread == 0) {
    // buf->base must not be freed
    // on_send() will free them all at once
    return;
  }

  free(send_req);
dst_recv_print_err:
  UDPFWD_TRACE("*** libuv: %s (dst_handle: %p)\n", uv_strerror(nread),
               (void *)this);
dst_recv_free_buf:
  buf_free(buf);
}

static void on_send(uv_udp_send_t *req, int status) {
  const udpfwd_send_req_data *data = (const udpfwd_send_req_data *)req->data;

  if (status < 0 || data->buffer.len <= 0) {
    UDPFWD_TRACE("*** libuv: %s (on_send)\n", uv_strerror(status));
    goto skip_printing_status;
  }

  printf("--> SENT %6lu BYTES TO   %s\n", data->buffer.len, data->dst_addr_str);

  // update actual transmission time for origin conn when send succeeds
  data->origin->last_trx = time(NULL);

skip_printing_status:
  // even though the uv_buf_t supplied in req->data
  // is a copy. but the req->data->base is allocated separately
  buf_free(&data->buffer);
  free(req);
}

static void srv_on_recv(uv_udp_t *this, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags) {
  uv_udp_send_t *send_req = NULL;
  udpfwd_send_req_data *req_data = NULL;
  // the client which the first inbound connection originates from
  udpfwd_inbound_info *origin = NULL;

  if (nread < 0)
    goto srv_recv_print_err;

  // empty packets
  if (nread == 0)
    goto srv_recv_free_buf;

  // find the corresponding destination handle opened for this client address
  origin = origin_find_in_list((udpfwd_inbound_info *)this->data, addr, this);
  if (origin == NULL)
    goto srv_recv_free_buf;

  printf("<-- RECV %6ld BYTES FROM %s\n", nread, origin->addr.str);

  // use one allocation and store the udpfwd_send_req_data at the end of first
  // struct.
  send_req = calloc(1, sizeof(uv_udp_send_t) + sizeof(udpfwd_send_req_data));
  req_data = (udpfwd_send_req_data *)(((unsigned long long)send_req) +
                                      sizeof(uv_udp_send_t));
  req_data->buffer.base = buf->base;
  req_data->buffer.len = nread; // actual size of the recv data
  req_data->dst_addr_str = (const char *)gDestAddr.str;
  req_data->origin = origin;

  send_req->data = (void *)req_data;

  // send from [NEW_SOCKET] -> [DESTINATION]
  nread = uv_udp_send(send_req, origin->dst_handle, &req_data->buffer, 1,
                      // For connected UDP handles, addr must be set to NULL,
                      // otherwise it will return UV_EISCONN error.
                      NULL, on_send);

  if (nread == 0 /* OK */) {
    // buf->base must not be freed
    // on_send will free them all at once
    return;
  }

  free(send_req);
srv_recv_print_err:
  UDPFWD_TRACE("*** libuv: %s (srv_handle: %p)\n", uv_strerror(nread),
               (void *)this);
srv_recv_free_buf:
  buf_free(buf);
}

static int sa_is_valid(const struct sockaddr *p) {
  if (p->sa_family == AF_INET) {
    const struct sockaddr_in *f = (const struct sockaddr_in *)p;
    return (f->sin_port != 0);
  }

  if (p->sa_family == AF_INET6) {
    const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)p;
    return (s->sin6_port != 0);
  }

  return 0;
}

static int sa_pton(udpfwd_sa *dst, const char *src) {
  static char tmp[128]; // max len for domains
  struct addrinfo hints, *servinfo = NULL, *p = NULL;
  int a, b;

  memset(dst, 0, sizeof(udpfwd_sa));
  memset(tmp, 0, sizeof(tmp));

  a = strlen(src);
  for (b = a - 1; b >= 1 && src[b] != ':'; b--)
    ;

  // no port
  if (b == 0) {
    fputs("no port number detected\n", stderr);
    return 2;
  }

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
        freeaddrinfo(servinfo);
        return 0;
      }
    }

    freeaddrinfo(servinfo);
    return 1; // no results?
  }

  return 0;
}

static int sa_ntop(char *dst, const udpfwd_sa *src) {
  int i = 0;

  if (!sa_is_valid((const struct sockaddr *)src)) {
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
    if (0 ==
        inet_ntop(AF_INET6, &src->v6.sin6_addr, dst + 1, UDPFWD_IPSTR_LEN)) {
      perror("inet_ntop(AF_INET6, ...):");
      return 3;
    }
  }

  for (; dst[i] != 0; i++)
    ;

  if (src->v6.sin6_family == AF_INET6) {
    dst[0] = '[';
    dst[i++] = ']';
  }

  sprintf(dst + i, ":%u", ntohs(src->v4.sin_port));

  return 0;
}

static int socket_timeout_set(int fd, time_t seconds) {
  struct timeval timeout;

  timeout.tv_sec = seconds;
  timeout.tv_usec = 0;

  return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}
