#include "udpfwd.h"

#include <getopt.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <uv.h>

static uv_signal_t     gSignal;
static udpfwd_addrinfo gDestAddr;
static udpfwd_conn     gSrv4, // udp server on ipv4 stack
					   gSrv6; // udp server on ipv6 stack

static const char *gOptsShort = "d:p:64lh?";
static struct option gOptsLong[] = {
	{"destination", required_argument, NULL, 'd'},
	{"listen-port", required_argument, NULL, 'p'},
	{"no-ipv4", no_argument, NULL, '6'},
	{"no-ipv6", no_argument, NULL, '4'},
	{"loopback", no_argument, NULL, 'l'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0}};

static int sa_pton(udpfwd_sa *dst, const char *src);
static int sa_ntop(char *dst, const udpfwd_sa *src);
static int sa_is_valid(const struct sockaddr *p);

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
	fprintf(stderr, "*** handle (%p) closed.\r\n", handle);

	if (handle->type == UV_UDP) {
		// all uv_udp_t handles are allocated by this program, so...
		free(handle);
	}
}

static void on_uv_walk(uv_handle_t* handle, void* arg) {
    uv_close(handle, on_close);
}

// https://stackoverflow.com/questions/25615340/closing-libuv-handles-correctly
static void signal_handler(uv_signal_t *handle, int signum) {
	fprintf(stdout, "*** signal %d received. stopping event loop...\r\n", signum);

	if (gSrv4.handle) {
		fprintf(stderr, "*** stopping udp4 server (%p)...\r\n", gSrv4.handle);
		uv_udp_recv_stop(gSrv4.handle);
	}

	if (gSrv6.handle) {
		fprintf(stderr, "*** stopping udp6 server (%p)...\r\n", gSrv6.handle);
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
		fprintf(stderr, "WSAStartup() failed: %d\n", WSAGetLastError());
		return EXIT_FAILURE;
	}
#endif // _WIN32

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
			fputs(
				  "udpfwd - yet another udp forwarder (just use socat :p)\n\n"
				  "USAGE:\n"
				  "--destination (-d)\t the destination address in `addr:port`\n"
				  "\t\t\t format. note that ipv6 addresses must be wrapped in square\n"
				  "\t\t\t brackets (e.g. `[::1]:1234`).\n"
				  "\t\t\t this option also supports domain names.\n"
				  "--listen-port (-p)\t the port to listen on\n"
				  "--no-ipv4 (-6)\t\t listen on the ipv6 stack only.\n"
				  "--no-ipv6 (-4)\t\t listen on the ipv4 stack only.\n"
				  "--loopback (-l)\t\t listen on loopback only. (e.g. 127.0.0.1 "
				  "and [::1])\n\n",
				  stdout);
			return EXIT_FAILURE;
		}

		if (tmp == '4') {
			allow_ipv6 = 0;
		}

		if (tmp == '6') {
			allow_ipv4 = 0;
		}

		if (tmp == 'l') {
			loopback_only = 1;
		}

		if (tmp == 'p') {
			listen_port = atoi(optarg);
			if (listen_port < 1 || listen_port > 65535) {
				fprintf(stderr, "invalid port number %d (%s)\r\n", listen_port,
						optarg);
				return EXIT_FAILURE;
			}
		}

		if (tmp == 'd') {
			if (sa_pton(&gDestAddr.sa, optarg)) {
				fprintf(stderr, "udpfwd_pton('%s') failed.\r\n", optarg);
				return EXIT_FAILURE;
			}
			sa_ntop(gDestAddr.str, &gDestAddr.sa);
		}
	}

	if (0 == sa_is_valid((const struct sockaddr *)&gDestAddr.sa)) {
		fputs("invalid destination address.\r\n", stderr);
		return EXIT_FAILURE;
	}

	// the last byte makes the difference
	*(((uint8_t *)&gSrv6.sa.v6.sin6_addr) + 15) = loopback_only;
	*((uint32_t *)&gSrv4.sa.v4.sin_addr) =
		htonl(loopback_only * INADDR_LOOPBACK);
	gSrv4.sa.v4.sin_port = gSrv6.sa.v6.sin6_port = htons(listen_port);
	gSrv6.sa.v6.sin6_family = AF_INET6;
	gSrv4.sa.v4.sin_family = AF_INET;

	puts("Binding sockets to:");

	sa_ntop(tmp_addr_str, &gSrv4.sa);
	printf("[%c] %s\n", ' ' + (11 * allow_ipv4), tmp_addr_str);

	sa_ntop(tmp_addr_str, &gSrv6.sa);
	printf("[%c] %s\n", ' ' + (11 * allow_ipv6), tmp_addr_str);

	printf("Forwarding to:\n%s\n", gDestAddr.str);

	tmp = uv_signal_init(uv_default_loop(), &gSignal);
	if (tmp) {
		fprintf(stderr, "uv_signal_init(): %s\r\n", uv_strerror(tmp));
		return EXIT_FAILURE;
	}

	uv_signal_start(&gSignal, signal_handler, SIGINT);

	if (allow_ipv4) {
		gSrv4.handle = (uv_udp_t *)calloc(1, sizeof(uv_udp_t) +
							(sizeof(udpfwd_inbound_info) * UDPFWD_MAX_CONNS));

		uv_udp_init(uv_default_loop(), gSrv4.handle);
		uv_udp_bind(gSrv4.handle, (const struct sockaddr *)&gSrv4.sa, 0);
		uv_udp_recv_start(gSrv4.handle, (uv_alloc_cb)buf_alloc, srv_on_recv);

		gSrv4.handle->data = (void *)(((unsigned long long)(gSrv4.handle)) +
										sizeof(uv_udp_t));

		fprintf(stderr, "*** udp4 handle: %p\r\n", gSrv4.handle);
	}

	if (allow_ipv6) {
		gSrv6.handle = (uv_udp_t *)calloc(1, sizeof(uv_udp_t) +
							(sizeof(udpfwd_inbound_info) * UDPFWD_MAX_CONNS));

		uv_udp_init(uv_default_loop(), gSrv6.handle);
		uv_udp_bind(gSrv6.handle, (const struct sockaddr *)&gSrv6.sa,
					UV_UDP_IPV6ONLY);
		uv_udp_recv_start(gSrv6.handle, (uv_alloc_cb)buf_alloc, srv_on_recv);

		gSrv6.handle->data = (void *)(((unsigned long long)(gSrv6.handle)) +
										sizeof(uv_udp_t));

		fprintf(stderr, "*** udp6 handle: %p\r\n", gSrv6.handle);
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

	for (; i < UDPFWD_MAX_CONNS; ++i) {
		if ((now - list[i].last_trx) >= UDPFWD_CONN_TTL) {
			if (first_free_index == -1) {
				first_free_index = i;
			}

			// this handle is active but stale
			if (list[i].dst_handle != NULL) {
				fprintf(stderr,
						"*** udp_recv_stop(handle: %p) i=%d, origin=%s\r\n",
						list[i].dst_handle, i, list[i].addr.str
						);
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

		fprintf(stderr, "*** new dest handle=%p, i=%d, origin=%s\r\n",
					j->dst_handle, first_free_index, j->addr.str);

		j->dst_handle->data = (void *)j; // keep a ref to itself for callbacks
		uv_udp_init(srv_handle->loop, j->dst_handle);
		uv_udp_connect(j->dst_handle, (const struct sockaddr *)&gDestAddr.sa);
		uv_udp_recv_start(j->dst_handle, buf_alloc, dst_on_recv);
		j->last_trx = now;
	}

	if (j == NULL) {
		fputs("*** j=NULL; max active connections reached!\r\n", stderr);
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

	if ((now-origin->last_trx) >= UDPFWD_CONN_TTL) {
		// just ignore it, closing it here again causes some double close
		goto dst_recv_free_buf;
	}

	// empty packets
	if (nread == 0)
		goto dst_recv_free_buf;

	// activity on the connection makes it alive
	origin->last_trx = time(NULL);

	fprintf(stdout, "<-- RECV %6lld BYTES FROM %s\r\n", nread, gDestAddr.str);

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
	fprintf(stderr, "*** libuv: %s (dst_handle: %p)\n", uv_strerror(nread),
				this);
dst_recv_free_buf:
	buf_free(buf);
}

static void on_send(uv_udp_send_t *req, int status) {
	const udpfwd_send_req_data *data = (const udpfwd_send_req_data *)req->data;

	if (status < 0 || data->buffer.len <= 0) {
		fprintf(stderr, "*** libuv: %s (on_send)\n", uv_strerror(status));
		goto skip_printing_status;
	}

	fprintf(stdout, "--> SENT %6lu BYTES TO   %s\r\n", data->buffer.len,
			data->dst_addr_str);

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
	origin = origin_find_in_list((udpfwd_inbound_info *)this->data, addr,
								 this);
	if (origin == NULL)
		goto srv_recv_free_buf;

	fprintf(stdout, "<-- RECV %6lld BYTES FROM %s\r\n", nread,
			origin->addr.str);

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
	fprintf(stderr, "*** libuv: %s (srv_handle: %p)\n", uv_strerror(nread),
					this);
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
		fputs("no port number detected\r\n", stderr);
		return 2;
	}

	a = atoi(src + b + 1);
	if (a < 1 || a > 65535) {
		fprintf(stderr, "invalid port number %d ('%s')]r\n", a, src + b + 1);
		return 5;
	}

	// ipv6
	if (src[0] == '[') {
		memcpy(tmp, src + 1, b - 2);
		if (0 == inet_pton(AF_INET6, tmp, &dst->v6.sin6_addr)) {
			fprintf(stderr, "inet_pton(AF_INET6, '%s') failed\r\n", tmp);
			return 3;
		}
		dst->v6.sin6_port = htons(a);
		dst->v6.sin6_family = AF_INET6;
	}
	// ipv4
	else if (src[0] > '0' && src[0] < '3') {
		memcpy(tmp, src, b);
		if (0 == inet_pton(AF_INET, tmp, &dst->v4.sin_addr)) {
			fprintf(stderr, "inet_pton(AF_INET, '%s') failed\r\n", tmp);
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
			fprintf(stderr, "getaddrinfo('%s', '%s'): %s\r\n", tmp, src + b + 1,
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
		if (0 == inet_ntop(AF_INET6, &src->v6.sin6_addr, dst + 1,
						   UDPFWD_IPSTR_LEN)) {
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
