#include "ttc-http/request.h"
#include <errno.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <poll.h>

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/msg.h>

#include <ttc-http/sockets.h>

#include <ttc-http/private/sockets.h>
#include <ttc-http/private/requests.h>

int ttc_http_socket_peek(ttc_http_socket_t *sock, void *buf, size_t in, size_t *out) {
	int res;

	switch(sock->type) {
		case TtcSocketSSL:
			return SSL_peek_ex(sock->ssl, buf, in, out);
		case TtcSocketHTTP:
			*out = recv(sock->fd, buf, in, MSG_PEEK);
			return *out ? 1 : 0;
		default:
			return 0;
	}
}

int ttc_http_socket_read(ttc_http_socket_t *sock, void *buf, size_t in, size_t *out) {
	int res;

	switch(sock->type) {
		case TtcSocketSSL:
			return SSL_read_ex(sock->ssl, buf, in, out);
		case TtcSocketHTTP:
			*out = recv(sock->fd, buf, in, 0);
			return *out ? 1 : 0;
		default:
			return 0;
	}
}



int ttc_http_socket_poll(ttc_http_socket_t *sock, short events, short *revents) {
	struct pollfd pfd;
	int res = 0;

	pfd.fd = sock->fd;
	pfd.events = events;
	pfd.revents = 0;

	switch(sock->type) {
		case TtcSocketSSL:
			res = SSL_pending(sock->ssl) || poll(&pfd, 1, -1);
			break;
		case TtcSocketHTTP:
			res = poll(&pfd, 1, -1);
			break;
		default:
			break;
	}

	*revents = pfd.revents;
	return res;
}

static int ttc_http_socket_from_host(const char *host, const char *port) {
	int res, fd;
	struct addrinfo *info;

	/*setup socket*/
	res = getaddrinfo(host, port, NULL, &info);
	if(res != 0) {
		printf("getaddrinfo: %s\n", gai_strerror(res));
		return -1;
	}

	fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if(fd < 0) {
		printf("socket: %m\n");
		freeaddrinfo(info);
		return -1;
	}

	res = connect(fd, info->ai_addr, (int)info->ai_addrlen);
	freeaddrinfo(info);
	if(res != 0) {
		printf("connect: %m\n");
		close(fd);
		return -1;
	}

	return fd;
}

static SSL *ttc_http_ssl_socket_setup(SSL_CTX *ctx, int fd) {
	SSL *ssl;

	ssl = SSL_new(ctx);

	SSL_set_fd(ssl, fd);

	SSL_connect(ssl);

	return ssl;
}

ttc_http_socket_t *ttc_http_new_socket(const char *host, const char *port, SSL_CTX *ctx) {
	ttc_http_socket_t *socket = calloc(1, sizeof(ttc_http_socket_t));

	socket->fd = ttc_http_socket_from_host(host, port);
	socket->type = TtcSocketHTTP;

	if(ctx) {
		socket->ctx = ctx;

		socket->ssl = ttc_http_ssl_socket_setup(ctx, socket->fd);
		socket->type = TtcSocketSSL;
	}

	return socket;
}

int ttc_http_socket_send_request(ttc_http_socket_t *sock, ttc_http_request_t *request) {
	ttc_http_request_build(request);
	printf("Sending %s\n", request->req_str);
	switch(sock->type) {
		case TtcSocketSSL:
			SSL_write(sock->ssl, request->req_str, strlen(request->req_str));
			return 0;
		case TtcSocketHTTP:
			send(sock->fd, request->req_str, strlen(request->req_str), 0);
			return 0;
	}

	return -1;
}

void ttc_http_socket_free(ttc_http_socket_t *socket) {
		SSL_shutdown(socket->ssl);

		SSL_free(socket->ssl);

		close(socket->fd);

		free(socket);
}
