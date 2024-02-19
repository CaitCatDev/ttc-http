#include <errno.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509v3.h>

#include <poll.h>

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ttc-log.h>
#include <unistd.h>

#include <sys/msg.h>
#include <sys/socket.h>

#include <ttc-http/sockets.h>

#include <ttc-http/private/requests.h>
#include <ttc-http/private/sockets.h>

int ttc_http_socket_peek(ttc_http_socket_t *sock, void *buf, size_t in, size_t *out) {
	int res;

	switch (sock->type) {
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

	switch (sock->type) {
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

	switch (sock->type) {
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

static int ttc_http_socket_from_host(const char *host, const char *port,
																		 const struct addrinfo *hints) {
	int res, fd;
	struct addrinfo *info, default_hints;

	if (hints) {
		/*Use user provided hints for socket*/
		memcpy(&default_hints, hints, sizeof(struct addrinfo));
	} else {
		/*Initialise to zero*/
		memset(&default_hints, 0, sizeof(struct addrinfo));
		default_hints.ai_socktype = SOCK_STREAM;
	}

	/*setup socket*/
	res = getaddrinfo(host, port, &default_hints, &info);
	if (res != 0) {
		printf("getaddrinfo: %s\n", gai_strerror(res));
		return -1;
	}

	fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if (fd < 0) {
		printf("socket: %m\n");
		freeaddrinfo(info);
		return -1;
	}

	res = connect(fd, info->ai_addr, (int) info->ai_addrlen);
	freeaddrinfo(info);
	if (res != 0) {
		printf("connect: %m\n");
		close(fd);
		return -1;
	}

	return fd;
}

static int verify_callback(int preverify, X509_STORE_CTX *x509_ctx) {
	int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	int err = X509_STORE_CTX_get_error(x509_ctx);

	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	X509_NAME *iname = cert ? X509_get_issuer_name(cert) : NULL;
	X509_NAME *sname = cert ? X509_get_subject_name(cert) : NULL;

	char *issuer = X509_NAME_oneline(iname, NULL, 0);
	char *subject = X509_NAME_oneline(sname, NULL, 0);

	TTC_LOG_DEBUG("Depth: %d\n", depth);
	TTC_LOG_DEBUG("Issuer (cn) %s\n", issuer);
	TTC_LOG_DEBUG("Subject (cn) %s\n", subject);
	TTC_LOG_DEBUG("Error: %d\n", err);

	free(issuer);
	free(subject);

	return preverify;
}

static SSL *ttc_http_ssl_socket_setup(SSL_CTX *ctx, int fd, const char *hostname) {
	SSL *ssl;
	int res;
	X509_VERIFY_PARAM *param;

	ssl = SSL_new(ctx);

	if (SSL_set_fd(ssl, fd) == 0) {
		printf("SSL_set_fd Failed\n");
		return NULL;
	}

	param = SSL_get0_param(ssl);

	/* Enable automatic hostname checks */
	X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	if (!X509_VERIFY_PARAM_set1_host(param, hostname, strlen(hostname))) {
		SSL_free(ssl);
		TTC_LOG_ERROR("Failed to set automatic hostname checks\n");
		return NULL;
	}

	/*provide sni for things that need it*/
	SSL_set_tlsext_host_name(ssl, hostname);
	SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_callback);
	/*Max depth*/
	SSL_set_verify_depth(ssl, 4);

	SSL_CTX_set_default_verify_paths(ctx);

	if ((res = SSL_connect(ssl)) != 1) {
		SSL_free(ssl);
		TTC_LOG_ERROR("Failed to SSL connect to host: %s\n", hostname);
		return NULL;
	}

	return ssl;
}

ttc_http_socket_t *ttc_http_new_socket(const char *host, const char *port, SSL_CTX *ctx) {
	return ttc_http_new_socket_hints(host, port, ctx, NULL);
}

ttc_http_socket_t *ttc_http_new_socket_hints(const char *host, const char *port, SSL_CTX *ctx,
																						 const struct addrinfo *hints) {
	ttc_http_socket_t *socket = calloc(1, sizeof(ttc_http_socket_t));

	socket->fd = ttc_http_socket_from_host(host, port, hints);
	if (socket->fd < 0) {
		free(socket);
		return NULL;
	}

	socket->type = TtcSocketHTTP;

	if (ctx) {
		SSL_load_error_strings();
		socket->ctx = ctx;

		socket->ssl = ttc_http_ssl_socket_setup(ctx, socket->fd, host);
		if (socket->ssl == NULL) {
			close(socket->fd);
			free(socket);
			return NULL;
		}
		socket->type = TtcSocketSSL;
	}

	return socket;
}

int ttc_http_socket_send_data(ttc_http_socket_t *sock, void *data, uint64_t length) {
	switch (sock->type) {
		case TtcSocketSSL:
			SSL_write(sock->ssl, data, length);
			return 1;
		case TtcSocketHTTP:
			send(sock->fd, data, length, 0);
			return 1;
	}

	return 0;
}

int ttc_http_socket_send_request(ttc_http_socket_t *sock, ttc_http_request_t *request) {
	ttc_http_request_build(request);
	TTC_LOG_INFO("Sending %s\n", request->req_str);
	switch (sock->type) {
		case TtcSocketSSL:
			SSL_write(sock->ssl, request->req_str, strlen(request->req_str));
			return 1;
		case TtcSocketHTTP:
			send(sock->fd, request->req_str, strlen(request->req_str), 0);
			return 1;
	}

	return 0;
}

void ttc_http_socket_free(ttc_http_socket_t *socket) {
	if (!socket) {
		return;
	}

	if (socket->ssl) {
		SSL_shutdown(socket->ssl);

		SSL_free(socket->ssl);
	}
	if (socket->fd > -1) {
		close(socket->fd);
	}

	free(socket);
}
