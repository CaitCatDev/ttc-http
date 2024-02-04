#pragma once

#include <openssl/ssl.h>
#include <ttc-http/request.h>
#include <stddef.h>

typedef struct ttc_http_socket ttc_http_socket_t;



ttc_http_socket_t *ttc_http_new_socket(const char *host, const char *port, SSL_CTX *ctx);
int ttc_http_socket_poll(ttc_http_socket_t *sock, short events, short *revents);
int ttc_http_socket_peek(ttc_http_socket_t *sock, void *buf, size_t in, size_t *out);
int ttc_http_socket_read(ttc_http_socket_t *sock, void *buf, size_t in, size_t *out);
int ttc_http_socket_send_request(ttc_http_socket_t *sock, ttc_http_request_t *request);
int ttc_http_socket_send_data(ttc_http_socket_t *sock, void *data, uint64_t length);
void ttc_http_socket_free(ttc_http_socket_t *socket);
