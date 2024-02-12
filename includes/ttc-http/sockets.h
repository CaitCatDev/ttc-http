#pragma once

#include <netdb.h>
#include <openssl/ssl.h>
#include <stddef.h>
#include <ttc-http/request.h>

typedef struct ttc_http_socket ttc_http_socket_t;

/** @brief This function just calls ttc_http_new_socket_hints with
 *	The hint field set to NULL
 */
ttc_http_socket_t *ttc_http_new_socket(const char *host, const char *port, SSL_CTX *ctx);

/** @brief Create a new socket paird with host and port.
 *  @param Host host name of socket
 *  @param Port port of the socket
 *  @param ctx SSL ctx if you want this to be an SSL socket. OPTIONAL
 *  @param hints user defined hints for getaddrinfo OPTIONAL
 *
 *  Socket hints defaults to a STREAM Socket and can be left out if this is desired socket type
 */
ttc_http_socket_t *ttc_http_new_socket_hints(const char *host, const char *port, SSL_CTX *ctx,
																						 const struct addrinfo *hints);

int ttc_http_socket_poll(ttc_http_socket_t *sock, short events, short *revents);
int ttc_http_socket_peek(ttc_http_socket_t *sock, void *buf, size_t in, size_t *out);
int ttc_http_socket_read(ttc_http_socket_t *sock, void *buf, size_t in, size_t *out);
int ttc_http_socket_send_request(ttc_http_socket_t *sock, ttc_http_request_t *request);
int ttc_http_socket_send_data(ttc_http_socket_t *sock, void *data, uint64_t length);
void ttc_http_socket_free(ttc_http_socket_t *socket);
