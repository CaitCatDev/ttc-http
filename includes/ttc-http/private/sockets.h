#pragma once

#include <openssl/ssl.h>
#include <stdint.h>

enum SOCKET_TYPE {
	TtcSocketHTTP,
	TtcSocketSSL,
};

struct ttc_http_socket {
	uint32_t type;

	/*Ignore the SSL fields when
	 * not TtcSocketSSL
	 */
	SSL_CTX *ctx;
	SSL *ssl;

	int fd;
};
