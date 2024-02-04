#pragma once

#include <ttc-http/sockets.h>

#include <stdint.h>


typedef struct ttc_http_request ttc_http_request_t;
typedef struct ttc_http_response {
	uint16_t status;

	char *headers;
	char *data;
} ttc_http_response_t;

void ttc_http_response_free(ttc_http_response_t *response);
ttc_http_response_t *ttc_http_get_response(ttc_http_socket_t *sock);
