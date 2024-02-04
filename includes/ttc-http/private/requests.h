#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ttc-http/request.h>

typedef struct ttc_http_request_headers ttc_http_request_headers_t;

struct ttc_http_request_headers {
	char *value;
	char *name;

	ttc_http_request_headers_t *next;
};

struct ttc_http_request {
	int dirty;
	char *method;
	char *path;
	ttc_http_request_headers_t *headers;
	char *header_str;
	size_t hdr_count;

	char *http_version;
	char *data;

	char *req_str;
};
