#pragma once


#include <stdint.h>
#define TTC_HTTP_VER_MAJ 0
#define TTC_HTTP_VER_MIN 4
#define TTC_HTTP_VER_VENDOR "ttc"

#define TTC_HTTP_VER_STR TTC_HTTP_VER_MAJ # "." TTC_HTTP_VER_MIN # "_" TTC_HTTP_VER_VENDOR

#include <openssl/ssl.h>


#define TTC_HTTP_METHOD_GET "GET"
#define TTC_HTTP_METHOD_POST "POST"
#define TTC_HTTP_METHOD_DELETE "DELETE"
#define TTC_HTTP_METHOD_HEAD "HEAD"
#define TTC_HTTP_METHOD_PUT "PUT"
#define TTC_HTTP_METHOD_CONNECT "CONNECT"
#define TTC_HTTP_METHOD_OPTIONS "OPTIONS"
#define TTC_HTTP_METHOD_TRACE "TRACE"
#define TTC_HTTP_METHOD_PATCH "PATCH"

#define HTTP_VER_09 ""
#define HTTP_VER_10 "HTTP/1.0"
#define HTTP_VER_11 "HTTP/1.1"
#define HTTP_VER_2 "HTTP/2"
#define HTTP_VER_3 "HTTP/3"

typedef struct ttc_http_request ttc_http_request_t;
typedef struct ttc_http_response {
	uint16_t status;
	
	char *headers;
	char *data;
} ttc_http_response_t;

typedef int ttc_http_ret_t;

enum ttc_http_RET_CODES {
	TTC_HTTP_SUCCESS = 0,
	TTC_HTTP_MEMORY_ALLOC = 1,
};



ttc_http_request_t *ttc_http_new_request();
void ttc_http_request_set_method(ttc_http_request_t *request, char *method);
void ttc_http_request_set_path(ttc_http_request_t *request, char *path); 
ttc_http_ret_t ttc_http_request_add_header(ttc_http_request_t *request, const char *name, const char *value);
ttc_http_ret_t ttc_http_request_add_data(ttc_http_request_t *request, const char *data);
void ttc_http_request_set_http_version(ttc_http_request_t *request, char *http_ver);
char *ttc_http_request_get_str(ttc_http_request_t *request);
ttc_http_ret_t ttc_http_request_build(ttc_http_request_t *request);
void ttc_http_request_free(ttc_http_request_t *request);

/*0.5 additions*/
int ttc_http_request_send(ttc_http_request_t *request, int socketfd);
int ttc_https_request_send(ttc_http_request_t *request, SSL *ssl);
ttc_http_response_t *ttc_http_get_response(int fd);	
ttc_http_response_t *ttc_https_get_response(SSL *ssl);
void ttc_http_response_free(ttc_http_response_t *response);
	
