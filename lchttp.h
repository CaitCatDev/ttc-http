#pragma once
#include <openssl/ssl.h>

typedef struct lchttp_request lchttp_request_t;
typedef struct lchttp_response lchttp_response_t;

typedef int lchttp_ret_t;

enum lchttp_RET_CODES {
	LCHTTP_SUCCESS = 0,
	LCHTTP_MEMORY_ALLOC = 1,
};


lchttp_request_t *lchttp_new_request();
void lchttp_request_set_method(lchttp_request_t *request, char *method);
void lchttp_request_set_path(lchttp_request_t *request, char *path); 
lchttp_ret_t lchttp_request_add_header(lchttp_request_t *request, char *name, char *value);
lchttp_ret_t lchttp_request_add_data(lchttp_request_t *request, char *data);
void lchttp_request_set_http_version(lchttp_request_t *request, char *http_ver);
char *lchttp_request_get_str(lchttp_request_t *request);
lchttp_ret_t lchttp_request_build(lchttp_request_t *request);
void lchttp_request_free(lchttp_request_t *request);
