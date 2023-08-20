#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lchttp.h" 

struct lchttp_request {
	char *method;
	char *path;
	char *headers;
	size_t hdr_len;

	char *http_version;
	char *data;

	char *req_str;
};


lchttp_request_t *lchttp_new_request() {
	return calloc(1, sizeof(lchttp_request_t));
}

void lchttp_request_set_method(lchttp_request_t *request, char *method) {
	request->method = method; /*set the method*/
}

void lchttp_request_set_path(lchttp_request_t *request, char *path) {
	request->path = path;
}

lchttp_ret_t lchttp_request_add_header(lchttp_request_t *request, char *name, char *value) {
	char *header;
	char *tmp;
	int length; 

	length = snprintf(NULL, 0, "\r\n%s: %s", name, value);
	header = calloc(1, length+1);
	if(header == NULL) {
		return LCHTTP_MEMORY_ALLOC;
	}

	snprintf(header, length+1, "\r\n%s: %s", name, value);
	

	tmp = realloc(request->headers, request->hdr_len + length + 1);
	if(tmp == NULL) {
		free(header);
		return LCHTTP_MEMORY_ALLOC;
	}

	memset(&tmp[request->hdr_len], 0, length);
	request->hdr_len += strlen(header);
	request->headers = tmp;

	strcat(request->headers, header);

	free(header);

	return 0;
}

lchttp_ret_t lchttp_request_add_data(lchttp_request_t *request, char *data) {
	if(request->data) {
		free(request->data);
		request->data = NULL;
	}

	request->data = calloc(1, strlen(data) + 1);
	if(request->data == NULL) {
		return LCHTTP_MEMORY_ALLOC;
	}

	strcpy(request->data, data);
	return LCHTTP_SUCCESS;
}

void lchttp_request_set_http_version(lchttp_request_t *request, char *http_ver) {
	request->http_version = http_ver;
}

char *lchttp_request_get_str(lchttp_request_t *request) {
	return request->req_str;
}

lchttp_ret_t lchttp_request_build(lchttp_request_t *request) {
	int length;

	length = snprintf(NULL, 0, "%s %s %s%s\r\n\r\n%s",
			request->method, request->path, 
			request->http_version, request->headers ? request->headers : "", 
			request->data ? request->data : "");
	
	request->req_str = calloc(1, length + 1);
	if(request->req_str == NULL) {
		return LCHTTP_MEMORY_ALLOC;
	}

	snprintf(request->req_str, length + 1, "%s %s %s%s\r\n\r\n%s",
			request->method, request->path, 
			request->http_version, request->headers ? request->headers : "", 
			request->data ? request->data : "");
	
	return LCHTTP_SUCCESS;
}

void lchttp_request_free(lchttp_request_t *request) {
	if(request->headers) {
		free(request->headers);
	}
	
	if(request->data) {
		free(request->data); 
	}

	if(request->req_str) {
		free(request->req_str);
	}

	free(request);
}
