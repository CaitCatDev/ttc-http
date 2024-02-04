#include <stdio.h>
#include <string.h>
#include <ttc-http/private/requests.h>
#include <ttc-http/http.h>

#include <stdlib.h>

ttc_http_request_t *ttc_http_new_request() {
	ttc_http_request_t *request;

	request = calloc(1, sizeof(ttc_http_request_t));
	if(request == NULL) {
		return NULL;
	}

	return request;
}

int ttc_http_request_set_method(ttc_http_request_t *request, const char *method) {
	int result = TTC_HTTP_FN_FAILED;
	char *tmp;

	if(!request) {
		return result;
	}

	tmp = strdup(method);

	if(tmp) {
		if(request->method) {
			free(request->method);
		}
		request->method = tmp;
		request->dirty = 1;
		result = TTC_HTTP_FN_SUCCESS;
	}

	return result;
}

int ttc_http_request_set_path(ttc_http_request_t *request, const char *path) {
	int result = TTC_HTTP_FN_FAILED;
	char *tmp;

	if(!request) {
		return result;
	}

	tmp = strdup(path);

	if(tmp) {
		if(request->path) {
			free(request->path);
		}
		request->path = tmp;
		request->dirty = 1;
		result = TTC_HTTP_FN_SUCCESS;
	}

	return result;
}

int ttc_http_request_set_http_version(ttc_http_request_t *request, const char *http_ver) {
	int result = TTC_HTTP_FN_FAILED;
	char *tmp;

	if(!result) {
		return result;
	}

	tmp = strdup(http_ver);

	if(tmp) {
		if(request->http_version) {
			free(request->http_version);
		}
		request->http_version = tmp;
		request->dirty = 1;
		result = TTC_HTTP_FN_SUCCESS;
	}

	return result;
}

static void ttc_http_header_insert(ttc_http_request_headers_t **list, ttc_http_request_headers_t *header) {
	ttc_http_request_headers_t *tmp;
	if(*list == NULL) {
		*list = header;
		return;
	}

	for(tmp = *list; tmp; tmp = tmp->next) {
		if(tmp->next == NULL) {
			tmp->next = header;
			return;
		}
	}
}

static void ttc_http_header_free(ttc_http_request_headers_t *header) {
	if(!header) {
		return;
	}

	if(header->name) {
		free(header->name);
	}

	if(header->value) {
		free(header->value);
	}

	free(header);
}

static void ttc_http_header_free_list(ttc_http_request_headers_t *headers) {
	ttc_http_request_headers_t *tmp, *next;

	if(!headers) {
		return;
	}

	for(tmp = headers; tmp; tmp = next) {
		next = tmp->next;
		ttc_http_header_free(tmp);
	}
}

int ttc_http_request_add_header(ttc_http_request_t *request, const char *name, const char *value) {
	ttc_http_request_headers_t *header;
	if(!request) {
		return TTC_HTTP_FN_FAILED;
	}

	header = calloc(1, sizeof(ttc_http_request_headers_t));
	if(header == NULL) {
		return TTC_HTTP_FN_FAILED;
	}

	header->name = strdup(name);
	if(header->name == NULL) {
		free(header);
		return TTC_HTTP_FN_FAILED;
	}

	header->value = strdup(value);
	if(header->value == NULL) {
		free(header->name);
		free(header);
		return TTC_HTTP_FN_FAILED;
	}

	ttc_http_header_insert(&request->headers, header);
	printf("Added Header: %s %s\n", header->name, header->value);
	request->hdr_count++;
	request->dirty = 1;

	return TTC_HTTP_FN_SUCCESS;
}

void ttc_http_request_del_header(ttc_http_request_t *request, const char *name) {
	ttc_http_request_headers_t *tmp, *prev;

	for(tmp = request->headers; tmp; tmp = tmp->next) {
		if(strncmp(tmp->name, name, strlen(name)) == 0) {
			prev->next = tmp->next;
			ttc_http_header_free(tmp);
			return;
		}
		prev = tmp;
	}
}

int ttc_http_request_set_data(ttc_http_request_t *request, const char *data) {
	int result = TTC_HTTP_FN_FAILED;
	void *tmp = NULL;
	if(!request) {
		return result;
	}

	tmp = calloc(1, strlen(data) + 1);
	if(!tmp) {
		return result;
	}

	if(request->data) {
		free(request->data);
	}

	request->data = tmp;
	strcpy(request->data, data);
	request->dirty = 1;
	result = TTC_HTTP_FN_SUCCESS;


	return result;
}

int ttc_http_request_build(ttc_http_request_t *request) {
	ttc_http_request_headers_t *tmp;
	int length, prev;
	char *holder;

	if(!request) {
		TTC_HTTP_FN_FAILED;
	}

	/*We rebuilding*/
	if(request->req_str) {
		if(!request->dirty) {
			/*Skip rebuild if nothing changed*/
		}
		free(request->header_str);
		request->header_str = NULL;
	}

	length = snprintf(NULL, 0, "%s %s %s",//%s\r\n\r\n%s",
			request->method, request->path,
			request->http_version);

	request->req_str = calloc(1, length + 1);
	if(request->req_str == NULL) {
		return TTC_HTTP_FN_FAILED;
	}

	snprintf(request->req_str, length + 1, "%s %s %s", //%s\r\n\r\n%s",
			request->method, request->path,
			request->http_version);

	prev = length;
	printf("Headers: %p\n", request->headers);
	for(tmp = request->headers; tmp; tmp = tmp->next) {
		length = snprintf(NULL, 0, "\r\n%s: %s", tmp->name, tmp->value);

		holder = realloc(request->req_str, prev + length + 1);
		if(!holder) {
			free(request->req_str);
			request->req_str = NULL;
			return TTC_HTTP_FN_FAILED;
		}
		request->req_str = holder;

		snprintf(&request->req_str[prev], length + 1,"\r\n%s: %s", tmp->name, tmp->value);
		prev += length;
	}

	length = snprintf(NULL, 0, "\r\n\r\n%s", request->data ? request->data : "");

	holder = realloc(request->req_str, prev + length + 1);
	if(!holder) {
		free(request->req_str);
		request->req_str = NULL;
		return TTC_HTTP_FN_FAILED;
	}
	request->req_str = holder;
	length = snprintf(&request->req_str[prev], length + 1, "\r\n\r\n%s", request->data ? request->data : "");

	return TTC_HTTP_FN_SUCCESS;
}

void ttc_http_request_free(ttc_http_request_t *request) {
	if(!request) {
		return;
	}

	ttc_http_header_free_list(request->headers);

	if(request->data) {
		free(request->data);
	}

	if(request->req_str) {
		free(request->req_str);
	}

	if(request->http_version) {
		free(request->http_version);
	}

	if(request->method) {
		free(request->method);
	}

	if(request->path) {
		free(request->path);
	}

	free(request);
}
