#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <poll.h>
#include <sys/socket.h>

#include <openssl/ssl.h>

#include "./ttc-http.h"


struct ttc_http_request {
	char *method;
	char *path;
	char *headers;
	size_t hdr_len;

	char *http_version;
	char *data;

	char *req_str;
};

ttc_http_request_t *ttc_http_new_request() {
	return calloc(1, sizeof(ttc_http_request_t));
}

void ttc_http_request_set_method(ttc_http_request_t *request, char *method) {
	request->method = method; /*set the method*/
}

void ttc_http_request_set_path(ttc_http_request_t *request, char *path) {
	request->path = path;
}

int ttc_http_request_send(ttc_http_request_t *request, int socketfd) {
	if(!request->req_str) {
		return -1;
	}

	return send(socketfd, request->req_str, strlen(request->req_str), 0);
}

int ttc_https_request_send(ttc_http_request_t *request, SSL *ssl) {
	if(!request->req_str) {
		return -1;
	}
	return SSL_write(ssl, request->req_str, strlen(request->req_str));
}

int ttc_http_chunked_to_unchunk(ttc_http_response_t *response) {
	uint64_t size, overall, ind;
	char *parsed_data = NULL, *tmp;
	char *data = response->data;
	overall = 0;

	while((size = strtoull(data, NULL, 16))) {
		data = strstr(data, "\r\n");
		data += 2;
		tmp = realloc(parsed_data, overall + size + 1);
		parsed_data = tmp;
		for(ind = 0; ind < size; ind++) {
			parsed_data[overall + ind] = data[ind];
		}

		data += size;
		overall += size;
	}
	parsed_data[overall] = 0;
	free(response->data);
	response->data = parsed_data;
	return 0;
}

int ttc_http_response_parse_headers(ttc_http_response_t *response) {
	char *headers = response->headers;

	char *status_code = strstr(headers, " ");
	response->status = strtoull(status_code, NULL, 10);
	
	char *encoding = strstr(headers, "Transfer-Encoding:");
	if(!encoding) return 0;

	encoding = &encoding[18];
	/*according to RFC https://www.rfc-editor.org/rfc/rfc2616#section-4.2
	 * Headers values can be precceded with white space though a single 
	 * space is preferred meaning in theroy there could be one space
	 * or there could be 20 so strip all the white space off
	 */
	while(isspace(*encoding)) {
		encoding++;
	}
	
	/*TODO: Parse other types of encoding*/
	if(strncmp(encoding, "chunked\r\n", 9) != 0) {
		printf("Encoding Type isn't recognize\n");
		return 1;
	}

	return ttc_http_chunked_to_unchunk(response);
}

void ttc_http_response_free(ttc_http_response_t *response) {
	free(response->data);
	free(response->headers);
	free(response);
}

ttc_http_response_t *ttc_http_get_response(int fd) {
	ttc_http_response_t *response;
	struct pollfd pfd;

	char *data, *header_end;
	size_t size;
	size_t length; 

	response = calloc(1, sizeof(*response));
	if(!response) {
		return NULL;
	}

	data = calloc(1, 256 + 1);
	if(!data) {
		free(response);
		return NULL;
	}

	length = 0;
	size = 256;


	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	while((fd = poll(&pfd, 1, 1000))) {
		length += recv(fd, &data[length], size -  length, 0);
		if(length >= size) {
			void *tmp = realloc(data, size + 256 + 1);
			if(!tmp) {
				free(data);
				free(response);
				return NULL;
			}
			data = tmp;
			size += 256;
		}
	}
	/*Make data a valid Cstring*/
	data[length] = 0;
	size_t header_size;
	header_end = strstr(data, "\r\n\r\n");
	if(!header_end) {
		/*Header End not found*/
		printf("We where unable to find the end of the headers despite\n"
				"polling for the response is it a valie HTTP response?\n"
				"response we errored on:\n%s\n", data);

		free(response);
		free(data);
		return NULL;
	}

	/*Sizes of the headers + 2 for last new line*/
	header_size = header_end - data + 2;
	
	response->data = strdup(&header_end[4]);
	if(!response->data) {
		free(response);
		free(data);
		return NULL;
	}

	response->headers = strndup(data, header_size + 2);
	if(!response->headers) {
		free(response->data);
		free(response);
		free(data);
		return NULL;
	}

	ttc_http_response_parse_headers(response);

	free(data);
	return response;
}

ttc_http_response_t *ttc_https_get_response(SSL *ssl) {
	ttc_http_response_t *response;
	struct pollfd pfd;
	int fd;

	char *data, *header_end;
	size_t size;
	size_t length; 

	response = calloc(1, sizeof(*response));
	if(!response) {
		return NULL;
	}

	data = calloc(1, 256 + 1);
	if(!data) {
		free(response);
		return NULL;
	}

	length = 0;
	size = 256;

	fd = SSL_get_fd(ssl);

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	while((fd = poll(&pfd, 1, 1000))) {
		length += SSL_read(ssl, &data[length], size -  length);
		if(length >= size) {
			void *tmp = realloc(data, size + 256 + 1);
			if(!tmp) {
				free(data);
				free(response);
				return NULL;
			}
			data = tmp;
			size += 256;
		}
	}
	/*Make data a valid Cstring*/
	data[length] = 0;
	size_t header_size;
	header_end = strstr(data, "\r\n\r\n");
	if(!header_end) {
		/*Header End not found*/
		printf("We where unable to find the end of the headers despite\n"
				"polling for the response is it a valie HTTP response?\n"
				"response we errored on:\n%s\n", data);

		free(response);
		free(data);
		return NULL;
	}

	/*Sizes of the headers + 2 for last new line*/
	header_size = header_end - data + 2;
	
	response->data = strdup(&header_end[4]);
	if(!response->data) {
		free(response);
		free(data);
		return NULL;
	}

	response->headers = strndup(data, header_size + 2);
	if(!response->headers) {
		free(response->data);
		free(response);
		free(data);
		return NULL;
	}

	ttc_http_response_parse_headers(response);

	free(data);
	return response;
}

ttc_http_ret_t ttc_http_request_add_header(ttc_http_request_t *request, char *name, char *value) {
	char *header;
	char *tmp;
	int length; 

	length = snprintf(NULL, 0, "\r\n%s: %s", name, value);
	header = calloc(1, length+1);
	if(header == NULL) {
		return TTC_HTTP_MEMORY_ALLOC;
	}

	snprintf(header, length+1, "\r\n%s: %s", name, value);
	

	tmp = realloc(request->headers, request->hdr_len + length + 1);
	if(tmp == NULL) {
		free(header);
		return TTC_HTTP_MEMORY_ALLOC;
	}

	memset(&tmp[request->hdr_len], 0, length);
	request->hdr_len += strlen(header);
	request->headers = tmp;

	strcat(request->headers, header);

	free(header);

	return 0;
}

ttc_http_ret_t ttc_http_request_add_data(ttc_http_request_t *request, char *data) {
	if(request->data) {
		free(request->data);
		request->data = NULL;
	}

	request->data = calloc(1, strlen(data) + 1);
	if(request->data == NULL) {
		return TTC_HTTP_MEMORY_ALLOC;
	}

	strcpy(request->data, data);
	return TTC_HTTP_SUCCESS;
}

void ttc_http_request_set_http_version(ttc_http_request_t *request, char *http_ver) {
	request->http_version = http_ver;
}

char *ttc_http_request_get_str(ttc_http_request_t *request) {
	return request->req_str;
}

ttc_http_ret_t ttc_http_request_build(ttc_http_request_t *request) {
	int length;

	length = snprintf(NULL, 0, "%s %s %s%s\r\n\r\n%s",
			request->method, request->path, 
			request->http_version, request->headers ? request->headers : "", 
			request->data ? request->data : "");
	
	request->req_str = calloc(1, length + 1);
	if(request->req_str == NULL) {
		return TTC_HTTP_MEMORY_ALLOC;
	}

	snprintf(request->req_str, length + 1, "%s %s %s%s\r\n\r\n%s",
			request->method, request->path, 
			request->http_version, request->headers ? request->headers : "", 
			request->data ? request->data : "");
	
	return TTC_HTTP_SUCCESS;
}

void ttc_http_request_free(ttc_http_request_t *request) {
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
