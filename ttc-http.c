#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <poll.h>
#include <sys/socket.h>

#include <openssl/ssl.h>

#include <ttc-log.h>
#include "./ttc-http.h"


struct ttc_http_request {
	const char *method;
	const char *path;
	char *headers;
	size_t hdr_len;

	const char *http_version;
	char *data;

	char *req_str;
};

ttc_http_request_t *ttc_http_new_request() {
	return calloc(1, sizeof(ttc_http_request_t));
}

void ttc_http_request_set_method(ttc_http_request_t *request, const char *method) {
	request->method = method; /*set the method*/
}

void ttc_http_request_set_path(ttc_http_request_t *request, const char *path) {
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

int ttc_https_parse_chunked_data(ttc_http_response_t *response, 
		char *encoding, SSL *ssl) {
	uint64_t size, length, useage, readout, total_size;
	char *data, outdata;

	response->data = NULL;
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
		TTC_LOG_ERROR("Encoding Type isn't recognize\n");
		return 1;
	}
	
	total_size = 0;
	size = 256;
	data = calloc(1, size);
	readout = 0;
	useage = 0;
	while(strncmp(data, "0\r\n", 3) != 0) {
		useage += SSL_read(ssl, &data[useage], 1);
		if(strstr(data, "\r\n")) {
			length = strtoull(data, NULL, 16);
			if(length == 0) break;
			total_size += length;
			void *tmp = realloc(response->data, total_size + 1);
			response->data = tmp;
			while(readout < total_size) {
				readout += SSL_read(ssl, &response->data[readout], total_size - readout);
			}
			response->data[readout] = 0;
			memset(data, 0, 256);
			int readin = SSL_read(ssl, data, 2);
			if(strncmp(data, "\r\n", 2) != 0) {
				TTC_LOG_ERROR("Chunk end is not equal to \\r\\n\n");
				return 1; /*Bail out bad chunk or we read it wrong*/
			}
			memset(data, 0, 256);
			useage = 0;
		}
	}
	SSL_read(ssl, data, 2);
	response->data[readout] = 0;
	free(data);	
	return 0;
}

int ttc_https_parse_content_length(ttc_http_response_t *response, 
		char *content_len, SSL *ssl) {
	uint64_t length, readout;
	while(isspace(*content_len)) {
		content_len++;
	}

	readout = 0;
	length = strtoull(content_len, NULL, 0);
	TTC_LOG_DEBUG("Length to read lu\n", length);
	response->data = calloc(1, length + 1);


	while(readout < length) {
		readout += SSL_read(ssl, response->data, length);
	}

	return 0;
}

int ttc_https_read_til_close(ttc_http_response_t *response, SSL *ssl) {
	return -1;
	/*TODO:*/	
}

int ttc_https_response_parse_headers(ttc_http_response_t *response, SSL *ssl) {
	char *headers = response->headers;

	char *status_code = strstr(headers, " ");
	response->status = strtoull(status_code, NULL, 10);
	
	char *encoding = strstr(headers, "Transfer-Encoding:");
	if(encoding) return ttc_https_parse_chunked_data(response, &encoding[18], ssl);

	char *content_len = strstr(headers, "Content-Length:");
	if(content_len) {
		TTC_LOG_WARN("Using Content Length\n");
		return ttc_https_parse_content_length(response, &content_len[15], ssl);
	}
	/*according to RFC for HTTP if content lenght or Transfer-Encoding are not
	 * speficed then the server should close our connection once it's 
	 * done talking to us.
	 */
	return ttc_https_read_til_close(response, ssl);
}

void ttc_http_response_free(ttc_http_response_t *response) {
	if(response->data) {
		free(response->data);
	}
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
		TTC_LOG_ERROR("We where unable to find the end of the headers despite\n"
				"\tpolling for the response is it a valie HTTP response?\n"
				"\tresponse we errored on:\n%s\n", data);

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

	free(data);
	return response;
}

ttc_http_response_t *ttc_https_get_response(SSL *ssl) {
	ttc_http_response_t *response;
	struct pollfd pfd;
	int fd, res;
	char *data, *header_end, transfer[257];
	size_t size, length;

	transfer[256] = 0;

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

	/*Check if FD can be read or if open SSL has bytes cached
	 * in the underlying BIO before exit */
	while(SSL_pending(ssl) || poll(&pfd, 1, -1)) {
		uint64_t readoff = 256;
		uint64_t actual_read = 0;
		void *tmp;
		
		actual_read = SSL_peek(ssl, transfer, readoff);
		if (actual_read <= 0 && SSL_get_error(ssl, 0) != SSL_ERROR_NONE) {
			TTC_LOG_ERROR("Failed to read server response.\n"
					"Socket was close unexpectly: errno = %d\n"
					"Data before free was: %s\n", SSL_get_error(ssl, 0), data);
			free(data);
			free(response);
			return NULL;
		}

		memcpy(&data[length], transfer, readoff);
		length += 256;
		data[length] = 0;

		if((tmp = strstr(data, "\r\n\r\n"))) {
			length -= 256;
			uint64_t rsize = (uint64_t)tmp - (uint64_t)data + 2;
			readoff = rsize - length + 2;
			data[rsize] = 0;
			int bytes = SSL_read(ssl, transfer, readoff);
			transfer[bytes] = 0;
			break;
		}

		tmp = realloc(data, size + 256 + 1);
		data = tmp;
		size += 256;

		SSL_read(ssl, transfer, readoff);
	}

	
	response->headers = data;

	ttc_https_response_parse_headers(response, ssl);

	return response;
}

ttc_http_ret_t ttc_http_request_add_header(ttc_http_request_t *request, const char *name, const char *value) {
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

ttc_http_ret_t ttc_http_request_add_data(ttc_http_request_t *request, const char *data) {
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

void ttc_http_request_set_http_version(ttc_http_request_t *request, const char *http_ver) {
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
