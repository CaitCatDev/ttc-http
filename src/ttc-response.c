#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <ctype.h>

#include <openssl/ssl.h>

#include <ttc-log.h>
#include <ttc-http/response.h>
#include <ttc-http/sockets.h>

void ttc_http_response_free(ttc_http_response_t *response) {
	if(!response) {
		return;
	}

	if(response->headers) {
		free(response->headers);
	}

	if(response->data) {
		free(response->data);
	}

	free(response);
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
		char *encoding, ttc_http_socket_t *sock) {
	uint64_t size, length, useage, readout, total_size, hold;
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
		hold = 0;
		ttc_http_socket_read(sock, &data[useage], 1, &hold);
		useage += hold;
		if(strstr(data, "\r\n")) {
			length = strtoull(data, NULL, 16);
			if(length == 0) break;
			total_size += length;
			void *tmp = realloc(response->data, total_size + 1);
			response->data = tmp;
			while(readout < total_size) {
				ttc_http_socket_read(sock, &response->data[readout], total_size - readout, &hold);
				readout += hold;
			}
			response->data[readout] = 0;
			ttc_http_socket_read(sock, data, 2, &hold);
			if(strncmp(data, "\r\n", 2) != 0) {
				TTC_LOG_ERROR("Chunk end is not equal to \\r\\n\n");
				return 1; /*Bail out bad chunk or we read it wrong*/
			}
			memset(data, 0, 256);
			useage = 0;
		}
	}

	ttc_http_socket_read(sock, data, 2, &hold);
	response->data[readout] = 0;
	free(data);
	return 0;
}

int ttc_https_parse_content_length(ttc_http_response_t *response,
		char *content_len, ttc_http_socket_t *sock) {
	uint64_t length, readout;
	while(isspace(*content_len)) {
		content_len++;
	}
	readout = 0;
	length = strtoull(content_len, NULL, 0);
	response->data = calloc(1, length + 1);


	while(length) {
		readout = 0;
		ttc_http_socket_read(sock, response->data, length, &readout);
		length -= readout;
	}

	return 0;
}

int ttc_https_read_til_close(ttc_http_response_t *response, ttc_http_socket_t *sock) {
	return -1;
	/*TODO:*/
}


int ttc_https_response_parse_headers(ttc_http_response_t *response, ttc_http_socket_t *sock) {
	char *headers = response->headers;

	char *status_code = strstr(headers, " ");
	response->status = strtoull(status_code, NULL, 10);

	char *encoding = strstr(headers, "Transfer-Encoding:");
	if(encoding) return ttc_https_parse_chunked_data(response, &encoding[18], sock);

	char *content_len = strstr(headers, "Content-Length:");
	if(content_len) {
		TTC_LOG_WARN("Using Content Length\n");
		return ttc_https_parse_content_length(response, &content_len[15], sock);
	}
	/*according to RFC for HTTP if content lenght or Transfer-Encoding are not
	 * speficed then the server should close our connection once it's
	 * done talking to us.
	 */
	return ttc_https_read_til_close(response, sock);
}

ttc_http_response_t *ttc_http_get_response(ttc_http_socket_t *sock) {
	ttc_http_response_t *response, local;
	int res;
	short revents = 0;
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

	/*Check if FD can be read or if open SSL has bytes cached
	 * in the underlying BIO before exit */

	while(ttc_http_socket_poll(sock, POLLIN, &revents)) {
		uint64_t readoff = 256;
		uint64_t actual_read = 0;
		void *tmp;

		if(revents & POLLHUP) {
			TTC_LOG_ERROR("Socket was close unexpectly\n");
		}

		res = ttc_http_socket_peek(sock, transfer, readoff, &actual_read);
		if (res == 0) {
			TTC_LOG_ERROR("Failed to read server response.\n"
					"Socket was close unexpectly: \n"
					"Data before free was: %s\n", data);
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
			res = ttc_http_socket_read(sock, transfer, readoff, &actual_read);
			transfer[actual_read] = 0;
			break;
		}

		tmp = realloc(data, size + 256 + 1);
		data = tmp;
		size += 256;

		ttc_http_socket_read(sock, transfer, readoff, &actual_read);
	}


	response->headers = data;
	ttc_https_response_parse_headers(response, sock);

	return response;
}
