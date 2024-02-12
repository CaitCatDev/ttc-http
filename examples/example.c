#include "ttc-http/sockets.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#include <netdb.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <ttc-log.h>
#include <unistd.h>

#include <ttc-http/http.h>
#include <ttc-http/request.h>
#include <ttc-http/response.h>

SSL_CTX *ssl_init() {
	SSL_library_init();

	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	SSL_load_error_strings();

	return SSL_CTX_new(TLS_client_method());
}

int main(int argc, char **argv) {
	ttc_http_request_t *request;
	ttc_http_response_t *response;
	ttc_http_socket_t *sock;
	int fd, res, len;
	SSL_CTX *ctx;
	SSL *ssl;
	char buf[2048];

	if (argc < 2) {
		printf("USAGE: ./ttc_http_example <DOMAIN_NAME>\n");
		return 1;
	}
	ttc_log_init_from_file(stderr);
	ctx = ssl_init();

	sock = ttc_http_new_socket(argv[1], "443", ctx);
	if (!sock) {
		SSL_CTX_free(ctx);
		return 1;
	}

	/*Request*/
	request = ttc_http_new_request();

	ttc_http_request_set_path(request, "/");
	ttc_http_request_set_method(request, "GET");
	ttc_http_request_set_http_version(request, "HTTP/1.1");

	res = ttc_http_request_add_header(
			request, "User-Agent",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0");
	if (res == TTC_HTTP_FN_FAILED) {
		printf("ttc_http_request_add_header: failed to allocate %m\n");
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		close(fd);
		ttc_http_request_free(request);
		return 1;
	}

	res = ttc_http_request_add_header(request, "Host", argv[1]);
	if (res == TTC_HTTP_FN_FAILED) {
		printf("ttc_http_request_add_header: failed to allocate %m\n");
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		close(fd);
		ttc_http_request_free(request);
		return 1;
	}

	res = ttc_http_socket_send_request(sock, request);
	response = ttc_http_get_response(sock);

	printf("%s\n", response->data);

	ttc_http_socket_free(sock);
	ttc_http_request_free(request);
	ttc_http_response_free(response);
	SSL_CTX_free(ctx);

	return 0;
}
