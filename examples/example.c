#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#include "../ttc-http.h"

#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <unistd.h>


int main(int argc, char **argv) {
	ttc_http_request_t *request;
	struct addrinfo *info;
	int fd, res, len;
	SSL_CTX *ctx;
	SSL *ssl;
	char buf[2048];

	if(argc < 2) {
		printf("USAGE: ./ttc_http_example <DOMAIN_NAME>\n");
		return 1;
	}

	/*setup socket*/
	res = getaddrinfo(argv[1], "443", NULL, &info);
	if(res != 0) {
		printf("getaddrinfo: %s\n", gai_strerror(res));
		return 1;
	}

	fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if(fd < 0) {
		printf("socket: %m\n");
		freeaddrinfo(info);
		return 1;
	}

	res = connect(fd, info->ai_addr, (int)info->ai_addrlen);
	freeaddrinfo(info);
	if(res != 0) { 
		printf("connect: %m\n");
		close(fd);
		return 1;
	}

	/*setup SSL*/
	SSL_library_init();
	OpenSSL_add_all_algorithms();


	ctx = SSL_CTX_new(TLS_client_method());

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);

	SSL_connect(ssl);


	/*Request*/
	request = ttc_http_new_request();

	ttc_http_request_set_path(request, "/");
	ttc_http_request_set_method(request, "GET");
	ttc_http_request_set_http_version(request, "HTTP/1.0");
	
	res = ttc_http_request_add_header(request, "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0");
	if(res == TTC_HTTP_MEMORY_ALLOC) {
		printf("ttc_http_request_add_header: failed to allocate %m\n");
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		close(fd);
		ttc_http_request_free(request);
		return 1;
	}

	res = ttc_http_request_add_header(request, "Host", argv[1]);
	if(res == TTC_HTTP_MEMORY_ALLOC) {
		printf("ttc_http_request_add_header: failed to allocate %m\n");
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		close(fd);
		ttc_http_request_free(request);
		return 1;
	}

	
	res = ttc_http_request_build(request);
	if(res == TTC_HTTP_MEMORY_ALLOC) {
		printf("ttc_http_request_build: failed to allocate %m\n");
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		close(fd);
		ttc_http_request_free(request);
		return 1;
	}
	
	/*This string shouldn't be null now as we check the last result*/
	char *str = ttc_http_request_get_str(request);
	printf("REQUEST:\n%s", str);
	
	SSL_write(ssl, str, strlen(str));

	len = 0;
	while((len = SSL_read(ssl, buf, 2047)) > 0) {
		buf[len] = 0;
		printf("%s", buf);
	}

	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(fd);
	ttc_http_request_free(request);



	return 0;
}
