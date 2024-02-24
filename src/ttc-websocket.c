#include <ttc-http/request.h>
#include <ttc-http/response.h>
#include <ttc-http/sockets.h>
#include <ttc-http/websockets.h>

#include <errno.h>
#include <unistd.h>

#include <pthread.h>
#include <ttc-log.h>

struct ttc_ws {
	pthread_mutex_t rlock, wlock;

	ttc_http_socket_t *sock;

	bool closed;
	uint16_t close_code;
};

/*this may read a little confusing but on LE machines
 * bitfields start at bit 0. So len: 7 for example is saying
 * bits 0-6 for 7 bit long field. Then mask: 1 as mask is the
 * 8th bit on that uint8_t;
 *
 * however on BIG endian machines bit 0 typically is the MSB
 * meaning that len: 7 would be same as saying bits 7-1
 * with mask being equal to bit position 0. Which would make
 * the data unrecognizeable once sent to another machine
 */
typedef struct ttc_ws_frame {
#if BYTE_ORDER == LITTLE_ENDIAN

	uint8_t opcode : 4; /*opcode*/
	uint8_t res : 3;    /*3 bit reserve/extension field*/
	uint8_t fin : 1;    /*1 bit final marker*/
	uint8_t len : 7;    /*length*/
	uint8_t mask : 1;   /*Data is masked?*/

#elif BYTE_ORDER == BIG_ENDIAN

	uint8_t fin : 1;
	uint8_t res : 3;
	uint8_t opcode : 4;
	uint8_t mask : 1;
	uint8_t len : 7;

#endif
	uint8_t extdata[];
} __attribute__((packed)) ttc_ws_frame_t;

/*byteN refers to that byte position in a multi byte number
 * going left to right
 * E.G. 0x1020
 * 0x10 would be byte 0
 * 0x20 would be byte 1
 */
uint16_t ttc_ws_endian_swap16(uint16_t innum) {
	uint16_t byte0, byte1;
	uint16_t ret;

	byte0 = innum >> 8;
	byte1 = innum & 0xff;

	ret = byte0 | (byte1 << 8);

	return ret;
}

uint32_t ttc_ws_endian_swap32(uint32_t innum) {
	uint32_t hbyte, lbyte, lmid_byte, hmid_byte;
	uint32_t ret;

	hbyte = (innum >> 24) & 0xff;
	hmid_byte = (innum >> 16) & 0xff;
	lmid_byte = (innum >> 8) & 0xff;
	lbyte = (innum) &0xff;

	ret = hbyte | (hmid_byte << 8) | (lmid_byte << 16) | lbyte << 24;

	return ret;
}

uint64_t ttc_ws_endian_swap64(uint64_t innum) {
	uint64_t byte0, byte1, byte2, byte3, byte4, byte5, byte6, byte7;
	uint64_t ret;

	byte0 = (innum >> 56) & 0xff;
	byte1 = (innum >> 48) & 0xff;
	byte2 = (innum >> 40) & 0xff;
	byte3 = (innum >> 32) & 0xff;
	byte4 = (innum >> 24) & 0xff;
	byte5 = (innum >> 16) & 0xff;
	byte6 = (innum >> 8) & 0xff;
	byte7 = innum & 0xff;

	ret = byte0 | byte1 << 8 | byte2 << 16 | byte3 << 24 | byte4 << 32 | byte5 << 40 | byte6 << 48 |
				byte7 << 56;

	return ret;
}

/*Mask our data to mee with the WS RFC format for clients*/
static char *ttc_ws_mask_data(uint8_t *mask_key, char *data, size_t length) {
	char *output = calloc(1, length);

	for (size_t ind = 0; ind < length; ++ind) {
		output[ind] = data[ind] ^ mask_key[ind % 4];
	}

	return output;
}

static uint8_t *ttc_random_array(size_t len) {
	size_t index;
	uint8_t *output;

	/*Sanity check the users input*/
	if (len == 0) {
		TTC_LOG_WARN("Invalid parameter passed in\n");
		return NULL;
	}

	output = calloc(sizeof(uint8_t), len);
	if (output == NULL) {
		TTC_LOG_ERROR("calloc failed %s\n", strerror(errno));
		return NULL;
	}

	srand(time(NULL));

	for (index = 0; index < len; ++index) {
		output[index] = ((uint8_t) rand() % 0xff);
	}

	return output;
}

static const char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t ttc_ws_b64_encode_len(size_t lenin) {
	size_t lenout = lenin;

	/*Make number cleanly divisible by 3 if it is not already*/
	if (lenout % 3) {
		lenout -= (lenout % 3);
		lenout += 3;
	}

	lenout /= 3; /*3 bytes is 24bits length in to number of blocks*/
	lenout *= 4; /*get actual byte length of output*/

	return lenout;
}

static char *ttc_ws_b64_encode(const uint8_t *data, size_t len) {
	size_t index, outindex, outlen;
	uint32_t block;
	char *outstr;

	if (!data || !len) {
		errno = -EINVAL;
		TTC_LOG_WARN("%s: Invlaid input\n");
		return NULL;
	}

	outlen = ttc_ws_b64_encode_len(len);       /*calc length needed*/
	outstr = calloc(sizeof(char), outlen + 1); /*allocate length +1*/

	if (outstr == NULL) {
		TTC_LOG_ERROR("%s: calloc error %s\n", strerror(errno));
		return NULL;
	}

	for (index = 0, outindex = 0; index < len; index += 3, outindex += 4) {
		/*construct a 24-bit int*/
		block = data[index];
		block = index + 1 < len ? block << 8 | data[index + 1] : block << 8;
		block = index + 2 < len ? block << 8 | data[index + 2] : block << 8;

		/*output the first two characters*/
		outstr[outindex] = b64table[(block >> 18) & 0x3F];
		outstr[outindex + 1] = b64table[(block >> 12) & 0x3f];

		/*Either set the next two characters or pad them if there are none*/
		outstr[outindex + 2] = index + 1 < len ? b64table[(block >> 6) & 0x3F] : '=';
		outstr[outindex + 3] = index + 2 < len ? b64table[block & 0x3F] : '=';
	}

	return outstr;
}

void ttc_ws_free(ttc_ws_t *ws) {
	if (ws) {
		pthread_mutex_destroy(&ws->wlock);
		pthread_mutex_destroy(&ws->rlock);

		/*Free the underlying connection*/
		ttc_http_socket_free(ws->sock);

		free(ws);
	}
}

void ttc_ws_buffer_free(ttc_ws_buffer_t *buf) {
	if (buf) {
		if (buf->data) {
			free(buf->data);
		}
		free(buf);
	}
}

ttc_ws_buffer_t *ttc_ws_read(ttc_ws_t *ws) {
	ttc_ws_buffer_t buffer = {0};
	uint8_t opcode, len;
	uint16_t len16;
	uint64_t len64, tmp, readin;

	if (ws == NULL) {
		TTC_LOG_ERROR("WS is NULL");
		return NULL;
	}

	if (ws->closed) {
		TTC_LOG_WARN("WS is closed\n");
		return NULL;
	}

	pthread_mutex_lock(&ws->rlock);

	ttc_http_socket_read(ws->sock, &opcode, 1, &readin);
	ttc_http_socket_read(ws->sock, &len, 1, &readin);

	buffer.fin = opcode & TTC_WS_FRAME_FINAL;
	buffer.opcode = opcode & 0x7f;

	len = len & 0x7f;
	if (len == 126) {
		ttc_http_socket_read(ws->sock, &len16, 2, &readin);
#if BYTE_ORDER == LITTLE_ENDIAN
		len16 = ttc_ws_endian_swap16(len16);
#endif
		buffer.len = len16;
	} else if (len == 127) {
		ttc_http_socket_read(ws->sock, &len16, 8, &readin);
#if BYTE_ORDER == LITTLE_ENDIAN
		len64 = ttc_ws_endian_swap64(len64);
#endif
		buffer.len = len64;
	} else {
		buffer.len = len;
	}

	if (buffer.opcode == TTC_WS_CONN_CLOSE_FRAME) {
		ws->closed = 1;
	}

	buffer.data = calloc(1, buffer.len + 1);
	if (!buffer.data) {
		TTC_LOG_ERROR("Allocation error\n");
		return NULL;
	}

	readin = 0;
	buffer.data[buffer.len] = 0;

	while (readin < buffer.len) {
		ttc_http_socket_read(ws->sock, &buffer.data[readin], buffer.len, &tmp);
		readin += tmp;
	}

	pthread_mutex_unlock(&ws->rlock);

	if (buffer.opcode == TTC_WS_CONN_CLOSE_FRAME) {
		ws->closed = 1;
		buffer.close_code = ttc_ws_endian_swap16(*((uint16_t *) buffer.data));
	}

	ttc_ws_buffer_t *buffer_heap = calloc(1, sizeof(ttc_ws_buffer_t));
	if (!buffer_heap) {
		TTC_LOG_ERROR("TTC_WS_ERROR: allocation error\n");
		free(buffer.data);
		return NULL;
	}
	memcpy(buffer_heap, &buffer, sizeof(ttc_ws_buffer_t));

	return buffer_heap;
}

int ttc_ws_write(ttc_ws_t *ws, ttc_ws_wrreq_t req) {
	ttc_ws_frame_t *frame;
	size_t len_needed;
	uint8_t *array_mask;
	char *masked_data;
	int ext_pos;

	if (ws->closed) {
		TTC_LOG_WARN("WS is closed\n");
		return 1;
	}

	ext_pos = 0;
	len_needed = sizeof(*frame);
	len_needed += req.len > 125 && req.len < UINT16_MAX ? 2 : 0;
	len_needed += req.len > UINT16_MAX ? 8 : 0;
	len_needed += req.mask ? 4 : 0;

	frame = calloc(1, len_needed + 1);
	if (!frame) {
		TTC_LOG_ERROR("Allocation Error\n");
		return 1;
	}

	if (req.len > 125 && req.len < UINT16_MAX) {
		frame->len = 126;
		frame->extdata[ext_pos++] = (req.len >> 8) & 0xff;
		frame->extdata[ext_pos++] = (req.len) & 0xff;
	} else if (req.len > UINT16_MAX) {
		frame->len = 127;
	} else {
		frame->len = req.len;
	}

	/*Mask the input data if mask is set(Client)*/
	if (req.mask) {

		/*generate a random data mask*/
		array_mask = ttc_random_array(4);

		masked_data = ttc_ws_mask_data(array_mask, req.data, req.len);

		frame->extdata[ext_pos++] = array_mask[0];
		frame->extdata[ext_pos++] = array_mask[1];
		frame->extdata[ext_pos++] = array_mask[2];
		frame->extdata[ext_pos++] = array_mask[3];
		free(array_mask);
	} else { /*else on the server don't mask at all*/
		array_mask = NULL;
		masked_data = req.data;
	}

	frame->fin = req.fin;
	frame->opcode = req.opcode;
	frame->res = req.res;
	frame->mask = req.mask;

	pthread_mutex_lock(&ws->wlock);
	ttc_http_socket_send_data(ws->sock, frame, len_needed);
	ttc_http_socket_send_data(ws->sock, masked_data, req.len);
	pthread_mutex_unlock(&ws->wlock);

	if (req.mask) {
		free(masked_data);
	}
	free(frame);

	return 0;
}

ttc_ws_t *ttc_ws_create_from_host(const char *host, const char *port, SSL_CTX *ctx) {
	ttc_http_socket_t *sock;
	ttc_http_request_t *request;
	ttc_http_response_t *response;
	ttc_ws_t *ws_out;
	uint8_t *ws_key_raw;
	char *b64key, *endpoint;
	int length, readout;

	/*Create new websocket*/
	sock = ttc_http_new_socket(host, port, ctx);
	if (!sock) {
		TTC_LOG_ERROR("Failed to allocate WS socket\n");
		return NULL;
	}

	ws_out = calloc(1, sizeof(ttc_ws_t));

	if (!ws_out) {
		TTC_LOG_ERROR("Allocation Error\n");
		return NULL;
	}

	ws_out->sock = sock;

	pthread_mutex_init(&ws_out->wlock, NULL);
	pthread_mutex_init(&ws_out->rlock, NULL);

	ws_key_raw = ttc_random_array(16);
	if (!ws_key_raw) {
		TTC_LOG_ERROR("Allocation Error\n");
		free(ws_out);
		return NULL;
	}

	b64key = ttc_ws_b64_encode(ws_key_raw, 16);
	if (!b64key) {
		TTC_LOG_ERROR("Allocation Error\n");
		free(ws_key_raw);
		free(ws_out);
		return NULL;
	}

	request = ttc_http_new_request();
	ttc_http_request_set_method(request, TTC_HTTP_METHOD_GET);
	ttc_http_request_set_http_version(request, HTTP_VER_11);
	ttc_http_request_add_header(request, "Sec-WebSocket-Key", b64key);
	ttc_http_request_add_header(request, "Sec-WebSocket-Version", "13");
	ttc_http_request_add_header(request, "Host", host);
	ttc_http_request_add_header(request, "Upgrade", "websocket");
	ttc_http_request_add_header(request, "Connection", "Upgrade");

	length = snprintf(NULL, 0, "%s://%s", ctx ? "wss" : "ws", host);

	endpoint = calloc(1, length + 1);
	if (!endpoint) {
		TTC_LOG_ERROR("Allocation Error\n");
		ttc_http_socket_free(ws_out->sock);
		free(b64key);
		free(ws_key_raw);
		free(ws_out);
		return NULL;
	}

	length = snprintf(endpoint, length + 1, "%s://%s", ctx ? "wss" : "ws", host);

	ttc_http_request_set_path(request, endpoint);

	ttc_http_socket_send_request(ws_out->sock, request);

	response = ttc_http_get_response(ws_out->sock);
	if (response->status != 101) {
		TTC_LOG_ERROR("websocket request responded with invalid status code %d\n", response->status);
		free(ws_out);
		ws_out = NULL;
	}

	ttc_http_request_free(request);
	ttc_http_response_free(response);
	free(b64key);
	free(ws_key_raw);
	free(endpoint);

	return ws_out;
}

int ttc_ws_poll(ttc_ws_t *ws, short events, short *revents) {
	return ttc_http_socket_poll(ws->sock, events, revents);
}
