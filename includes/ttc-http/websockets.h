#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/ssl.h>

#define TTC_WS_CONTINUATION_FRAME 0x0
#define TTC_WS_TEXT_FRAME 0x1
#define TTC_WS_BIN_FRAME 0x2

#define TTC_WS_CONN_CLOSE_FRAME 0x8
#define TTC_WS_PING_FRAME 0x9
#define TTC_WS_PONG_FRAME 0xa

#define TTC_WS_FRAME_FINAL 0x80;

enum TTC_WS_CLOSE_CODES {
	TtcWsCloseNormal = 1000,
	TtcWsGoingAway = 1001,
	TtcWsProtocolErr = 1002,
	TtcWsInvalidData = 1003,
	TtcWsCloseRes = 1004,
	TtcWsCloseRes2 = 1005,
	TtcWsCloseResAbnormal = 1006,
	TtcWsDataTypeError = 1007,
	TtcWsPolicyViolation = 1008,
	TtcWsMessageToBig = 1009,
	TtcWsExtNotSupported = 1010,
	TtcWsRequestFailed = 1011,
	TtcWsTLSFailureRes = 1015,
};

typedef struct ttc_ws_wrreq {
	bool fin;
	bool mask;
	uint8_t res : 3;
	uint8_t opcode : 4;
	size_t len;
	char *data;
} ttc_ws_wrreq_t;

typedef struct ttc_ws_buffer {
	bool fin; /*final part of this message*/
	uint8_t opcode;
	char *data;
	size_t len; /*length of data*/
	char mask[4];
	uint16_t close_code;
} ttc_ws_buffer_t;

typedef struct ttc_ws ttc_ws_t;

void ttc_ws_free(ttc_ws_t *ws);
void ttc_ws_buffer_free(ttc_ws_buffer_t *buf);
ttc_ws_buffer_t *ttc_ws_read(ttc_ws_t *ws);
int ttc_ws_write(ttc_ws_t *ws, ttc_ws_wrreq_t req);
ttc_ws_t *ttc_ws_create_from_host(const char *host, const char *port, SSL_CTX *ctx);

/** All though this isn't the main purpose of the library just
 *  expose these symbols in case someone wants to use them
 */
uint16_t ttc_ws_endian_swap16(uint16_t innum);
uint32_t ttc_ws_endian_swap32(uint32_t innum);
uint64_t ttc_ws_endian_swap64(uint64_t innum);
