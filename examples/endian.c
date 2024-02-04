#include <stdio.h>
#include <stdint.h>
#include <ttc-ws.h>

int main() {
	uint16_t number = 0x0010;
	uint32_t number32 = 0xCAFEBABE;
	uint64_t number64 = 0xDEADBEEFCAFEBABE;

	printf("%#X %d\n", number, number);

	number = ttc_ws_endian_swap16(number);

	printf("0x%x%.2x\n", (number >> 8), number & 0xff);

	printf("%X\n", number32);

	number32 = ttc_ws_endian_swap32(number32);

	printf("%x\n", number32);

	printf("%lx\n", number64);

	number64 = ttc_ws_endian_swap64(number64);

	printf("%lx\n", number64);

	return 0;
}
