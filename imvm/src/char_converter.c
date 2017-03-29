/*
 * char_converter.c
 *
 *  Created on: 24-Dec-2015
 *      Author: vijay prakash
 */

#include"char_converter.h"

#ifdef _WIN32
#define uint8_t __int8
#endif

//map of asci char to hex values
const uint8_t char_hashmap[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // ........
		};

/**
 * convert hex string to binary string
 * hex_str: hex character string, hex_str_len: length of hex_character string,
 * byte_buffer: buffer to store byte array, byte_buffer_len: length of byte_buffer array
 * return:
 * 		on success: the length of resultant converted byte string
 * 		on failure: less than 0, -1 for hex_string is NULL, -2 for byte buffer is NULL,
 * 					-3 for byte buffer is not long enough to store converted binary string
 * 					-4 if hex string is on odd length
 * 					-5 if hex string contains invalid chars
 */
int hex2bin(char* hex_str, int hex_str_len, unsigned char* byte_buffer,
		int byte_buffer_len) {
	if (hex_str == NULL)
		return -1;
	if (byte_buffer == NULL)
		return -2;
	if (hex_str_len / 2 > byte_buffer_len - 1)
		return -3;
	if (hex_str_len % 2 != 0)
		return -4;
	int index;
	uint8_t msb_half_idx;
	uint8_t lsb_half_idx;
#ifdef _WIN32
	ZeroMemory(byte_buffer, byte_buffer_len);
#elif __linux__
	bzero(byte_buffer, byte_buffer_len);
#endif
	for (index = 0; index / 2 < byte_buffer_len - 1 && index < hex_str_len;
			index += 2) {
		char msb_hex_char = hex_str[index];
		char lsb_hex_char = hex_str[index + 1];
		if ((msb_hex_char >= 48 && msb_hex_char <= 57)
				|| (msb_hex_char >= 65 && msb_hex_char <= 70)
				|| (msb_hex_char >= 97 && msb_hex_char <= 102)) {
			msb_half_idx = (uint8_t) msb_hex_char;
		} else
			return -5;
		if ((lsb_hex_char >= 48 && lsb_hex_char <= 57)
				|| (lsb_hex_char >= 65 && lsb_hex_char <= 70)
				|| (lsb_hex_char >= 97 && lsb_hex_char <= 102)) {
			lsb_half_idx = (uint8_t) lsb_hex_char;
			byte_buffer[index / 2] = (uint8_t) (char_hashmap[msb_half_idx] << 4)
					| char_hashmap[lsb_half_idx];
		} else
			return -5;
	}
	return (index / 2);
}

/**
 * convert binary string to hex string
 * byte_buffer: buffer to store byte array, byte_buffer_len: length of byte_buffer array
 * hex_str: hex character string, hex_str_len: length of hex_character string,
 * return:
 * 		on success: the length of resultant converted hex string
 * 		on failure: less than 0, -1 for byte buffer is NULL, -2 for hex_string buffer is NULL,
 * 					-3 for hex string buffer is not long enough to store converted hex string
 */
int bin2hex(unsigned char * byte_buffer, int byte_buffer_len, char * hex_str,
		int hex_str_len) {
	if (byte_buffer == NULL)
		return -2;
	if (hex_str == NULL)
		return -1;
	if (byte_buffer_len * 2 + 1 > hex_str_len)
		return -3;
#ifdef _WIN32
	ZeroMemory(hex_str, hex_str_len);
#elif __linux__
	bzero(hex_str, hex_str_len);
#endif
	const char bin_char_map[] = "0123456789abcdef";
	int index;
	for (index = 0; index < byte_buffer_len; index++) {
		hex_str[2 * index] = bin_char_map[(byte_buffer[index] >> 4) & 0x0F];
		hex_str[2 * index + 1] = bin_char_map[byte_buffer[index] & 0x0F];
	}
	return (index) * 2;
}
