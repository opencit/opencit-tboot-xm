/*
 * char_converter.c
 *
 *  Created on: 24-Dec-2015
 *      Author: vijay prakash
 */

#include<char_converter.h>


//map of asci char to hex values
const uint8_t char_hashmap[] =
   {
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
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
 */
int hex2bin(char* hex_str, int hex_str_len, unsigned char* byte_buffer,
		int byte_buffer_len) {

	if (hex_str == NULL) return -1;
	if (byte_buffer == NULL) return -2;
	if (hex_str_len/2 > byte_buffer_len - 1) return -3;
	int index;
	uint8_t msb_half_idx;
	uint8_t lsb_half_idx;
	bzero(byte_buffer, byte_buffer_len);
	//memset(byte_buffer, byte_buffer_len, 0);
	for(index = 0 ; index/2 < byte_buffer_len - 1 && index < hex_str_len ; index+=2 ) {
		msb_half_idx = (uint8_t)hex_str[index];
		lsb_half_idx = (uint8_t)hex_str[index+1];
		byte_buffer[index/2] = (uint8_t)(char_hashmap[msb_half_idx] << 4) | char_hashmap[lsb_half_idx];
	}
	return (index/2);
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
int bin2hex(unsigned char * byte_buffer, int byte_buffer_len, char * hex_str, int hex_str_len) {
	if (byte_buffer == NULL) return -2;
	if (hex_str == NULL) return -1;
	if ( byte_buffer_len * 2 + 1 < hex_str_len) return -3;

	const char bin_char_map[] = "0123456789abcdef";
	int index;
	for ( index =0 ; index < byte_buffer_len ; index ++) {
		hex_str[2*index] = bin_char_map[(byte_buffer[index] >>4) & 0x0F];
		hex_str[2*index + 1] = bin_char_map[ byte_buffer[index] & 0x0F];
	}
	return (index) * 2;
}

#ifdef STANDALONE
int hexstr_to_asciistr(char *hex_str, int hex_str_len, unsigned char * out_str) {
	int i = 0;
	unsigned int buff = 0 & 0xFF;
	int scanerr;
	for (i = 0 ; i < (hex_str_len + 1) /2 ; i ++) {
		scanerr = sscanf(hex_str+ (i*2), "%02x", &buff);
		if (scanerr == EOF && scanerr != 1) {
			printf("\nError while converting...");
			return -1;
		}
		out_str[i] = buff;
	}
	out_str[i] = '\0';
	return i;
}


int main(int argc, char* argv[] ) {

	if (argc < 2 ) {
		printf("Usage : ./char_converter \"hex strings\"");
		return 0;
	}
	int i;
	int input_sz;
	unsigned char * output;
	char * hex_output;
	int output_sz, hex_output_sz;
	for ( i = 1 ; i < argc ; i++ ) {
		input_sz = strlen(argv[i]);
		output_sz = input_sz/2 + 1;
		output = (unsigned char *) malloc( sizeof(unsigned char) * output_sz);
		output_sz = hex2bin(argv[i], input_sz, output, output_sz);
		printf("converted binary string  is : %s : its size : %d\n", (char *)&output[0], output_sz);
		output_sz = hexstr_to_asciistr(argv[i], input_sz, output);
		printf("converted binary string  is : %s : its size : %d\n", (char *)&output[0], output_sz);
		hex_output_sz= output_sz* 2 + 1;
		hex_output = (char *) calloc(1, sizeof(char)* hex_output_sz);
		hex_output_sz = bin2hex(output, output_sz, hex_output, hex_output_sz);
		printf("hex string converted from binary string : \"%s\" : its size : %d\n", hex_output, hex_output_sz);

		free(output);
		free(hex_output);
	}
	return 0;
}
#endif
