/*
 * char_converter.h
 *
 *  Created on: 24-Dec-2015
 *      Author: vijay prakash
 */

#ifndef CHAR_CONVERTER_H_
#define CHAR_CONVERTER_H_

#include<stdio.h>
#include<string.h>
#include<stdint.h>
#include<stdlib.h>

int hex2bin(char *hex_str, int hex_str_len, unsigned char *byte_buffer, int byte_buffer_len);
int bin2hex(unsigned char * byte_buffer, int byte_buffer_len, char * hex_str, int hex_str_len);

#endif /* CHAR_CONVERTER_H_ */
