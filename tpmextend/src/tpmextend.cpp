#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
//#include <sys/types.h>
#include <unistd.h>
//#include "vTCIDirect.h"

#define MAX_HASH_LEN 		65
typedef struct __packed {
    uint8_t     digest[MAX_HASH_LEN];
} tpm_digest_t;
typedef tpm_digest_t tpm_pcr_value_t;

#define STDOUT stdout
#define BUFSIZE 4*1024

typedef unsigned char byte;
// RPMMIO
#define RPTPMDEVICE "/dev/rpmmio0"

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

	bzero(byte_buffer, byte_buffer_len);
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

void PrintBytes(const char* szMsg, byte* pbData, int iSize)
{
    int i;
    int col = 80;
    fprintf(STDOUT, "%s", szMsg);
    for (i= 0; i<iSize; i++) {
        fprintf(STDOUT, "%02x", pbData[i]);
        if((i%col)==(col-1))
            fprintf(STDOUT, "\n");
        }
    fprintf(STDOUT, "\n");
}

int main(int argc, char** argv)
{
    unsigned    locality;
    byte    rgpcr[BUFSIZE];
    byte    rgRandom[BUFSIZE];
    int     size;
    int     offset, ret;
    int     pcrno = -1;
    int     hash_size = 0;
    char    filesystem_hash[MAX_HASH_LEN] = {0};

    fprintf(STDOUT, "TPM extension\n\n");

    if(argc != 3) {
      printf("Usage: tpmextend <PCR number> <filesystem hash>\n");
      return -1;
    }

    if (argc == 3) {
        pcrno = atoi(argv[1]);
        if (pcrno < 0 || pcrno > 22) {
        	printf("Please provide a valid PCR no. to extend\n");
        	return -1;
        }

	size = snprintf(filesystem_hash, MAX_HASH_LEN, "%s", argv[2]);
	if(size == 40){
		hash_size = 20;
	}
	else if(size == 64){
		hash_size = 32;
	}
	else{
		printf("Please provide a valid digest size to extend\nCurrently supported digest size are 20 and 32\n");
		return -1;
	}
    }
    	printf("Will extend PCR%d by with filesyatem hash %s\n", pcrno, filesystem_hash);
 
	fprintf(STDOUT, "use rpmmio\n");
	int tpmfd = open(RPTPMDEVICE, O_RDWR);

    if(tpmfd < 0) {
      fprintf(STDOUT, "Cann't open %s", RPTPMDEVICE);
      return false;
    }

	
	tpm_digest_t in = {{0,}};
	tpm_pcr_value_t out = {{0,}};

	hex2bin(filesystem_hash, size, in.digest, MAX_HASH_LEN);
	PrintBytes("extend pcr: ", in.digest, hash_size);

    //test of rpmmio tpm driver
    //Prepare and pass arguments pcr and locaity to the driver, by overriding
    //the offset input field of lseek().
    locality = 0;
    size= BUFSIZE;

	int returnSize=hash_size;
    byte returnDigest[hash_size];
    
    locality=0;
    offset = (pcrno<<16) | (locality&0XFFFF);
    lseek(tpmfd, offset, SEEK_SET);
    fprintf(STDOUT, "pcr %d, locality %d\n", pcrno, locality);
    ret=read(tpmfd, &rgpcr, hash_size);
    PrintBytes("PCR contents read by RPMMIO ", rgpcr, hash_size);
        if(ret<0){
        fprintf(STDOUT, "read failed\n");
        close(tpmfd);
        return false;
    }
    
    locality=2;
    offset = (pcrno<<16) | (locality&0XFFFF);
    lseek(tpmfd, offset, SEEK_SET);
    //int ret=read(tpmfd, rgpcr, size);
    fprintf(STDOUT, "extend prc %d, locality %d\n", pcrno, locality);
    ret = write(tpmfd, in.digest, hash_size);
    
    locality = 0;
	offset = (pcrno<<16) | (locality&0XFFFF);
    lseek(tpmfd, offset, SEEK_SET);
    fprintf(STDOUT, "pcr %d, locality %d\n", pcrno, locality);
    ret=read(tpmfd, &rgpcr, hash_size);
    PrintBytes("PCR contents read by RPMMIO ", rgpcr, hash_size);
    if(ret<0){
        fprintf(STDOUT, "read failed, ret %d\n", ret);
        close(tpmfd);
        return false;
    }
    
    close(tpmfd); 
    PrintBytes("PCR contents: ", rgpcr, hash_size);
    
    if(ret<0){
        fprintf(STDOUT, "submitTPMExtendReq failed\n");
        return false;
    }
    
    fprintf(STDOUT, "\n\nTPM test done\n");
    return 0;
}


// --------------------------------------------------------------------------


