#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
//#include <sys/types.h>
#include <unistd.h>
//#include "vTCIDirect.h"

//Hash value in PCRs: 20 bytes
#define TPM_DIGEST_SIZE          20
typedef struct __packed {
    uint8_t     digest[TPM_DIGEST_SIZE];
} tpm_digest_t;
typedef tpm_digest_t tpm_pcr_value_t;

#define STDOUT stdout
#define BUFSIZE 4*1024

typedef unsigned char byte;
// RPMMIO
#define RPTPMDEVICE "/dev/rpmmio0"

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
    char    *filesystem_hash = NULL;
    uint8_t hash_bytes[TPM_DIGEST_SIZE];
    size_t  i = 0;

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
        filesystem_hash = argv[2];
        printf("Will extend PCR%d by with filesyatem hash %s\n", pcrno, filesystem_hash);
    }
 
	fprintf(STDOUT, "use rpmmio\n");
	int tpmfd = open(RPTPMDEVICE, O_RDWR);

    if(tpmfd < 0) {
      fprintf(STDOUT, "Cann't open %s", RPTPMDEVICE);
      return false;
    }


	//test of rpmmio tpm driver
    //Prepare and pass arguments pcr and locaity to the driver, by overriding
    //the offset input field of lseek().
    locality = 0;
    size= BUFSIZE;
    tpm_digest_t in = {{0,}};

    for(i = 0; i < TPM_DIGEST_SIZE ; i++) {
        sscanf(&filesystem_hash[i*2], "%2hhx", &(in.digest[i]));
    }

    tpm_pcr_value_t out = {{0,}};
    PrintBytes("extend pcr: ", in.digest, TPM_DIGEST_SIZE);

    int returnSize=TPM_DIGEST_SIZE;
    byte returnDigest[TPM_DIGEST_SIZE];
    
    locality=0;
    offset = (pcrno<<16) | (locality&0XFFFF);
    lseek(tpmfd, offset, SEEK_SET);
    fprintf(STDOUT, "pcr %d, locality %d\n", pcrno, locality);
    ret=read(tpmfd, &rgpcr, TPM_DIGEST_SIZE);
    PrintBytes("PCR contents read by RPMMIO ", rgpcr, TPM_DIGEST_SIZE);
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
    ret = write(tpmfd, in.digest, TPM_DIGEST_SIZE);
    
    locality = 0;
	offset = (pcrno<<16) | (locality&0XFFFF);
    lseek(tpmfd, offset, SEEK_SET);
    fprintf(STDOUT, "pcr %d, locality %d\n", pcrno, locality);
    ret=read(tpmfd, &rgpcr, TPM_DIGEST_SIZE);
    PrintBytes("PCR contents read by RPMMIO ", rgpcr, TPM_DIGEST_SIZE);
    if(ret<0){
        fprintf(STDOUT, "read failed, ret %d\n", ret);
        close(tpmfd);
        return false;
    }
    
    close(tpmfd); 
    PrintBytes("PCR contents: ", rgpcr, TPM_DIGEST_SIZE);
    
    if(ret<0){
        fprintf(STDOUT, "submitTPMExtendReq failed\n");
        return false;
    }
    
    fprintf(STDOUT, "\n\nTPM test done\n");
    return 0;
}


// --------------------------------------------------------------------------


