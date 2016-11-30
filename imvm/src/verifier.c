/* Measurement Agent - Litev2
@SRK 
Intel Corp - CSS-DCG 
Hard requirements: Manifest should be named manifestlist.xml - Parameters should be passed on command line using the entire file/directory path
Keywords in the Policy should match with those in this code : DigestAlg, File Path, Dir, sha1 and sha256
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/xmlreader.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include "openssl/sha.h"
#include <fcntl.h>
#include <errno.h>
#include <linux/limits.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <ctype.h>
#include "safe_lib.h"
#include "char_converter.h"

#define DEBUG_LOG(fmt, args...) fprintf(stdout, fmt, ##args)
#define ERROR_LOG(fmt, args...) fprintf(stderr, fmt, ##args)
#define byte unsigned char
#define MAX_LEN 4096
#define NODE_LEN 512
#define MAX_HASH_LEN 65

char hashType[10];
char hashFile[NODE_LEN];
char node_value[NODE_LEN];
char fs_mount_path[NODE_LEN];
int sha_one = 1;
int version = 1;

/*These global variables are required for calculating the cumulative hash */
unsigned char cHash[SHA_DIGEST_LENGTH] = {'\0'}; //Cumulative hash
unsigned char cHash256[SHA256_DIGEST_LENGTH] = {'\0'};
unsigned char uHash[SHA_DIGEST_LENGTH]={0};
unsigned char uHash256[SHA256_DIGEST_LENGTH]={0};
SHA_CTX csha1;
SHA256_CTX csha256;


/*This function keeps track of the cumulative hash and stores it in a global variable (which is later written to a file) */
void generate_cumulative_hash(char *hash) {

    DEBUG_LOG("\nIncoming Hash : %s\n",hash);
    char ob[MAX_HASH_LEN]= {'\0'};
    if(sha_one) {
    	char cur_hash[SHA_DIGEST_LENGTH + 1] = {'\0'};
	strncpy_s((char *)cHash,sizeof(cHash),(char *)uHash,SHA_DIGEST_LENGTH);
	bin2hex(cHash, sizeof(cHash), ob, sizeof(ob));
	DEBUG_LOG("\n%s %s","Cumulative Hash before:",ob);
	SHA1_Init(&csha1);
	SHA1_Update(&csha1,uHash,SHA_DIGEST_LENGTH);
	if (SHA_DIGEST_LENGTH == hex2bin(hash, strnlen_s(hash,MAX_LEN), (unsigned char *)cur_hash, sizeof(cur_hash))) {
		SHA1_Update(&csha1,cur_hash, SHA_DIGEST_LENGTH);
	}
	else {
		DEBUG_LOG("\n length of string converted from hex is not equal to SHA1 digest length");
	}
	SHA1_Final(uHash,&csha1);

	strncpy_s( (char *)cHash,sizeof(cHash), (char *)uHash,SHA_DIGEST_LENGTH);
	bin2hex(cHash, sizeof(cHash), ob, sizeof(ob));
	DEBUG_LOG("\n%s %s","Cumulative Hash after is:",ob);
	memset_s(ob,strnlen_s(ob,sizeof(ob)),'\0');
	return;
    }
    else{
        char cur_hash[SHA256_DIGEST_LENGTH + 1] = {'\0'};
	strncpy_s(( char *)cHash256,sizeof(cHash256), (char *)uHash256,SHA256_DIGEST_LENGTH);
	bin2hex(cHash256, sizeof(cHash256), ob, sizeof(ob));
    	DEBUG_LOG("\n%s %s","Cumulative Hash before:",ob);
	SHA256_Init(&csha256);
	SHA256_Update(&csha256,uHash256,SHA256_DIGEST_LENGTH);
	if (SHA256_DIGEST_LENGTH == hex2bin(hash, strnlen_s(hash,MAX_LEN), (unsigned char *)cur_hash, sizeof(cur_hash))) {
	    SHA256_Update(&csha256,cur_hash, SHA256_DIGEST_LENGTH);
	}
	else {
	    DEBUG_LOG("\n length of string converted from hex is not equal to SHA256 digest length");
	}
	SHA256_Final(uHash256, &csha256);
	strncpy_s((char *)cHash256,sizeof(cHash256), (char *) uHash256,SHA256_DIGEST_LENGTH);
	bin2hex(cHash256, sizeof(cHash256), ob, sizeof(ob));
	DEBUG_LOG("\n%s %s","Cumulative Hash after is:",ob);
	memset_s(ob,strnlen_s(ob,sizeof(ob)),'\0');
	return;
    }
}

/* 
 * getSymLinkValue:
 * @path : path of the file/symbolic link
 *
 * Returns the actual value for the symbolic link provided as input
 */
int getSymLinkValue(char *path) {

    struct stat p_statbuf;
    char symlinkpath[512];
    if (lstat(path, &p_statbuf) < 0) {  /* if error occured */
        ERROR_LOG("\n%s %s","Not valid path -", path);
        return -1;
    }
    // Check if the file path is a symbolic link
    if (S_ISLNK(p_statbuf.st_mode) ==1) {
        // If symbolic link doesn't exists read the path its pointing to
        int len = readlink(path, symlinkpath, sizeof(symlinkpath));
        if (len != -1) {
            symlinkpath[len] = '\0';
        }
        DEBUG_LOG("\n%s %s %s %s","Symlink",path," points to",symlinkpath);
        //("Symlink '%s' points to '%s' \n", path, symlinkpath);
        char sympathroot[512];
        // If the path is starting with "/" and 'fs_mount_path' is not appended
        if(((strstr(symlinkpath, "/") - symlinkpath) == 0) && (strstr(symlinkpath,fs_mount_path) == NULL)) {
            snprintf(sympathroot, sizeof sympathroot, "%s%s", fs_mount_path, symlinkpath);
            DEBUG_LOG("\n%s %s %s %s","Absolute symlink path",symlinkpath,"points to",sympathroot);
	    //printf("Absolute symlink path '%s' points to '%s'\n", symlinkpath, sympathroot);
        }
        else {
            char* last_backslash = strrchr(path, '/');
            if (last_backslash) {
                *last_backslash = '\0';
            }
            snprintf(sympathroot, sizeof sympathroot, "%s%s%s", path, "/", symlinkpath);
            DEBUG_LOG("\n%s %s %s %s","Relative symlink path",symlinkpath,"points to",sympathroot);
	    //printf("Relative symlink path '%s' point to '%s'\n", symlinkpath, sympathroot);
        }

        strcpy_s(path, MAX_LEN, sympathroot);
        if(version == 2) {
            strcpy_s(path, MAX_LEN, symlinkpath);
	} else {
	    return getSymLinkValue(path);
	}
    }
    return 0;
}

/*This function returns the value of an XML tag. 
Input parameter: Line read from the XML file
Output: Value in the tag
How it works: THe function accepts a line containing tag value as input
it parses the line until it reaches quotes (" ") 
and returns the value held inside them 
so <File Path = "a.txt" .....> returns a.txt
include="*.out" ....> returns *.out and so on..
*/
char *tagEntry (char* line) {

    int i =0;
    char key[NODE_LEN];
    char *start,*end;
    /*We use a local string 'key' here so that we dont make any changes
    to the line pointer passed to the function. 
    This is useful in a line containing more than 1 XML tag values.
    E.g :<Dir Path="/etc" include="*.bin" exclude="*.conf">
    */
    strcpy_s(key,sizeof(key),line);
 
    while(key[i] != '\"')
        i++;
    start = &key[++i];

    end = start;
    while(*end != '\"')
        end++;
    *end = '\0';

    strcpy_s(node_value, sizeof(node_value), start);
}

void convertWildcardToRegex(char *wildcard) {

    int i=0, j=0;
    char c;
    char key[NODE_LEN];

    strcpy_s(key,sizeof(key),wildcard);
    node_value[j++] = '^';

    c = key[i];
    while(c) {
    	switch(c) {
      	    case '*':
		node_value[j++] = '.';
        	node_value[j++] = '*';
        	break;
            case '?':
        	node_value[j++] = '.';
        	break;
      	    case '(':
      	    case ')':
      	    case '[':
      	    case ']':
      	    case '$':
     	    case '^':
      	    case '.':
      	    case '{':
      	    case '}':
      	    case '|':
      	    case '\\':
        	node_value[j++] = '\\';
        	node_value[j++] = c;
        	break;
      	    default:
        	node_value[j++] = c;
        	break;
	}
	c = key[++i];
    }

    node_value[j++] = '$';
    node_value[j] = '\0';
}

 /*
 * calculate:
 * @path : path of the file
 * @output : character array for storing the resulted file hash
 *
 * Calculate hash of file
 */
char* calculateSymlinkHash(char *line, FILE *fq) {

    int retval = -1; 
    int bytesRead = 0;
    char *buffer = NULL;
    char hash_str[MAX_LEN] = {'\0'};
    char output[MAX_HASH_LEN] = {'\0'};
    char file_name_buff[1024] = {'\0'};
    FILE *file;

    tagEntry(line);
    snprintf(file_name_buff, sizeof(file_name_buff), "%s/%s", fs_mount_path, node_value);
    DEBUG_LOG("\nfile path : %s\n", file_name_buff);
    retval = getSymLinkValue(file_name_buff);
    if( retval == 0 ) {
        fprintf(fq,"<Symlink Path=\"%s\">",node_value);
        DEBUG_LOG("\n%s %s %s %s","Target file path for symlink",node_value,"is",file_name_buff);

        snprintf(hash_str, MAX_LEN, "%s%s", node_value, file_name_buff);
        /*How the process works:
        1. Concatenate source path and target path
        2. Store that content into char * buffer
        3. Pass those to SHA function.(Output to char output passed to the function)
        4. Return the Output string.
        */
        if(sha_one) {
            // Using SHA1 algorithm for hash calculation
            unsigned char hash[SHA_DIGEST_LENGTH];
            SHA_CTX sha1;
            SHA1_Init(&sha1);
            SHA1_Update(&sha1, hash_str, strnlen_s(hash_str, sizeof(hash_str)));
            SHA1_Final(hash, &sha1);
            bin2hex(hash, sizeof(hash), output, MAX_HASH_LEN);
            generate_cumulative_hash(output);
        }
        else {
            //For SHA 256 hash**Hard dependency on exact usage of 'sha256'
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, hash_str, strnlen_s(hash_str, sizeof(hash_str)));
            SHA256_Final(hash, &sha256);
            bin2hex(hash, sizeof(hash), output, MAX_HASH_LEN);
            generate_cumulative_hash(output);
        }
        fprintf(fq,"%s</Symlink>\n", output);
        DEBUG_LOG("\n%s %s %s %s","Symlink :",node_value,"Hash Measured:",output);
    }
}

 /*
 * calculate:
 * @path : path of the file
 * @output : character array for storing the resulted file hash
 *
 * Calculate hash of file
 */
char* calculateFileHash(char *line, FILE *fq) {

    int retval = -1; 
    int bytesRead = 0;
    char *buffer = NULL;
    char output[MAX_HASH_LEN] = {'\0'};
    char file_name_buff[1024] = {'\0'};
    FILE *file;

    tagEntry(line);
    snprintf(file_name_buff, sizeof(file_name_buff), "%s/%s", fs_mount_path, node_value);
    DEBUG_LOG("\nfile path : %s\n", file_name_buff);
    retval = getSymLinkValue(file_name_buff);
    if( retval == 0 ) {
	fprintf(fq,"<File Path=\"%s\">",node_value);
	DEBUG_LOG("\n%s %s %s %s","Mounted file path for file",node_value,"is",file_name_buff);
    
	file = fopen(file_name_buff, "rb");
	if(!file) {
	    ERROR_LOG("\n%s %s","File not found-", file_name_buff);
            goto cleanup;
	}
	/*How the process works: 
	1. Open the file pointed by value
	2. Read the file contents into char * buffer
	3. Pass those to SHA function.(Output to char output passed to the function)
	4. Return the Output string. 
	*/
    	if(sha_one) {
	    // Using SHA1 algorithm for hash calculation
            unsigned char hash[SHA_DIGEST_LENGTH];
            SHA_CTX sha1;
            SHA1_Init(&sha1);
            const int bufSize = 32768;

            buffer = (char *) malloc(bufSize);
            if(!buffer) {
                goto cleanup;
            }
            while((bytesRead = fread(buffer, 1, bufSize, file))) {
                SHA1_Update(&sha1, buffer, bytesRead);
            }
            SHA1_Final(hash, &sha1);
            bin2hex(hash, sizeof(hash), output, MAX_HASH_LEN);
            generate_cumulative_hash(output);
        }
        else {
	    //For SHA 256 hash**Hard dependency on exact usage of 'sha256'
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            const int bufSize = 65000;

            buffer = (char *)malloc(bufSize);
            if(!buffer) {
                goto cleanup;
            }
            while((bytesRead = fread(buffer, 1, bufSize, file))) {
              SHA256_Update(&sha256, buffer, bytesRead);
            }
            SHA256_Final(hash, &sha256);
            bin2hex(hash, sizeof(hash), output, MAX_HASH_LEN);
            generate_cumulative_hash(output);
        }

    cleanup:
	if(file) fclose(file);
	if(buffer) free(buffer);

        fprintf(fq,"%s</File>\n", output);
	DEBUG_LOG("\n%s %s %s %s","File :",node_value,"Hash Measured:",output);
    }
}

char* calculateDirHashV1(char *line, FILE *fq) {

    int slen = 0;
    size_t len = 0;
    size_t dhash_max = 128;
    char *dhash = NULL;
    char *temp_ptr = NULL;
    char *next_token = NULL;
    char dir_path[NODE_LEN] = {'\0'};
    char recursive_cmd[32] = {'\0'};
    char hash_algo[16] = {'\0'};
    char recursive[16] = {'\0'};
    char exclude[128] = { '\0'};
    char include[128] = {'\0'};
    char Dir_Str[256] = {'\0'};
    char mDpath[256] = {'\0'};
    FILE *dir_file;

    temp_ptr = strstr(line, "Path=");
    if (temp_ptr != NULL ) {
	tagEntry(temp_ptr);
	strcpy_s(dir_path,sizeof(dir_path),node_value);
    }
    DEBUG_LOG("\n%s %s","Directory :",node_value);

    temp_ptr=NULL;
    temp_ptr=strstr(line, "Recursive=");
    if ( temp_ptr != NULL ) {
	tagEntry(temp_ptr);
	strcpy_s(recursive,sizeof(recursive),node_value);
	DEBUG_LOG("\nRecursive : %s", node_value);
	if ( strcmp(recursive, "false") == 0) {
            snprintf(recursive_cmd, sizeof(recursive_cmd), "-maxdepth 1");
	}
    }

    temp_ptr = NULL;
    temp_ptr = strstr(line, "Include=");
    if (temp_ptr != NULL) {
	tagEntry(temp_ptr);
	strcpy_s(include,sizeof(include),node_value);
	DEBUG_LOG("\n%s %s","Include type :",node_value);
    }

    temp_ptr = NULL;
    temp_ptr = strstr(line,"Exclude=");
    if ( temp_ptr != NULL ) {
	tagEntry(temp_ptr);
	strcpy_s(exclude,sizeof(exclude),node_value);
	DEBUG_LOG("\n%s %s","Exclude type :",node_value);
    }

    strcpy_s(mDpath,sizeof(mDpath),fs_mount_path);
    strcat_s(mDpath,sizeof(mDpath),dir_path);//path of dir in the VM

    //to remove mount path from the find command output and directory path and +1 is to remove the additional / after directory
    slen = strnlen_s(mDpath,sizeof(mDpath)) + 1; 
    snprintf(hash_algo,sizeof(hash_algo),"%ssum",hashType);

    if(strcmp(include,"") != 0 && strcmp(exclude,"") != 0 )
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" %s ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | grep -vE \"%s\" | %s",mDpath, recursive_cmd, slen, include, exclude, hash_algo);
    else if(strcmp(include,"") != 0)
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" %s ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | %s",mDpath, recursive_cmd, slen, include, hash_algo);
    else if(strcmp(exclude,"") != 0)
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" %s ! -type d | sed -r 's/.{%d}//' | grep -vE \"%s\" | %s",mDpath, recursive_cmd, slen, exclude, hash_algo);
    else
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" %s ! -type d | sed -r 's/.{%d}//' | %s",mDpath, recursive_cmd, slen, hash_algo);

    DEBUG_LOG("\n%s %s %s %s","********mDpath is ----------",mDpath," and command is ",Dir_Str);

    dir_file = popen(Dir_Str,"r");
    if (dir_file != NULL ) {
	getline(&dhash, &len, dir_file);
	strtok_s(dhash,&dhash_max," ",&next_token);
    }
    else {
	dhash = "\0";
    }

    fprintf(fq,"<Dir Path=\"%s\">",dir_path);
    fprintf(fq,"%s</Dir>\n",dhash);
    if(strcmp(hashType, "sha256") == 0)
	generate_cumulative_hash(dhash);
    else
        generate_cumulative_hash(dhash);

    if (dir_file != NULL) {
	pclose(dir_file);
    }
}

char* calculateDirHashV2(char *line, FILE *fq) {

    int slen = 0;
    int is_wildcard = 0;
    size_t len = 0;
    size_t dhash_max = 128;
    char *dhash = NULL;
    char *temp_ptr = NULL;
    char *next_token = NULL;
    char dir_path[NODE_LEN] = {'\0'};
    char filter_type[32] = {'\0'};
    char hash_algo[16] = {'\0'};
    char exclude[128] = { '\0'};
    char include[128] = {'\0'};
    char Dir_Str[256] = {'\0'};
    char mDpath[256] = {'\0'};
    FILE *dir_file;

    temp_ptr = strstr(line, "Path=");
    if (temp_ptr != NULL ) {
	tagEntry(temp_ptr);
	strcpy_s(dir_path,sizeof(dir_path),node_value);
    }
    DEBUG_LOG("\n%s %s","Directory :",node_value);

    temp_ptr = NULL;
    temp_ptr = strstr(line,"FilterType=");
    if ( temp_ptr != NULL ) {
	tagEntry(temp_ptr);
	strcpy_s(filter_type,sizeof(filter_type),node_value);
	DEBUG_LOG("\n%s %s","Filter type :",node_value);

	if(strcmp(filter_type, "wildcard") == 0) {
	    is_wildcard = 1;
	}
    }

    temp_ptr = NULL;
    temp_ptr = strstr(line, "Include=");
    if (temp_ptr != NULL) {
	tagEntry(temp_ptr);
	strcpy_s(include,sizeof(include),node_value);
	DEBUG_LOG("\n%s %s","Include type :",node_value);
        if(is_wildcard == 1 && strcmp(include,"") != 0) {
	    convertWildcardToRegex(include);
	    strcpy_s(include,sizeof(include),node_value);
	    DEBUG_LOG("\n%s %s","Include type in node_value :",node_value);
	}
    }

    temp_ptr = NULL;
    temp_ptr = strstr(line,"Exclude=");
    if ( temp_ptr != NULL ) {
	tagEntry(temp_ptr);
	strcpy_s(exclude,sizeof(exclude),node_value);
	DEBUG_LOG("\n%s %s","Exclude type :",node_value);
        if(is_wildcard == 1 && strcmp(exclude,"") != 0) {
	    convertWildcardToRegex(exclude);
	    strcpy_s(exclude,sizeof(exclude),node_value);
	    DEBUG_LOG("\n%s %s","Exclude type in node_value :",node_value);
	}
    }

    strcpy_s(mDpath,sizeof(mDpath),fs_mount_path);
    strcat_s(mDpath,sizeof(mDpath),dir_path);//path of dir in the VM

    //to remove mount path from the find command output and directory path and +1 is to remove the additional / after directory
    slen = strnlen_s(mDpath,sizeof(mDpath)) + 1; 
    snprintf(hash_algo,sizeof(hash_algo),"%ssum",hashType);

    if(strcmp(include,"") != 0 && strcmp(exclude,"") != 0 )
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | grep -vE \"%s\" | %s",mDpath, slen, include, exclude, hash_algo);
    else if(strcmp(include,"") != 0)
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | %s",mDpath, slen, include, hash_algo);
    else if(strcmp(exclude,"") != 0)
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -vE \"%s\" | %s",mDpath, slen, exclude, hash_algo);
    else
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | %s",mDpath, slen, hash_algo);

    DEBUG_LOG("\n%s %s %s %s","********mDpath is ----------",mDpath," and command is ",Dir_Str);

    dir_file = popen(Dir_Str,"r");
    if (dir_file != NULL ) {
	getline(&dhash, &len, dir_file);
	strtok_s(dhash,&dhash_max," ",&next_token);
    }
    else {
	dhash = "\0";
    }

    fprintf(fq,"<Dir Path=\"%s\">",dir_path);
    fprintf(fq,"%s</Dir>\n",dhash);
    if(strcmp(hashType, "sha256") == 0)
	generate_cumulative_hash(dhash);
    else
        generate_cumulative_hash(dhash);

    if (dir_file != NULL) {
	pclose(dir_file);
    }
}

/*
This is the major function of the measurement agent.
It scans the Manifest for the key words : File Path **** Hard Dependency 
                                          Dir Path  **** Hard Dependency
										  DigestAlg= **** Hard Dependency
										  Include **** Hard Dependency     
										  Exclude **** Hard Dependency
and generates appropriate logs. 

Maybe we can have a to_upper/lower kinda function here that can take care of format issues.(Not covered in the Lite version)

Manifest path is passed as the argument to the function.
Log path is the directory where manifestlist.xml is present. 

How it works: 
File is scanned line by line, value of file path, dir path, incl.excl cases are obtained
if its just a file or a dir, the path is passed directly to the hashing function: calculate()
If there are incl, excl cases, system command is run to create a file containing directory files of the required type
The newly created filepath (Not file object!) 
is passed to calculate and the hash is added against log the dir in question									

*/
void generateMeasurementLogs(const char *origManifestPath, char *imagePath, char *verificationType) {

    int digest_check = 0;
    size_t len = 0;
    char *line = NULL;
    char *temp_ptr = NULL;
    char ma_result_path[1024] = {'\0'};
    char cH[MAX_HASH_LEN]= {'\0'};
    char ma_result_path_default[100]="/var/log/trustagent/measurement.xml";
    FILE *fp, *fq, *fd; 

    if(strcmp(verificationType,"HOST") == 0)
        snprintf(ma_result_path, sizeof(ma_result_path), "%s%s", fs_mount_path, ma_result_path_default);
    else
        snprintf(ma_result_path, sizeof(ma_result_path), "%s%s",hashFile,"xml");
    
    DEBUG_LOG("\n%s %s","Manifest Path",origManifestPath);
    fp = fopen(origManifestPath,"r");
    if (fp != NULL) {
	fq = fopen(ma_result_path,"w");
	chmod(ma_result_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fq != NULL) {
            fprintf(fq,"<?xml version=\"1.0\"?>\n");
	   //Open Manifest to get list of files to hash
	    while (getline(&line, &len, fp) != -1) {
		if(strstr(line,"<Manifest ") != NULL) {
		    temp_ptr = strstr(line,"DigestAlg=");
		    if(temp_ptr != NULL){
		        /*Get the type of hash */
		        tagEntry(temp_ptr);
		        strcpy_s(hashType,sizeof(hashType),node_value);
			if(strcmp(hashType, "sha256") == 0) {
			    sha_one = 0;
			}
		        digest_check = 1;
		        DEBUG_LOG("\n%s %s","Type of Hash used :",hashType);
		    }

		    temp_ptr = NULL;
		    temp_ptr = strstr(line,"Version=");
		    if(temp_ptr != NULL){
		        /*Get the type of version */
		        tagEntry(temp_ptr);
			version = *(node_value + 2) - '0';
		        DEBUG_LOG("\n%s %d","Version of Policy used :",version);
		    }
		    fprintf(fq,"<Measurements xmlns=\"mtwilson:trustdirector:measurements:1.%d\" DigestAlg=\"%s\">\n",version,hashType);
		}

		//File Hashes
		if(strstr(line,"<File Path=") != NULL && digest_check) {
		    calculateFileHash(line, fq);
		}

		//Symlink Hashes
		if(strstr(line,"<Symlink Path=") != NULL && digest_check) {
		    calculateSymlinkHash(line, fq);
		}

		//Directory Hashes
		if(strstr(line,"<Dir ") != NULL && digest_check) {
		    if(version == 1)
			calculateDirHashV1(line, fq);
		    else
			calculateDirHashV2(line, fq);
		}//Dir hash ends

	    }//While ends

	    if(!digest_check){
		ERROR_LOG("%s","Hash Algorithm not specified!");
	    }

	    fprintf(fq,"</Measurements>");
		fclose(fq);
	    }
	    else{
		ERROR_LOG("Can not open file: %s to write the measurement", ma_result_path);
		fclose(fp);
		return;
	    }
	fclose(fp);
    }
    else {
    	ERROR_LOG("Can not open Manifest file: %s", origManifestPath);
    	return;
    }

    strcat_s(hashFile,sizeof(hashFile),hashType);
    /*Write the Cumulative Hash calculated to the file*/
    FILE *fc = fopen(hashFile,"w");
	chmod(hashFile, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fc == NULL ) {
    	ERROR_LOG("Can not open file: %s, to write cumulative hash", hashFile);
    	return;
    }
    if(strcmp(hashType, "sha256") == 0){
    	bin2hex(uHash256, sizeof(uHash256), cH, sizeof(cH));
    }
    else {
    	bin2hex(uHash, sizeof(uHash), cH, sizeof(cH));
    }
    fprintf(fc,"%s",cH);
    fclose(fc);
}

/*
 * Main function which checks for the different input parameters 
 * provided to the verifier and calls a xml parsing function
 */
int main(int argc, char **argv) {

    char* last_oblique_ptr = NULL;
    char manifest_file[256] = {'\0'};
    xmlDocPtr Doc;

    if(argc != 4) {
        ERROR_LOG("\n%s %s %s","Usage:",argv[0]," <manifest_path> <mounted_path> <IMVM/HOST>");
        return EXIT_FAILURE;
    }
    DEBUG_LOG("\n%s %s","MANIFEST-PATH :", argv[1]);
    DEBUG_LOG("\n%s %s","MOUNTED-PATH :", argv[2]);
    DEBUG_LOG("\n%s %s","MODE :", argv[3]);

    strcpy_s(manifest_file,sizeof(manifest_file),argv[1]);
    strcpy_s(fs_mount_path,sizeof(fs_mount_path),argv[2]);
    strcat_s(fs_mount_path,sizeof(fs_mount_path),"/");
    memset_s((char *)cHash,strnlen_s((char *)cHash,sizeof(cHash)),0);
    memset_s((char *)cHash256,strnlen_s((char *)cHash256,sizeof(cHash256)),0);

    if (strcmp(argv[3], "IMVM") == 0) {
    	last_oblique_ptr = strrchr(manifest_file, '/');
    	strncpy_s(hashFile,sizeof(hashFile),manifest_file,strnlen_s(manifest_file,sizeof(manifest_file))-strnlen_s(last_oblique_ptr + 1, sizeof("/manifest.xml")));
    	strcat_s(hashFile,sizeof(hashFile),"/measurement.");
    } else if (strcmp(argv[3], "HOST") == 0) {
        snprintf(hashFile, sizeof(hashFile), "%s/var/log/trustagent/measurement.", fs_mount_path);
    } else { 
        ERROR_LOG("\n%s","Invalid verification_type.Valid options are IMVM/HOST\n");
        return EXIT_FAILURE;
    }

    Doc = xmlParseFile(argv[1]); 
    /*This will save the XML file in a correct format, as desired by our parser. 
    We dont use libxml tools to parse but our own pointer legerdemain for the time being
    Main advantage is simplicity and speed ~O(n) provided space isn't an issue */
    xmlSaveFormatFile (argv[1], Doc, 1); /*This would render even inline XML perfect for line by line parsing*/  
    xmlFreeDoc(Doc);  
    generateMeasurementLogs(argv[1], argv[2], argv[3]);
    
    return 0;
}
