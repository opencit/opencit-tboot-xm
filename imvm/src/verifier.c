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
#include <string.h>
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

//#define MOUNTPATH_IMVM  "/tmp/"
//#define MOUNTPATH_HOST  "/tmp/root"
#define DEBUG_LOG(fmt, args...) fprintf(stdout, fmt, ##args)
#define ERROR_LOG(fmt, args...) fprintf(stderr, fmt, ##args)
#define byte unsigned char
#define MAX_LEN 4096
#define MAX_HASH_LEN 65

char fs_mount_path[1024];
char hashType[10]; //SHA1 or SHA256
char NodeValue[500]; //XML Tag value
/*These global variables are required for calculating the cumulative hash */
unsigned char cHash[SHA_DIGEST_LENGTH] = {'\0'}; //Cumulative hash
unsigned char cHash2[SHA256_DIGEST_LENGTH] = {'\0'};
unsigned char d1[SHA_DIGEST_LENGTH]={0};
unsigned char d2[SHA256_DIGEST_LENGTH]={0};
char cH2[MAX_HASH_LEN];
char hash_file[256];
int process_started = 0;
SHA256_CTX csha256;
SHA_CTX csha1;


/*This function keeps track of the cumulative hash and stores it in a global variable (which is later written to a file) */
void generate_cumulative_hash(char *hash,int sha_one){
    DEBUG_LOG("\nIncoming Hash : %s\n",hash);
	char ob[MAX_HASH_LEN]= {'\0'};
	char cur_hash[SHA256_DIGEST_LENGTH + 1] = {'\0'};
    if(sha_one){
    	//char cur_hash[SHA_DIGEST_LENGTH + 1] = {'\0'};
	   strncpy_s((char *)cHash,sizeof(cHash),(char *)d1,SHA_DIGEST_LENGTH);
	   bin2hex(cHash, sizeof(cHash), ob, sizeof(ob));
       //DEBUG_LOG("\n%s %s","Cumulative Hash before:",sha1_hash_string(cHash,ob));
	   DEBUG_LOG("\n%s %s","Cumulative Hash before:",ob);
	   SHA1_Init(&csha1);
	   SHA1_Update(&csha1,d1,SHA_DIGEST_LENGTH);
	   if (SHA_DIGEST_LENGTH == hex2bin(hash, strnlen_s(hash,MAX_LEN), (unsigned char *)cur_hash, sizeof(cur_hash))) {
		   SHA1_Update(&csha1,cur_hash, SHA_DIGEST_LENGTH);
	   }
	   else {
		   DEBUG_LOG("\n length of string converted from hex is not equal to SHA1 digest length");
	   }
	   SHA1_Final(d1,&csha1);
	   
	   strncpy_s( (char *)cHash,sizeof(cHash), (char *)d1,SHA_DIGEST_LENGTH);
	   bin2hex(cHash, sizeof(cHash), ob, sizeof(ob));
	   //DEBUG_LOG("\n%s %s","Cumulative Hash after is:",sha1_hash_string(cHash,ob));
	   DEBUG_LOG("\n%s %s","Cumulative Hash after is:",ob);
	   memset_s(ob,strnlen_s(ob,sizeof(ob)),'\0');
	   
	   return;
	}
	
	else{
	   strncpy_s(( char *)cHash2,sizeof(cHash2), (char *)d2,SHA256_DIGEST_LENGTH);
	   bin2hex(cHash2, sizeof(cHash2), ob, sizeof(ob));
       //DEBUG_LOG("\n%s %s","Cumulative Hash before:",sha256_hash_string(cHash2,ob));
       DEBUG_LOG("\n%s %s","Cumulative Hash before:",ob);
	   SHA256_Init(&csha256);
	   SHA256_Update(&csha256,d2,SHA256_DIGEST_LENGTH);
	   if (SHA256_DIGEST_LENGTH == hex2bin(hash, strnlen_s(hash,MAX_LEN), (unsigned char *)cur_hash, sizeof(cur_hash))) {
		   SHA256_Update(&csha256,cur_hash, SHA256_DIGEST_LENGTH);
	   }
	   else {
		   DEBUG_LOG("\n length of string converted from hex is not equal to SHA256 digest length");
	   }
	   SHA256_Final(d2, &csha256);
	   strncpy_s((char *)cHash2,sizeof(cHash2), (char *) d2,SHA256_DIGEST_LENGTH);
	   bin2hex(cHash2, sizeof(cHash2), ob, sizeof(ob));
	   //DEBUG_LOG("\n%s %s","Cumulative Hash after is:",sha256_hash_string(cHash2,ob));
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
            return getSymLinkValue(path);
    }
    return 0;
}
 /*
 * calculate:
 * @path : path of the file
 * @output : character array for storing the resulted file hash
 *
 * Calculate hash of file
 */
char* calculate(char *path, char output[MAX_HASH_LEN]) {
    
    char hash_in[65];
    char value[1056] = {'\0'};
    /*We append the mount path before the filepath first, 
	 and then pass that address to calculate the hash */

    strcpy_s(value, sizeof(value), fs_mount_path);
    strcat_s(value,sizeof(value),path);//Value = Mount Path + Path in the image/disk
    int retval = getSymLinkValue(value);
    if(retval != 0) {
        ERROR_LOG("\n%s %s %s","File:",path,"doesn't exist");
        return NULL;
    }
	DEBUG_LOG("\n%s %s %s %s","Mounted file path for file",path,"is",value);
    
    FILE* file = fopen(value, "rb");
    if(!file) {
        ERROR_LOG("\n%s %s","File not found-", value);
        return NULL;
    }
    /*How the process works: 
   1. Open the file pointed by value
   2. Read the file contents into char * buffer
   3. Pass those to SHA function.(Output to char output passed to the function)
   4. Return the Output string. 
   */
    if(strcmp(hashType, "sha256") == 0) {
     //For SHA 256 hash**Hard dependency on exact usage of 'sha256'   
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        const int bufSize = 65000;
        char *buffer = (char *)malloc(bufSize);
       
        int bytesRead = 0;
        if(!buffer) {
        	fclose(file);
        	return NULL;
        }
        while((bytesRead = fread(buffer, 1, bufSize, file))) {
             
              SHA256_Update(&sha256, buffer, bytesRead);
        }
        SHA256_Final(hash, &sha256);
        //output = sha256_hash_string(hash, output);
        bin2hex(hash, sizeof(hash), output, MAX_HASH_LEN);
		strcpy_s(hash_in,sizeof(hash_in),output);
        generate_cumulative_hash(output,0);
        fclose(file);
        free(buffer);
    }
    else {
        // Using SHA1 algorithm for hash calculation
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA_CTX sha1;
        SHA1_Init(&sha1);
        const int bufSize = 32768;
        char *buffer = (char *) malloc(bufSize);
        int bytesRead = 0;
        if(!buffer) {
        	fclose(file);
        	return NULL;
        }
        while((bytesRead = fread(buffer, 1, bufSize, file))) {
            SHA1_Update(&sha1, buffer, bytesRead);
        }
        SHA1_Final(hash, &sha1);
        //output = sha1_hash_string(hash, output);
        bin2hex(hash, sizeof(hash), output, MAX_HASH_LEN);
	    strcpy_s(hash_in,sizeof(hash_in),output);
		generate_cumulative_hash(output,1);
        fclose(file);
        free(buffer);
    }
    
	return output;
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
void tagEntry (char* line){
           
        char key[500];
		/*We use a local string 'key' here so that we dont make any changes
		to the line pointer passed to the function. 
		This is useful in a line containing more than 1 XML tag values.
		E.g :<Dir Path="/etc" include="*.bin" exclude="*.conf">
		*/
        int i =0;
        strcpy_s(key,sizeof(key),line);
        char  *start,*end;
         
		while(key[i] != '\"')
            i++;
        start = &key[++i];
        end = start;
        while(*end != '\"')
            end++;
        *end = '\0';
        /*NodeValue is a global variable that holds the XML tag value
		at a given point of time. 
		Its contents are copied after its new value addition immediately
		*/
		strcpy_s(NodeValue,sizeof(NodeValue),start);
        
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
static void generateLogs(const char *origManifestPath, char *imagePath, char *verificationType){
  
    FILE *fp, *fq, *fd; 
    char * line = NULL;
    char include[128] = {'\0'};
    char exclude[128] = { '\0'};
	char recursive[16] = {'\0'};
	char recursive_cmd[32] = {'\0'};
    size_t len = 0;
    char calc_hash[MAX_HASH_LEN] = {'\0'};
    char ma_result_path[256] = {'\0'};
	//memset_s(ma_result_path,sizeof(ma_result_path),'/0');
    char ma_result_path_default[100]="/var/log/trustagent/measurement.xml";
    int digest_check  = 0;

    if(strcmp(verificationType,"HOST") == 0)
      snprintf(ma_result_path, sizeof(ma_result_path), "%s%s", fs_mount_path, ma_result_path_default);
    else
      snprintf(ma_result_path, sizeof(ma_result_path), "%s%s",hash_file,"xml");

    
	DEBUG_LOG("%s %s","Manifest Path",origManifestPath);
    fp=fopen(origManifestPath,"r");
    if (fp != NULL) {
		fq=fopen(ma_result_path,"w");
		chmod(ma_result_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (fq != NULL) {
			fprintf(fq,"<?xml version=\"1.0\"?>\n");
			char * temp_ptr = NULL;
		   //Open Manifest to get list of files to hash
			while (getline(&line, &len, fp) != -1) {

			 strcpy_s(include,sizeof(include),"");
			 strcpy_s(exclude,sizeof(exclude),"");
			 strcpy_s(recursive,sizeof(recursive),"");
				  temp_ptr = NULL;
				  temp_ptr = strstr(line,"DigestAlg=");
				  if(temp_ptr != NULL){
				   /*Get the type of hash */
				   tagEntry(temp_ptr);
				   strcpy_s(hashType,sizeof(hashType),NodeValue);
				   digest_check = 1;
				   DEBUG_LOG("\n%s %s","Type of Hash used :",hashType);
				   fprintf(fq,"<Measurements xmlns=\"mtwilson:trustdirector:measurements:1.1\" DigestAlg=\"%s\">\n",hashType);
				 }


			 //File Hashes
				  if(strstr(line,"<File Path=")!= NULL && digest_check){
					tagEntry(line);
					char file_name_buff[1024] = {'\0'};
					snprintf(file_name_buff, sizeof(file_name_buff), "%s/%s", fs_mount_path, NodeValue);
					DEBUG_LOG("\nfile path : %s\n", file_name_buff);
					int retval = getSymLinkValue(file_name_buff);
					if ( retval == 0 )
					{
						//file exist

						fprintf(fq,"<File Path=\"%s\">",NodeValue);
						temp_ptr = calculate(NodeValue,calc_hash);
						if (temp_ptr != NULL) {
							fprintf(fq,"%s</File>\n", temp_ptr);
						}
						DEBUG_LOG("\n%s %s %s %s","File :",NodeValue,"Hash Measured:",calc_hash);
					}
					else {
						continue;
					}
				  }

			 //Directory Hashes
				  if(strstr(line,"<Dir ")!= NULL && digest_check){
						temp_ptr = NULL;
						temp_ptr = strstr(line, "Path=");
						char dir_path[500] = {'\0'};
						if (temp_ptr != NULL ) {
							tagEntry(temp_ptr);
							strcpy_s(dir_path,sizeof(dir_path),NodeValue);
						}
						DEBUG_LOG("\n%s %s","Directory :",NodeValue);
						temp_ptr = NULL;
						temp_ptr = strstr(line, "Include=");
						if (temp_ptr != NULL) {
							tagEntry(temp_ptr);
							strcpy_s(include,sizeof(include),NodeValue);
							DEBUG_LOG("\n%s %s","Include type :",NodeValue);
						}
						temp_ptr = NULL;
						temp_ptr = strstr(line,"Exclude=");
						if ( temp_ptr != NULL ) {
							tagEntry(temp_ptr);
							strcpy_s(exclude,sizeof(exclude),NodeValue);
							DEBUG_LOG("\n%s %s","Exclude type :",NodeValue);
						}
						temp_ptr=NULL;
						temp_ptr=strstr(line, "Recursive=");
						if ( temp_ptr != NULL ) {
							tagEntry(temp_ptr);
							strcpy_s(recursive,sizeof(recursive),NodeValue);
							DEBUG_LOG("\nRecursive : %s", NodeValue);
							if ( strcmp(recursive,"false") == 0) {
								snprintf(recursive_cmd, sizeof(recursive_cmd), "-maxdepth 1");
							}
						}

					char Dir_Str[256];

					char mDpath[256] = {'\0'};
					strcpy_s(mDpath,sizeof(mDpath),fs_mount_path);
					strcat_s(mDpath,sizeof(mDpath),dir_path);//path of dir in the VM

					//to remove mount path from the find command output and directory path and +1 is to remove the additional / after directory
					int slen = strnlen_s(mDpath,sizeof(mDpath)) + 1; 
					char hash_algo[15] = {'\0'};
					snprintf(hash_algo,sizeof(hash_algo),"%ssum",hashType);
					if(strcmp(include,"") != 0 && strcmp(exclude,"") != 0 )
					   snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" %s ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | grep -vE \"%s\" | %s",mDpath, recursive_cmd, slen, include, exclude, hash_algo);
					else if(strcmp(include,"") != 0)
					   snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" %s ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | %s",mDpath, recursive_cmd, slen, include, hash_algo);
					else if(strcmp(exclude,"") != 0)
					   snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" %s ! -type d | sed -r 's/.{%d}//' | grep -vE \"%s\" | %s",mDpath, recursive_cmd, slen, exclude, hash_algo);
					else
					   snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" ! -type d| sed -r 's/.{%d}//' | %s",mDpath,slen,hash_algo);

					/*char ops[200];
					snprintf(ops,sizeof(ops),"find \"%s\"/ ! -type d | sed -r 's/.{%d}//'",mDpath,slen);*/

					DEBUG_LOG("\n%s %s %s %s","********mDpath is ----------",mDpath," and command is ",Dir_Str);

					FILE *dir_file = popen(Dir_Str,"r");
					char *dhash = NULL;
					if (dir_file != NULL ) {
						getline(&dhash, &len, dir_file);
						size_t dhash_max = 128;
						char *next_token;
						strtok_s(dhash,&dhash_max," ",&next_token);
					}
					else {
						dhash = "\0";
					}

					fprintf(fq,"<Dir Path=\"%s\">",dir_path);
					fprintf(fq,"%s</Dir>\n",dhash);
					char outputBuffer[65];
					if(strcmp(hashType, "sha256") == 0)
					   generate_cumulative_hash(dhash,0);
					else
					   generate_cumulative_hash(dhash,1);

					if (dir_file != NULL) {
						pclose(dir_file);
					}

				  }//Dir hash ends

			}//While ends

			if(!digest_check){
				ERROR_LOG("%s","Hash Algorithm not specified!");
				//return -1 ?
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
    strcat_s(hash_file,sizeof(hash_file),hashType);
    /*Write the Cumulative Hash calculated to the file*/
    FILE *fc = fopen(hash_file,"w");
	chmod(hash_file, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fc == NULL ) {
    	ERROR_LOG("Can not open file: %s, to write cumulative hash", hash_file);
    	return;
    }
    char *ptr;
    if(strcmp(hashType, "sha256") == 0){
    	bin2hex(d2, sizeof(d2), cH2, sizeof(cH2));
    	ptr= cH2;
        //ptr = sha256_hash_string(d2,cH2);
    }
    else {
    	bin2hex(d1, sizeof(d1), cH2, sizeof(cH2));
    	ptr= cH2;
        //   ptr = sha1_hash_string(d1,cH2);
    }
    fprintf(fc,"%s",ptr);
    fclose(fc);
}

/*
 * Main function which checks for the different input parameters 
 * provided to the verifier and calls a xml parsing function
 */
int main(int argc, char **argv) {

    char manifest_file[256] = {'\0'};
    xmlDocPtr Doc;
    if(argc != 4) {
        ERROR_LOG("\n%s %s %s","Usage:",argv[0]," <manifest_path> <mounted_path> <IMVM/HOST>");
        return EXIT_FAILURE;
    }
    DEBUG_LOG("\n%s %s","MANIFEST-PATH :", argv[1]);
	DEBUG_LOG("\n%s %s","MOUNTED-PATH :", argv[2]);
	DEBUG_LOG("\n MODE : %s", argv[3]);
  
	strcpy_s(manifest_file,sizeof(manifest_file),argv[1]);
	strcpy_s(fs_mount_path,sizeof(fs_mount_path),argv[2]);
	strcat_s(fs_mount_path,sizeof(fs_mount_path),"/");
    memset_s((char *)cHash,strnlen_s((char *)cHash,sizeof(cHash)),0);
    if (strcmp(argv[3], "IMVM") == 0) {
    	char* last_oblique_ptr = strrchr(manifest_file, '/');
        //strncpy_s(hash_file,sizeof(hash_file),manifest_file,strlen(manifest_file)-strlen("/manifestlist.xml"));
    	strncpy_s(hash_file,sizeof(hash_file),manifest_file,strnlen_s(manifest_file,sizeof(manifest_file))-strnlen_s(last_oblique_ptr + 1, sizeof("/manifest.xml")));
    	strcat_s(hash_file,sizeof(hash_file),"/measurement.");
    } else if (strcmp(argv[3], "HOST") == 0) {
        snprintf(hash_file, sizeof(hash_file), "%s/var/log/trustagent/measurement.", fs_mount_path);
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
    generateLogs(argv[1], argv[2], argv[3]);
    
    return 0;
}













