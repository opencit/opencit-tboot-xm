#include <stdio.h>
#include <stdlib.h>
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
#include <nxjson.h>

#define MOUNTPATH_IMVM  "/tmp/mount/"
#define MOUNTPATH_HOST  "/root"
#define MAX_FILES       120000

int fileCount;
char fs_mount_path[1024];
char array[MAX_FILES][1024];
char exclude_file[MAX_FILES][1024];
int exclude_file_count = 0;
char *hidden;
char *hashType;
char *policy;
unsigned char* signature;
char *document;

unsigned char* manifestHash;

char imageHash[256];
char customerID[256];
char imageID[256];
char rpID[256];
char kernelHash[256];
char initrdHash[256];
char kernelPath[512];
char initrdPath[512];
static char nodeName[256];
int imageHashOnly = 0;
char value[512];
int imageMountingRequired = 0;
char *delimiter = "###";


/*
 * injectRpParams:
 * @imagePath : path of the vm image
 * @rp_id : ID from RPCore
 *
 * Injects RP_ID, RP_PORT and RP_IPADDRESS into the VM image
 */
void injectRpParams() {

        char command[512];
        char rp_id_env[256], image_id_env[256], customer_id_env[256], image_hash_env[256], signature_env[512];        
        //sprintf(command,"../../scripts/mount_vm_image.sh %s", imagePath);
        //system(command);
        mkdir("/tmp/mount/etc/rpcore/", 0777);
        FILE *fp = fopen("/tmp/mount/etc/rpcore/rp.cfg","ab+");
        system("echo \"RPCORE_IPADDRESS=`echo $RPCORE_IPADDR`\" > /tmp/mount/etc/rpcore/rp.cfg");
        system(" echo \"RPCORE_PORT=`echo $RPCORE_PORT`\" >> /tmp/mount/etc/rpcore/rp.cfg");
        snprintf(rp_id_env, sizeof rp_id_env, "%s%s%s", "RP_ID", "=", rpID);
        snprintf(image_id_env, sizeof image_id_env, "%s%s%s", "VM_IMAGE_ID", "=", imageID);
        snprintf(customer_id_env, sizeof customer_id_env, "%s%s%s", "VM_CUSTOMER_ID", "=", customerID);
        snprintf(image_hash_env, sizeof image_hash_env, "%s%s%s", "VM_MANIFEST_HASH", "=", imageHash);
        snprintf(signature_env, sizeof signature_env, "%s%s%s", "VM_MANIFEST_SIGNATURE", "=", signature);
        fprintf(fp,"%s",rp_id_env);
        fprintf(fp,"\n%s",image_id_env);
        fprintf(fp,"\n%s",customer_id_env);
        fprintf(fp,"\n%s",image_hash_env);
        fprintf(fp,"\n%s",signature_env);
        fclose(fp);
        //system("../../scripts/mount_vm_image.sh");
}


/*
 * load_file:
 * @filepath : path of the file
 *
 * Returns the contents of the file 
 */
static char* load_file(const char* filepath) {
  struct stat st;
  if (stat(filepath, &st)==-1) {
    printf("can't find file %s\n", filepath);
    return 0;
  }
  int fd=open(filepath, O_RDONLY);
  if (fd==-1) {
   printf("can't open file %s\n", filepath);
    return 0;
  }
  char* text=malloc(st.st_size+1);
  if (st.st_size!=read(fd, text, st.st_size)) {
    printf("can't read file %s\n", filepath);
    close(fd);
    return 0;
  }
  close(fd);
  text[st.st_size]='\0';
  return text;
}


/*
 * getSymLinkValue:
 * @path : path of the file/symbolic link
 *
 * Returns the actual value for the symbolic link provided as input
 */
void getSymLinkValue(char *path) {
    struct stat p_statbuf;
    char actualpath [512];
    char symlinkpath[512];
    if (lstat(path, &p_statbuf) < 0) {  /* if error occured */
    }

	// Check if the file path is a symbolic link
    if (S_ISLNK(p_statbuf.st_mode) ==1) {
            // If symbolic link doesn't exists read the path its pointing to
            int len = readlink(path, symlinkpath, sizeof(symlinkpath));
            if (len != -1) {
                symlinkpath[len] = '\0';
            }

            // If the path is starting with "/" and 'fs_mount_path' is not appended
            if(((strstr(symlinkpath, "/") - symlinkpath) == 0) && (strstr(symlinkpath,fs_mount_path) == NULL)) {
                char sympathroot[512];
                snprintf(sympathroot, sizeof sympathroot, "%s%s", fs_mount_path, symlinkpath);
                getSymLinkValue(sympathroot);
            }
            else if(((strstr(symlinkpath, ".") - symlinkpath) == 0) || ((strstr(symlinkpath, "..") - symlinkpath) == 0) || ((strstr(symlinkpath, "/") - symlinkpath) != 0)){
                char sympathroot[512];
                char* last_backslash = strrchr(path, '/'); 
                if (last_backslash) {
                    *last_backslash = '\0';
                }
                snprintf(sympathroot, sizeof sympathroot, "%s%s%s", path, "/", symlinkpath);
                getSymLinkValue(sympathroot);
            }
            else {
                strcpy(value,"NOT EXIST");
            }
    }
    else {
        // Copy the new path, which the symbolic link is actually referring to
        strcpy(value, path);		
    }       
}


/*
 * sha256_hash_string:
 * @hash : hash value for the file
 *
 * Store hash of file in "fileHashes.txt"
 */
char* sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65], int type) {
    int i;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    if (type == 0) {
        FILE *fp = fopen("fileHashes.txt","a");
        fprintf(fp,"%s\n",outputBuffer);
        fclose(fp);
    }
    return outputBuffer;
}


/*
 * sha1_hash_string:
 * @hash : hash value for the file
 *
 * Store hash of file in "fileHashes.txt"
 */
char* sha1_hash_string (unsigned char hash[SHA_DIGEST_LENGTH], char outputBuffer[65], int type)
{
    int i = 0;
    for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    if (type == 0) {
        FILE *fp = fopen("fileHashes.txt","a");
        fprintf(fp,"%s\n",outputBuffer);
        fclose(fp);
    }
    return outputBuffer;
}


/*
 * calculate:
 * @path : path of the file
 * @output : character array for storing the resulted file hash
 *
 * Calculate hash of file
 */
char* calculate(char *path, char output[65], int type) {
    struct stat p_statbuf;
    //strcpy(value, path);
    char *token;
    char buf[512];
    strcpy(buf, path);
    strcpy(value, path);
    if ((strcmp(path,"fileHashes.txt") != 0) && (strcmp(path,"dirHashes.txt") != 0) && (strcmp(path,initrdPath) != 0) && (strcmp(path,kernelPath) != 0)) {
        token = strtok(buf, delimiter);   
        token = strtok(NULL, delimiter);
        strcpy(value, token);
    }

    FILE* file = fopen(value, "rb");
    if(!file) return NULL;

    if(strcmp(hashType, "SHA-256") == 0) {
        // Using SHA256 algorithm for hash calculation
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        const int bufSize = 32768;
        char* buffer = malloc(bufSize);
        int bytesRead = 0;
        if(!buffer) return NULL;
        while((bytesRead = fread(buffer, 1, bufSize, file))) {
            SHA256_Update(&sha256, buffer, bytesRead);
        }
        SHA256_Final(hash, &sha256);
        output = sha256_hash_string(hash, output, type);
        fclose(file);
        free(buffer);
    }
    else {
        // Using SHA1 algorithm for hash calculation
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA_CTX sha1;
        SHA1_Init(&sha1);
        const int bufSize = 32768;
        char* buffer = malloc(bufSize);
        int bytesRead = 0;
        if(!buffer) return NULL;
        while((bytesRead = fread(buffer, 1, bufSize, file))) {
            SHA1_Update(&sha1, buffer, bytesRead);
        }
        SHA1_Final(hash, &sha1);
        output = sha1_hash_string(hash, output, type);
        fclose(file);
        free(buffer);
    }
    return output;
}	


/*
 * calc_sha:
 * @arrayList : global array containing all the files under a particular directory
 * @output : character array for storing the resulted file hash
 * 
 * Iterate over the global array and calls a function for 
 * calculating hash of every element of the array
 */
int calc_sha (char arrayList[fileCount][1024], char output[65]) {
    char line[1000];
    int z;    
    // Iterating over the array of files
    for (z = 0; z < fileCount; z++){
        strcpy(line, arrayList[z]);
        // Function call to calculate hash of each file
        calculate(line, output, 0);
    }
    return 0;
}


/*
 * sortCompare:
 *
 * Compare array elements and sort them
 */
int sortCompare(const void *arg1, const void *arg2){
    return strcmp(arg1,arg2);
}


/*
 * sort:
 *
 * Sort the array of files in acsending order
 */
int sort() {
    remove("fileHashes.txt");
    char calc_hash[65];
    // qsort() used for sorting
    qsort(array, (size_t)fileCount, 1024, sortCompare);
    // Function call to calculate hashes of sorted array elements
    calc_sha(array, calc_hash);
    return 0;
}


/*
 * listFile:
 * @path : directory path
 * @filter : filter value used for the directory
 *
 * Add the file with the given file name along with 
 * the full path to the array if the path/file exists
 */
void listFile(char *path, char *origPath, char slash, char* name, char *filter) {
    char buf[512];
    char origBuf[512];
    char symlinkpath[512];
    char actualpath [512];
    char *ptr;
    struct stat p_statbuf;
    int flag = 0;

    strcpy(buf, path);
    strcpy(origBuf, origPath);
    strcpy(value, buf);	

    if (lstat(value, &p_statbuf) < 0) {  /* if error occured */
    }
	
    // Check if the path is a symbolic link or not
    if (S_ISLNK(p_statbuf.st_mode) == 1) {
        // Function call to getSymLinkValue() 
        getSymLinkValue(value);
    }
    // Else append fs_mount_path to the path, if not already appended 
    else {
        char actualpath[512];
        char *res = realpath(buf, actualpath);
        if (res) {
            if (strstr(actualpath,fs_mount_path) == NULL){
                char sympathroot[512];
                snprintf(sympathroot, sizeof sympathroot, "%s%s", fs_mount_path, actualpath);
                strcpy(value, sympathroot);
            }
        } else {
            strcpy(value,"NOT EXIST");
        }
    }

    if (lstat(value, &p_statbuf) < 0) {  /* if error occured */
    }

    if (S_ISDIR(p_statbuf.st_mode) == 1) {
	    strcpy(value,"NOT EXIST");
    }

    // If all the files needs to be verified
    if (strcmp(filter, "*") == 0) {	
        // Check if the file exists or not
        if((access(value, F_OK) == 0)) {
            char sympath[512];
            strcpy(sympath, buf);
            ptr = realpath(buf, actualpath);
            // Append fs_mount_path to the real path, if not already appended
            if (strstr(actualpath,fs_mount_path) == NULL){
                char sympathroot[512];
                snprintf(sympathroot, sizeof sympathroot, "%s%s", fs_mount_path, actualpath);
                strcpy(sympath, sympathroot);
            }
            stat(ptr, &p_statbuf);
            if (S_ISDIR(p_statbuf.st_mode)) {
                flag = 1;
            }
			
            if((flag == 0) && !isExcludeFile(origBuf)) {
                // Copying the file path to the global array
                char file[512];
                snprintf(file, sizeof file, "%s%s%s", origBuf, delimiter, value);
                strcpy(array[fileCount], file);
                // Incrementing the counter
                fileCount++;
            }
        }
    }

    // If only the binary files needs to be verified
    else if (strcmp(filter, "binary") == 0) {	
        // Check if the disk image was a Windows or Ubuntu/Linux one
        if (0 != access("/tmp/mount//Windows/System32/ntoskrnl.exe", F_OK)) {
            // Check if the file exists and is a binary file
            if((access(value, X_OK) == 0) && (access(value, F_OK) == 0)) {
                char sympath[512];
                strcpy(sympath, buf);
                ptr = realpath(buf, actualpath);
                // Append fs_mount_path to the real path, if not already appended
                if (strstr(actualpath,fs_mount_path) == NULL) {
                    char sympathroot[512];
                    snprintf(sympathroot, sizeof sympathroot, "%s%s", fs_mount_path, actualpath);
                    strcpy(sympath, sympathroot);
                }
                stat(ptr, &p_statbuf);
                if (S_ISDIR(p_statbuf.st_mode)) {
                    flag = 1;
                }

                if((flag == 0) && !isExcludeFile(origBuf)) {
                    char file[512];
                    snprintf(file, sizeof file, "%s%s%s", origBuf, delimiter, value);
                    // Copying the file path to the global array
                    strcpy(array[fileCount], file);
                    // Incrementing the counter
                    fileCount++;
                }
            }
        }
        // For Windows image, check for binary files
        else {
            FILE *fp = fopen(buf,"rb+");
            const int bufSize = 2;
            char* buffer = malloc(bufSize);
            fread(buffer, 1, bufSize, fp);
            // 'MZ' as first two bytes for a binary file in windows image
            if ((strstr(buffer, "MZ") != NULL)) {
                char sympath[512];
                strcpy(sympath, buf);
                ptr = realpath(buf, actualpath);
                // Append fs_mount_path to the real path, if not already appended
                if (strstr(actualpath,fs_mount_path) == NULL) {
                    char sympathroot[512];
                    snprintf(sympathroot, sizeof sympathroot, "%s%s", fs_mount_path, actualpath);
                    strcpy(sympath, sympathroot);
                }
                stat(ptr, &p_statbuf);
                if (S_ISDIR(p_statbuf.st_mode)) {
                    flag = 1;
                }

                if((flag == 0) && !isExcludeFile(origBuf)) {
                    char file[512];
                    snprintf(file, sizeof file, "%s%s%s", origBuf, delimiter, value);
                    // Copying the file path to the global array
                    strcpy(array[fileCount], file);
                    // Incrementing the counter
                    fileCount++;
                }
            }
            free(buffer);
            fclose(fp);
        }
    }
    // If files with some specific extension(.txt,.sh etc) needs to be verified
    else {
        char *token;
        char filt[512];
        char *name_new;
        strcpy(filt, filter);
        // Tokenizing the filter value using ";" as a field separator
        token = strtok(filt, ";");

        while (token != NULL) {
            name_new = strrchr(name, '.');
            if( name_new != NULL ) {	
                // Check if the file extension matches with any of the token
                if(strcmp(name_new, token) == 0) {
                    // Check if the file exists
                    if((access(value, F_OK) == 0)) {
                        char sympath[512];
                        strcpy(sympath, buf);
                        ptr = realpath(buf, actualpath);
                        // Append fs_mount_path to the real path, if not already appended
                        if (strstr(actualpath,fs_mount_path) == NULL){
                            char sympathroot[512];
                            snprintf(sympathroot, sizeof sympathroot, "%s%s", fs_mount_path, actualpath);
                            strcpy(sympath, sympathroot);
                        }
                        stat(ptr, &p_statbuf);
                        if (S_ISDIR(p_statbuf.st_mode)) {
                            flag = 1;
                        }

                        if((flag == 0) && !isExcludeFile(origBuf)) {
                            char file[512];
                            snprintf(file, sizeof file, "%s%s%s", origBuf, delimiter, value);
                            // Copying the file path to the global array
                            strcpy(array[fileCount], file);
                            // Incrementing the counter
                            fileCount++;
                        }
                    }
                }
            }
            token = strtok(NULL, ";");
        }

    }
}



/*
 * listDir_helper:
 * @path : directory path
 * @count : file count under the directory
 * @hash : hash of the directory
 * @filter : filter value used for the directory
 * @hidden : flag to check whether to include hidden files or not
 *
 * List the files under a particular directory
 * and store it in a global array
 */
int listDir_helper(char* path, char *realPath, char* count, char* hash, char* filter, char* hidden) {
    char slash = '/';
    DIR* dir;
    struct dirent *ent;
    struct stat p_statbuf;
    char *NulPosition_real = &realPath[strlen(realPath)];
    char *NulPosition = &path[strlen(path)];
    if ((dir = opendir(realPath)) != NULL) {
        // Continues until all the entries in the directory are visited
        while ((ent = readdir(dir)) != NULL) {
            // Check if the entry is a directory or a symbolic link to a directory
            if ((ent->d_type == DT_DIR)) {	
                // Check if hidden flag is set to true,
                // means to include hidden directory or not
                if (strcmp(hidden,"true") == 0) {
                    if ((strcmp(ent->d_name, ".") != 0) && (strcmp(ent->d_name, "..") != 0)) {
                        sprintf(NulPosition, "%c%s", slash, ent->d_name);
                        sprintf(NulPosition_real, "%c%s", slash, ent->d_name);
                        // Recursively calls the listDir_helper with new path value
                        if (listDir_helper(path, realPath, count, hash, filter, hidden)) {
                            closedir(dir);
                            return 1;
                        }
                        *NulPosition = '\0';
                        *NulPosition_real = '\0';
                    }
                }
                // For excluding the hidden directory
                else {
                    if ((ent->d_name[0] != '.') &&(strcmp(ent->d_name, ".") != 0) && (strcmp(ent->d_name, "..") != 0)) {
                        sprintf(NulPosition, "%c%s", slash, ent->d_name);
                        sprintf(NulPosition_real, "%c%s", slash, ent->d_name);
                        // Recursively calls the listDir_helper with new path value
                        if (listDir_helper(path, realPath, count, hash, filter, hidden)) {
                            closedir(dir);
                            return 1;
                        }
                        *NulPosition = '\0';
                        *NulPosition_real = '\0';
                    }
                }
            }

            else if (ent->d_type == DT_LNK) {
                char sympathroot[512];
                char path_new[512];
                char realPath_new[512];
                char *ptr;
                char actualpath [512];
                ptr = realpath(path, actualpath);
                snprintf(sympathroot, sizeof sympathroot, "%s%c%s", realPath, slash, ent->d_name);
                strcpy(path_new, sympathroot);
                int len = readlink(path_new, realPath_new, sizeof(realPath_new));
                struct stat p_statbuf;
                if (len != -1) {
                    realPath_new[len] = '\0';
                }
                if(((strstr(realPath_new, "/") - realPath_new) == 0) && (strstr(realPath_new,fs_mount_path) == NULL)) {
                    char sympathroot[512];
                    snprintf(sympathroot, sizeof sympathroot, "%s%s", fs_mount_path, realPath_new);
                    strcpy(realPath_new, sympathroot);
                }
                else if(((strstr(realPath_new, ".") - realPath_new == 0) || ((strstr(realPath_new, "..") - realPath_new) == 0) || ((strstr(realPath_new, "/") - realPath_new) != 0))){
                    char sympathroot[512];
                    char path_new[512];
                    strcpy(path_new, path);
                    snprintf(sympathroot, sizeof sympathroot, "%s%s%s", path_new, "/", realPath_new);
                    strcpy(realPath_new, sympathroot);
                }

                if (lstat(realPath_new, &p_statbuf) < 0) {  /* if error occured */
                }

                if (S_ISDIR(p_statbuf.st_mode) == 1) {
                    char path1[512];
                    char path2[512];
                    char path3[512];
                    char path4[512];
                    snprintf(path4, sizeof path4, "%s%s%s", path, "/", ent->d_name);
                    snprintf(path3, sizeof path3, "%s%s%s", realPath, "/", ent->d_name);
                    char *res = realpath(path4, path1);
                    if(res){}
                    else {
                       strcpy(path1, "NOT EXIST");
                    }
                    realpath(path3, path2);

                    if((strcmp(path1, path2) != 0) && (strcmp(path1, "NOT EXIST") != 0)) {
                        if (strcmp(hidden,"true") == 0) {
                            if ((strcmp(ent->d_name, ".") != 0) && (strcmp(ent->d_name, "..") != 0)) {

                                sprintf(NulPosition, "%c%s", slash, ent->d_name);
                                // Recursively calls the listDir_helper with new path value
                                if (listDir_helper(path, realPath_new, count, hash, filter, hidden)) {
                                    closedir(dir);
                                    return 1;
                                }
                                *NulPosition = '\0';
                            }
                        }
                        // For excluding the hidden directory
                        else {
                            if ((ent->d_name[0] != '.') &&(strcmp(ent->d_name, ".") != 0) && (strcmp(ent->d_name, "..") != 0)) {
                                 sprintf(NulPosition, "%c%s", slash, ent->d_name);
                                // Recursively calls the listDir_helper with new path value
                                if (listDir_helper(path, realPath_new, count, hash, filter, hidden)) {
                                    closedir(dir);
                                    return 1;
                                }
                                *NulPosition = '\0';
                            }
                        }
                    }
                }
                else {
                     // For including the hidden files
                     if (strcmp(hidden, "true") == 0) {
                         char path_new[512];
                         snprintf(path_new, sizeof path_new, "%s%c%s", path, slash, ent->d_name);
                         // Function call to add this file entry to the array of files
                         listFile(realPath_new, path_new, slash, ent->d_name, filter);
                    }
                    else {
                        if ((ent->d_name[0] != '.')){
                            char path_new[512];
                            snprintf(path_new, sizeof path_new, "%s%c%s", path, slash, ent->d_name);
                            // Function call to add this file entry to the array of files
                            listFile(realPath_new, path_new, slash, ent->d_name, filter);
                        }
                    }
                }
            }

            else if(((ent->d_type == DT_REG) || ((ent->d_type == DT_UNKNOWN)))) {
                // For including the hidden files
                if (strcmp(hidden, "true") == 0) {
                    char realPath_new[512];
                    char path_new[512];
                    snprintf(realPath_new, sizeof realPath_new, "%s%c%s", realPath, slash, ent->d_name);
		    snprintf(path_new, sizeof path_new, "%s%c%s", path, slash, ent->d_name);
                    // Function call to add this file entry to the array of files
                    listFile(realPath_new, path_new, slash, ent->d_name, filter);
                }
                else {
                    if ((ent->d_name[0] != '.')){
                        char realPath_new[512];
                        char path_new[512];
                        snprintf(realPath_new, sizeof realPath_new, "%s%c%s", realPath, slash, ent->d_name);
                        snprintf(path_new, sizeof path_new, "%s%c%s", path, slash, ent->d_name);
                        // Function call to add this file entry to the array of files
                        listFile(realPath_new, path_new, slash, ent->d_name, filter);
                    }
                }	
            }
       } 
   }
    closedir(dir);
    return 0;
}


/*
 * listDir:
 * @path : directory path 
 * @count : file count under the directory
 * @hash : hash of the directory
 * @filter : filter value used for the directory
 * @hidden : flag to check whether to include hidden files or not
 *
 * Calls a function to list the files under a particular directory 
 * and checks if file count and dir hash matches or not
 */
int listDir(char* path, char* count, char* hash, char* filter, char* hidden) {
    struct dirent *ent;
    int z;
    char calc_hash[256];
    char c[20];
    char pathmax[MAXPATHLEN+1+sizeof(ent->d_name)+1];
    char pathmax_copy[MAXPATHLEN+1+sizeof(ent->d_name)+1];
    FILE *fp = fopen("dirHashes.txt","a");

    fileCount = 0;
    if (strlen(path) > MAXPATHLEN) return 1;
    strcpy(pathmax, path);
    strcpy(pathmax_copy, path);

    // Function call to list the files under the directory
    listDir_helper(pathmax, pathmax_copy, count, hash, filter, hidden);
    sprintf(c, "%d", fileCount);
    //printf("listDir  :: %s %s %s %s %s %s\n", pathmax, count, hash, filter, hidden, imageHash);
    //printf("COUNTTTTT: %d : %s", fileCount, count);

    // Check if the file count matches with the one in the manifest file for this particular directory
    if( strcmp(count,c) != 0 ) {
        printf("fail - count mismatch for directory %s, expected=%s, actual=%s\n", pathmax, count, c);
        //printf("IMVM Verification Failed!\n");
        //system("../../scripts/mount_vm_image.sh");
        //return -1;
    } else {
        printf("file count successfull for directory %s, count=%s\n", pathmax, count);
    }

    if (fileCount == 0) {
        FILE *fp = fopen("fileHashes.txt","w");
        fclose(fp);
    } else {
        // Sort the array of files(containing all the files under a particular directory) in ascending order using qsort()
        sort();
    }

    fprintf(fp,"%s\n",calculate("fileHashes.txt", calc_hash, 1));
    fclose(fp);

    // Comparing the calculated directory hash with the one in the manifest file
    if ((strcmp(hash,calculate("fileHashes.txt", calc_hash, 1)) != 0)) {
        printf("fail - dir hash mismatch for directory %s\n", pathmax);
        //printf("IMVM Verification Failed!\n");
        //system("../../scripts/mount_vm_image.sh");
        //return -1;
    } else {
        printf("dir hash match successfull for directory %s\n", pathmax);
    }
    return 0;
}


/**
 * processNode:
 * @reader: the xmlReader
 * @imagePath: Path of the image to be mounted
 *
 * Dump information about the current node
 */
void processNode(xmlTextReaderPtr reader, char *imagePath) {
    xmlChar *name;
    xmlChar *value;
    int nodeType;

    // Getting the name of the xml node
    name = xmlTextReaderName(reader);
    if (name == NULL)
        name = BAD_CAST "--";

    if (strcmp(name,"#text") != 0 ) {
        strcpy(nodeName, name);
    }

    nodeType = xmlTextReaderNodeType(reader);

    // Getting the value of the xml node
    value = xmlTextReaderValue(reader);

    // Extracting the "Launch policy" tag from manifest and storing its value into a global variable
    if ((strcmp(nodeName,"Launch_Policy") ==0)  && (value != NULL) && (nodeType == XML_TEXT_NODE)) {
        policy = value;
        printf("Launch policy used = %s\n",(char*)value);
    }
   
    // Extracting the "hash type" tag from manifest and storing its value into a global variable
    if ((strcmp(nodeName,"Hash_Type") ==0)  && (value != NULL) && (nodeType == XML_TEXT_NODE)) {
        hashType = value;
        printf("hash algorithm used = %s\n",(char*)value);
    }

    // Extracting the "hidden files" tag from manifest and storing its value into a global variable
    if ((strcmp(nodeName,"Hidden_Files") == 0) && (value != NULL) && (nodeType == XML_TEXT_NODE)) {
        hidden = value;
        printf("include hidden files = %s\n",(char*)value);
    }

    // Extracting the "image hash" tag from manifest and storing its value into a global variable
    if ((strcmp(nodeName,"Image_Hash") == 0)  && (value != NULL) && (nodeType == XML_TEXT_NODE)) {
        strcpy(imageHash, value);
        printf("expected image hash = %s\n",(char*)value);
    }

    // Extracting the "image id" tag from manifest and storing its value into a global variable
    if ((strcmp(nodeName,"Image_ID") == 0)  && (value != NULL) && (nodeType == XML_TEXT_NODE)) {
        strcpy(imageID, value);
    }

    // Extracting the "customer id" tag from manifest and storing its value into a global variable
    if ((strcmp(nodeName,"Customer_ID") == 0)  && (value != NULL) && (nodeType == XML_TEXT_NODE)) {
        strcpy(customerID, value);
    }

    // Check for the "file hashes" tag and mounting the image if tag is present
    if (strcmp(nodeName,"File_Hashes") == 0) {
        if (imageMountingRequired == 0) {
            char command[512];
            sprintf(command,"../../scripts/mount_vm_image.sh %s", imagePath);
            int res = system(command);
            if (res !=0) {
                printf("\nError in mounting the image!!!!\n");
                exit(1);
            }
            // Injecting certain params into the VM image         
            //injectRpParams();    
            printf("\nVM_IMAGE_ID=%s",imageID);
            printf("\nVM_CUSTOMER_ID=%s",customerID);
            printf("\nVM_MANIFEST_HASH=%s",imageHash);
            printf("\nVM_MANIFEST_SIGNATURE=%s",signature);
        }
        FILE *fp = fopen("dirHashes.txt","a");
        fclose(fp);
        imageHashOnly = 1;
    }

    // Extracting the "kernel hash" tag from manifest and storing its value into a global variable
    if ((strcmp(nodeName,"Kernel_Hash") == 0)  && (value != NULL) && (nodeType == XML_TEXT_NODE)) {
        strcpy(kernelHash, value);
        printf("expected kernel hash = %s\n",(char*)value);
    }    
    
    // Extracting the "initrd hash" tag from manifest and storing its value into a global variable
    if ((strcmp(nodeName,"Initrd_Hash") == 0)  && (value != NULL) && (nodeType == XML_TEXT_NODE)) {
        strcpy(initrdHash, value);
        printf("expected initrd hash = %s\n",(char*)value);
    }

    xmlNodePtr node = xmlTextReaderCurrentNode(reader);

    // Checks if the node has some attributes/properties assosiated with it
    if (xmlTextReaderNodeType(reader) == 1 && node && node->properties && xmlStrEqual(node->name, "Dir")) {
        xmlAttr* attribute = node->properties;
        int count = 0;
        char *loc = fs_mount_path;
        char *dirPath, *dirHash, *fileCount, *filter;
        while(attribute && attribute->name && attribute->children) {
            xmlChar* value = xmlNodeListGetString(node->doc, attribute->children, 1);

            // Name of the directory
            if (xmlStrEqual(attribute->name, "name")) {
                dirPath = malloc(256*sizeof(char));
                dirPath = value;
                count++;
            }
            // File count under the directory
            else if (xmlStrEqual(attribute->name, "file_count")) {
                fileCount = malloc(256*sizeof(char));
                fileCount = value;
                count++;
            }
            // Hash of the directory
            else if (xmlStrEqual(attribute->name, "dir_hash")) {
                dirHash = malloc(256*sizeof(char));
                dirHash = value;
                count++;
            }
            // Filter(all files, only binaries or some custom extensions) used for the directory
            else if (xmlStrEqual(attribute->name, "filter")) {
                filter = malloc(256*sizeof(char));
                filter = value;
                count++;
            }

            if (count == 4) {
                char path[256];
                int ret;
                snprintf(path, sizeof path, "%s%s", loc, dirPath);
                // Calls a function that will list the files under particular directory
                ret = listDir(path, fileCount, dirHash, filter, hidden);
                if (ret < 0)
                    exit(0);
            }
            attribute = attribute->next;
        }
    } 
}


/**
 * isExcludeFile:
 * @fileName: name of the file
 *
 * Check if the given file needs to be excluded during the verification process
 */
int isExcludeFile(char* fileName) {
    int i=0, found=0;
    for(i=0; i<exclude_file_count; i++) {
        char file_new[512];
        snprintf(file_new, sizeof file_new, "%s%s", fs_mount_path, exclude_file[i]);
        if (strcmp(fileName, file_new) == 0) {
            printf("will exclude %s\n", exclude_file[i]);
            found = 1;
            break;
        }
    }
    return found;
}


/**
 * populateExcludeFileArray:
 * @fileName: name of the file
 *
 * Populating an array of files containing all the files to be excluded during verification
 */
void populateExcludeFileArray (const char *filename) {
    xmlDoc *doc = NULL;
    doc = xmlReadFile(filename, NULL, XML_PARSE_HUGE);

    if (doc == NULL) {
        printf("error: could not parse file %s\n", filename);
        exit(1);
    }

    xmlNode *root = xmlDocGetRootElement(doc);
    xmlNode *cur_node = NULL, *inner_node = NULL, *filenode = NULL;
    char* exclude_filepath;
    exclude_file_count = 0;

    for (cur_node = root->children; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE && xmlStrEqual(cur_node->name, "File_Hashes")) {
            for (inner_node = cur_node->children; inner_node; inner_node = inner_node->next) {
                if (inner_node->type == XML_ELEMENT_NODE && xmlStrEqual(inner_node->name, "Measurement_Exclude_Files")) {
                    filenode = inner_node->children;
                    while (filenode != NULL) {
                        if (filenode->type != XML_ELEMENT_NODE)
                            filenode = filenode->next;
                        exclude_filepath = (char*) xmlNodeGetContent(filenode);
                        printf("Excluded file %s\n", exclude_filepath);
                        strcpy(exclude_file[exclude_file_count], exclude_filepath);
                        exclude_file_count++;
                        filenode = filenode->next;
                    }
                }
            }
        }
    }
    xmlFreeDoc(doc);
    xmlCleanupParser();
}


/**
 * verifySignature:
 * @publicKeyFP : file containing the public key
 * @dataFileFP  : file containing the document value
 * @sigFileFP   : file containing the signature part
 *
 * Verifies the manifest signature
 */
int verifySignature(FILE * publicKeyFP, FILE * dataFileFP, FILE * sigFileFP)
{
    RSA *rsa_pkey = NULL;
    EVP_PKEY *pkey;
    EVP_MD_CTX ctx;
    unsigned char buffer[4096];
    size_t len;
    unsigned char *sig;
    unsigned int siglen;
    struct stat stat_buf;

    if (!PEM_read_RSA_PUBKEY(publicKeyFP, &rsa_pkey, NULL, NULL)) {
        fprintf(stderr, "Error loading RSA public Key File.\n");
        return 2;
    }
    pkey = EVP_PKEY_new();


    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey)) {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        return 3;
    }
    /* Read the signature */
    if (fstat(fileno(sigFileFP), &stat_buf) == -1) {
        fprintf(stderr, "Unable to read signature \n");
        return 4;
    }
    siglen = stat_buf.st_size;
    sig = (unsigned char *)malloc(siglen);
    if (sig == NULL) {
        fprintf(stderr, "Unable to allocated %d bytes for signature\n",
            siglen);
        return 5;
    }
    if ((fread(sig, 1, siglen, sigFileFP)) != siglen) {
        fprintf(stderr, "Unable to read %d bytes for signature\n",
            siglen);
        return 6;
    }

    EVP_MD_CTX_init(&ctx);

    if (!EVP_VerifyInit(&ctx, EVP_sha256())) {
        fprintf(stderr, "EVP_SignInit: failed.\n");
        EVP_PKEY_free(pkey);
        return 7;
    }

    while ((len = fread(buffer, 1, sizeof(buffer), dataFileFP)) != '\0') {
        buffer[len-1]='\0';
        if (!EVP_VerifyUpdate(&ctx, buffer, (int)len - 1)) {
            fprintf(stderr, "EVP_SignUpdate: failed.\n");
            EVP_PKEY_free(pkey);
            return 8;
        }
    }

    if (ferror(dataFileFP)) {
        perror("input file");
        EVP_PKEY_free(pkey);
        return 9;
    }

    if (!EVP_VerifyFinal(&ctx, sig, siglen, pkey)) {
        fprintf(stderr, "EVP_VerifyFinal: failed.\n");
        free(sig);
        EVP_PKEY_free(pkey);
        return 10;
    }
    free(sig);
    EVP_PKEY_free(pkey);
    return 0;
}


int calcDecodeLength(const char* b64input) { //Calculates the length of a decoded base64 string
    int len = strlen(b64input);
    int padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    return (int)len*0.75 - padding;
}


/**
 * Base64Decode:
 * @b64message: base64 encoded message
 * @buffer: buffer to store the base64 decoded message
 *
 * Base64 decoding of the signature part.
*/
int Base64Decode(char* b64message, unsigned char** buffer) { //Decodes a base64 encoded string
    BIO *bio, *b64;
    int decodeLen = calcDecodeLength(b64message),
    len = 0;
    *buffer = (char*)malloc(decodeLen+1);
    FILE* stream = fmemopen(b64message, strlen(b64message), "r");

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    len = BIO_read(bio, *buffer, strlen(b64message));
    //Can test here if len == decodeLen - if not, then return an error
    (*buffer)[len] = '\0';

    BIO_free_all(bio);
    fclose(stream);

    return (0); //success
}


/**
 * parseSignatureXml:
 * @fileName: name of the file with signature
 *
 * Get the value of Signature and Document tag
 */
void parseSignatureXml (const char *filename) {
    xmlDoc *doc = NULL;
    doc = xmlReadFile(filename, NULL, XML_PARSE_HUGE);

    if (doc == NULL) {
        printf("error: could not parse file %s\n", filename);
        exit(1);
    }

    xmlNode *root = xmlDocGetRootElement(doc);
    xmlNode *cur_node = NULL, *filenode = NULL;

    for (cur_node = root->children; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE && xmlStrEqual(cur_node->name, "signature")) {
            filenode = cur_node->children;
            signature = (char*) xmlNodeGetContent(filenode);
            printf("Signature : %s\n", signature);
            filenode = filenode->next;
        }
        if (cur_node->type == XML_ELEMENT_NODE && xmlStrEqual(cur_node->name, "document")) {
            filenode = cur_node->children;
            document = (char*) xmlNodeGetContent(filenode);
            printf("Document : %s\n", document);
            filenode = filenode->next;
        }
    }
    xmlFreeDoc(doc);
    xmlCleanupParser();
}


/**
 * streamFile:
 * @filename: the file name to parse
 * @imagePath: the image disk to be mounted
 *
 * Parse XML file.
*/
static void streamFile(const char *origManifestPath, char *imagePath, char *verificationType, char* mtwPubKeyFile) {
    xmlTextReaderPtr reader;
    int ret;
    char calc_hash[256];
    char *manifestPath = "/tmp/manifest.xml";

    remove("dirHashes.txt");
    remove("fileHashes.txt");
    xmlKeepBlanksDefault(0);

    char command[512];

    sprintf(command,"cat %s | awk -F '</Manifest>' '{print $2}' > signature.xml ; cat %s | sed 's/<manifest_signature>.*//g' | tr -d '\n' > temp-manifest ; mv temp-manifest %s", origManifestPath, origManifestPath, manifestPath);
    system(command);

// Uncomment the below part for verfication of the manifest file

    parseSignatureXml("signature.xml");
  
    unsigned char* base64DecodeOutput;
    FILE *dataFileFP, *publicKeyFP, *sigFileFP, *privateKeyFP, *outFileFP;
    unsigned int res;

    struct stat stat_buf;
    unsigned int hashlen;
    char cal_hash[256], *manifestHashEncode;

    publicKeyFP = fopen(mtwPubKeyFile, "r");

    if (publicKeyFP == NULL) {
        printf("Couldn't open pub key file %s\n", mtwPubKeyFile);
        exit(1);
    }


    OpenSSL_add_all_digests();

    //Base64Decode(signature, &base64DecodeOutput);

    FILE *fp = fopen("signature","w+");
    fprintf(fp,"%s",signature);
    fclose(fp);
    FILE *fptr = fopen("document-value","w+");
    fprintf(fptr,"%s\n",document);
    fclose(fptr);

    system("base64 -d signature > signature-base64-decoded");

    dataFileFP = fopen("document-value", "r");
    sigFileFP = fopen("signature-base64-decoded", "r");
    res=verifySignature(publicKeyFP, dataFileFP, sigFileFP);

    // Remove temporary files
    remove("signature");
    remove("signature.xml");
    remove("signature-base64-decoded");

    if (res != 0) {
        printf("Manifest Signature Verification Unsuccessful!!!!\n");
        exit(1);
    }
    else {
        // Parse the document-value json to extract the manifest file hash
        char* jsonText=load_file("document-value");
        const nx_json* json=nx_json_parse(jsonText, 0);
        if (json) {
            manifestHashEncode=nx_json_get(json, "manifest_hash")->text_value;
            printf("Manifest Hash value encoded with base64 is : %s\n", nx_json_get(json, "manifest_hash")->text_value);
            Base64Decode(manifestHashEncode, &manifestHash);
            printf("Manifest Hash value is : %s\n", manifestHash);
            nx_json_free(json);
        }

        // Compare the manifest hash(from MtW response) with actual manifest file hash
        remove("fileHashes.txt");
        remove("document-value");
        sprintf(command,"cp %s fileHashes.txt", manifestPath);
        hashType = "SHA-256";
        system(command);        
        printf("Original manifest hash is : %s\n",calculate("fileHashes.txt", cal_hash, 1));
        if ( strcmp(manifestHash,calculate("fileHashes.txt", cal_hash, 1)) != 0 ) {
            printf("Manifest Signature Verification Unsuccessful!!!!, Manifest File Hash Mismatch!!!!\n");
            remove("fileHashes.txt");
            exit(1);
        }
        printf("Manifest Signature Verification Successful!!!!\n");
    }
    // Remove temporary files
    remove("fileHashes.txt");

    populateExcludeFileArray(manifestPath);
    reader = xmlReaderForFile(manifestPath, NULL, XML_PARSE_HUGE);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            processNode(reader, imagePath);
            ret = xmlTextReaderRead(reader);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            fprintf(stderr, "%s : failed to parse\n", manifestPath);
            exit(1);
        }
    } else {
        fprintf(stderr, "Unable to open %s\n", manifestPath);
        exit(1);
    }

    // Comparing the calculated kernel and ramdisk hash with the one in the manifest file
    if ((strcmp(kernelHash,"") != 0) && (strcmp(initrdHash,"") != 0)) {
        FILE *fp = fopen("dirHashes.txt","a");
        if ( strcmp(kernelHash,calculate(kernelPath, calc_hash, 1)) == 0 )
            fprintf(fp,"%s\n",calculate(kernelPath, calc_hash, 1));
        else {
            printf("fail - kernel hash mismatch\n");
            //printf("IMVM Verification Failed!");
            //system("../../scripts/mount_vm_image.sh");
            //exit(0);
        }
        if ( strcmp(initrdHash,calculate(initrdPath, calc_hash, 1)) == 0 )
            fprintf(fp,"%s\n",calculate(initrdPath, calc_hash, 1));
        else {
            printf("fail - initrd hash mismatch\n");
            //printf("IMVM Verification Failed!\n");
            //system("../../scripts/mount_vm_image.sh");
            //exit(0);
        }
        fclose(fp);
    }
    // If manifest file contains only the hash of complete image,
    // compare the complete image hash with the one in the manifest file
    if (imageHashOnly == 0 && imageMountingRequired == 1) {
        if ( strcmp(imageHash,calculate(imagePath, calc_hash, 1)) != 0 ) {
            printf("fail - image hash mismatch\n");
            printf("IMVM Verification Failed!\n");
            system("../../scripts/mount_vm_image.sh");
            exit(0);
        }
        else {
            char *finalHash = calculate(imagePath, calc_hash, 1);
            printf("pass - %s\n", calculate(imagePath, calc_hash, 1));
            printf("IMVM Verification Successfull!\n\n\n");
            if(strcmp(hashType, "SHA-256") == 0) {
                unsigned char hash[SHA_DIGEST_LENGTH];
                char output[65];
                SHA_CTX sha1;
                SHA1_Init(&sha1);
                SHA1_Update(&sha1, (unsigned char *)finalHash, strlen(finalHash));
                SHA1_Final(hash, &sha1);
                printf("SHA-256-IMAGE-HASH:%s\n",finalHash);
                printf("SHA-1-IMAGE-HASH:%s\n\n",sha1_hash_string(hash, output, 1));
            } else {
                unsigned char hash[SHA256_DIGEST_LENGTH];
                char output[65];
                SHA256_CTX sha256;
                SHA256_Init(&sha256);
                SHA256_Update(&sha256, (unsigned char *)finalHash, strlen(finalHash));
                SHA256_Final(hash, &sha256);
                printf("SHA-256-IMAGE-HASH:%s\n",sha256_hash_string(hash, output, 1));
                printf("SHA-1-IMAGE-HASH:%s\n\n",finalHash);
            }
        }
    }

    // If directory hashes are also included in the manifest file,
    // then compare calculated dir hash with the one in the manifest file
    else if ( strcmp(imageHash,calculate("dirHashes.txt", calc_hash, 1)) != 0 ) {
        printf("fail - cumulative directory hash mismatch\n");
        printf("IMVM Verification Failed!\n");
        system("../../scripts/mount_vm_image.sh");
        exit(0);
    }
    else {
        char *finalHash = calculate("dirHashes.txt", calc_hash, 1);
        printf("pass - %s\n", calculate("dirHashes.txt", calc_hash, 1));
        printf("IMVM Verification Successfull!\n\n\n");
        if(strcmp(hashType, "SHA-256") == 0) {
             unsigned char hash[SHA_DIGEST_LENGTH];
             char output[65];
             SHA_CTX sha1;
             SHA1_Init(&sha1);
             SHA1_Update(&sha1, (unsigned char *)finalHash, strlen(finalHash));
             SHA1_Final(hash, &sha1);
             printf("SHA-256-IMAGE-HASH:%s\n",finalHash);
             printf("SHA-1-IMAGE-HASH:%s\n\n",sha1_hash_string(hash, output, 1));
        } else {
             unsigned char hash[SHA256_DIGEST_LENGTH];
             char output[65];
             SHA256_CTX sha256;
             SHA256_Init(&sha256);
             SHA256_Update(&sha256, (unsigned char *)finalHash, strlen(finalHash));
             SHA256_Final(hash, &sha256);
             printf("SHA-256-IMAGE-HASH:%s\n",sha256_hash_string(hash, output, 1));
             printf("SHA-1-IMAGE-HASH:%s\n\n",finalHash);
        }
    }
}

/*
 * Main function which checks for the different input parameters 
 * provided to the verifier and calls a xml parsing function
 */
int main(int argc, char **argv) {

    if((argc != 6) && (argc != 8)) {
        printf("Usage:\n%s <manifest_path> <disk_path> <verification_type(IMVM/HOST)> <mt_wilson_pub_key_path> <rp_id> <kernel_path> <initrd_path>\n", argv[0]);
        printf("Last two arguments are optional\n");
        return EXIT_FAILURE;
    }

    // Checks if kernel and ramdisk path are also provided separately as input.
    if (argc == 8) {
        strcpy(kernelPath, argv[6]);
        strcpy(initrdPath, argv[7]);
        printf("KERNEL-PATH : %s\n", argv[6]);
        printf("INITRD-PATH : %s\n", argv[7]);
    }
    printf("MANIFEST-PATH : %s\n", argv[1]);
    printf("DISK-PATH : %s\n", argv[2]);

    if (strcmp(argv[3], "IMVM") == 0) {
        strcpy(fs_mount_path, MOUNTPATH_IMVM);
        imageMountingRequired = 0;
    } else if (strcmp(argv[3], "HOST") == 0) {
        strcpy(fs_mount_path, MOUNTPATH_HOST);
        imageMountingRequired = 1;
    } else {
        printf("Invalid verification_type. Valid options are IMVM/HOST\n");
        return EXIT_FAILURE;
    }
  
    strcpy(rpID, argv[5]);
 
    // Function call for parsing the manifest file provided as input
    streamFile(argv[1], argv[2], argv[3], argv[4]);
    xmlCleanupParser();
    xmlMemoryDump();

    // Unmount the disk image after verification process completes
    if (strcmp(argv[3], "IMVM") == 0) {
        system("../../scripts/mount_vm_image.sh");
    }
    return 0;
}
