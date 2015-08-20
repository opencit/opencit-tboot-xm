/* Measurement Agent - Litev2
@SRK 
Intel Corp - CSS-DCG 
Hard requirements: Manifest should be named manifestlist.xml - Parameters should be passed on command line using the entire file/directory path
Keywords in the Policy should match with those in this code : DigestAlg, File Path, Dir, sha1 and sha256
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#ifdef __linux__
#include <linux/limits.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <dirent.h>
#include <sys/param.h>
#elif _WIN32
#include <Windows.h>
#include <processthreadsapi.h>
#include <WinBase.h>
#include <bcrypt.h>
#include <WinIoCtl.h>
#include <xmllite.h>
#endif
//#include <libxml/xmlreader.h>

#ifdef __linux__
#define MOUNTPATH_IMVM  "/tmp/"
#define MOUNTPATH_HOST  "/tmp/root"
#elif _WIN32
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define MOUNTPATH_IMVM  "../temp"
#define MOUNTPATH_HOST  "../temp/root"

#define malloc(size) HeapAlloc(GetProcessHeap(), 0, size)
#define free(mem_ptr) HeapFree(GetProcessHeap(),0, mem_ptr)
typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG  Flags;
			WCHAR  PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR  PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR DataBuffer[1];
		} GenericReparseBuffer;
	};
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;
#endif

int ISLINK(char *);
int readlink(char *, char *, int);

#define DEBUG_LOG(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__);
#define ERROR_LOG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__);
#define snprintf _snprintf
#define popen _popen
#define pclose _pclose

char fs_mount_path[1024];
char hashType[10]; //SHA1 or SHA256
char NodeValue[500]; //XML Tag value

/*These global variables are required for calculating the cumulative hash */
#ifdef __linux__
unsigned char cHash[SHA_DIGEST_LENGTH]; //Cumulative hash
unsigned char cHash2[SHA256_DIGEST_LENGTH];
unsigned char d1[SHA_DIGEST_LENGTH]={0};
unsigned char d2[SHA256_DIGEST_LENGTH]={0};
char cH2[65];
SHA256_CTX csha256;
SHA_CTX csha1;
#endif
char hash_file[256];
int process_started = 0;

#ifdef _WIN32
static BCRYPT_ALG_HANDLE       handle_Alg = NULL;
static BCRYPT_HASH_HANDLE      handle_Hash_object = NULL;
static NTSTATUS                status = STATUS_UNSUCCESSFUL;
static DWORD                   out_data_size = 0,
								hash_size = 0,
								hashObject_size = 0;
static PBYTE                   hashObject_ptr = NULL;
static PBYTE                   hash_ptr = NULL;

/*
Cleanup the CNG api
return : 0 for success or failure status
*/
void cleanup_CNG_api() {
	if (handle_Alg) {
		BCryptCloseAlgorithmProvider(handle_Alg, 0);
	}
	if (handle_Hash_object) {
		BCryptDestroyHash(handle_Hash_object);
	}
	if (hashObject_ptr) {
		free(hashObject_ptr);
	}
	if (hash_ptr) {
		free(hash_ptr);
	}
}

/*
open Crypto Algorithm Handle, allocate buffer for hashObject and hash buffer,
and create hash object
return : 0 for success or failure status
*/
int setup_CNG_api() {
	// Open algorithm
	if (strcmp(hashType, "sha256") == 0) {
		status = BCryptOpenAlgorithmProvider(&handle_Alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);	
	}
	else {
		status = BCryptOpenAlgorithmProvider(&handle_Alg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
	}
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api();
		return status;
	}

	//calculate the size of buffer of hashobject
	status = BCryptGetProperty(handle_Alg, BCRYPT_OBJECT_LENGTH, (PBYTE )&hashObject_size, sizeof(DWORD), &out_data_size, 0);
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api();
		return status;
	}
	hashObject_ptr = (PBYTE)malloc(hashObject_size*sizeof(BYTE));
	memset(hashObject_ptr, 0, hashObject_size*sizeof(BYTE));
	if (hashObject_ptr == NULL) {
		cleanup_CNG_api();
		return -1;
	}
	//calculate the size of buffer of hash
	status = BCryptGetProperty(handle_Alg, BCRYPT_HASH_LENGTH, (PBYTE)&hash_size, sizeof(DWORD), &out_data_size, 0);
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api();
		return status;
	}
	hash_ptr = (PBYTE)malloc(hash_size*sizeof(BYTE));
	memset(hash_ptr, 0, hash_size*sizeof(BYTE));
	if (hash_ptr == NULL){
		cleanup_CNG_api();
		return -1;
	}
	//create hashobject 
	status = BCryptCreateHash(handle_Alg, &handle_Hash_object, hashObject_ptr, hashObject_size, NULL, 0, 0);
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api();	
	}
	return status;
}

/*
Calculate the hash and update it in global Hash Object
return : 0 for success or failure status
*/
int calc_and_update_hash_CNG_api(char *input) {
	status = BCryptHashData(handle_Hash_object, input, strlen(input), 0);
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api();
	}
	return status;
}

/*
dump the final hash in global hash_ptr, and finish the Hash Object handle
 and cleanup CNG api
return : 0 for success or failure status
*/
int finalize_hash_CNG_api() {
	status = BCryptFinishHash(handle_Hash_object, hash_ptr, hash_size, 0);
	cleanup_CNG_api();
	return status;
}

/*
Cleaup the CNG api,
Close and Destroy the handle, free the allocated memory for hash Object and hash buffer
return: error number
*/
void cleanup_CNG_api_args(BCRYPT_ALG_HANDLE * handle_Alg, BCRYPT_HASH_HANDLE *handle_Hash_object, PBYTE* hashObject_ptr, PBYTE* hash_ptr) {
	int err = 0;
	if (*handle_Alg) {
		BCryptCloseAlgorithmProvider(*handle_Alg, 0);
	}
	if (*handle_Hash_object) {
		BCryptDestroyHash(*handle_Hash_object);
	}
	if (*hashObject_ptr) {
		free(*hashObject_ptr);
	}
	if (*hash_ptr) {
		free(*hash_ptr);
	}
}

/*
*setup_CNG_api_args() : initialise the CNG api and set the algorithm handle *handle_Alg, hash Object Handle in *handle_Hash_object,
*allocate the memory for hash object buffer and hash buffer,
*set the size possible size of buffer of hash Object and Hash buffer

*return : 0 for success or failure status
*/
int setup_CNG_api_args(BCRYPT_ALG_HANDLE * handle_Alg, BCRYPT_HASH_HANDLE *handle_Hash_object, PBYTE* hashObject_ptr, int * hashObject_size,PBYTE* hash_ptr, int * hash_size ) {
	// Open algorithm
	int out_data_size;
	if (strcmp(hashType, "sha256") == 0) {
		status = BCryptOpenAlgorithmProvider(handle_Alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	}
	else {
		status = BCryptOpenAlgorithmProvider(handle_Alg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
	}
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api_args(handle_Alg, handle_Hash_object, hashObject_ptr, hash_ptr);
		return status;
	}

	//calculate the size of buffer of hashobject
	status = BCryptGetProperty(*handle_Alg, BCRYPT_OBJECT_LENGTH, (PBYTE)hashObject_size, sizeof(DWORD), &out_data_size, 0);
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api_args(handle_Alg, handle_Hash_object, hashObject_ptr, hash_ptr);
		return status;
	}	

	*hashObject_ptr = (PBYTE)malloc(*hashObject_size);
	if (hashObject_ptr == NULL) {
		cleanup_CNG_api_args(handle_Alg, handle_Hash_object, hashObject_ptr, hash_ptr);
		return -1;
	}
	//calculate the size of buffer of hash
	status = BCryptGetProperty(*handle_Alg, BCRYPT_HASH_LENGTH, (PBYTE)hash_size, sizeof(DWORD), &out_data_size, 0);
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api_args(handle_Alg, handle_Hash_object, hashObject_ptr, hash_ptr);
		return status;
	}
	*hash_ptr = (PBYTE)malloc(*hash_size);
	if (*hash_ptr == NULL) {
		cleanup_CNG_api_args(handle_Alg, handle_Hash_object, hashObject_ptr, hash_ptr);
		return -1;
	}
	//create hashobject 
	status = BCryptCreateHash(*handle_Alg, handle_Hash_object, *hashObject_ptr, *hashObject_size, NULL, 0, 0);
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api_args(handle_Alg, handle_Hash_object, hashObject_ptr, hash_ptr);
		
	}
	return status;
}

#endif

/*
 * sha256_hash_string: convert a sha256 hash to char string
 * @hash : hash value for the file
 * @hash_size : size of the hash value passed in char size
 * @outputBuffer : pointer to buffer to store the converted hash, enough memory must be allocated to beforehand
 * Store hash of file in "fileHashes.txt"
 */
char* sha256_hash_string (unsigned char* hash, int hash_size, char* outputBuffer) {
    int i;	
    for(i = 0; i < hash_size; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    return outputBuffer;
}
/* 
 * sha1_hash_string:
 * @hash : hash value for the file
 * @hash_size : size of the hash value passed in char size
 * @outputBuffer : pointer to buffer to store the converted hash, enough memory must be allocated to beforehand
 * Store hash of file in "fileHashes.txt"
 */
char* sha1_hash_string (unsigned char* hash, int hash_size, char* outputBuffer)
{
    int i = 0;
    for(i = 0; i < hash_size; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
   return outputBuffer;
}

/*This function keeps track of the cumulative hash and stores it in a global variable (which is later written to a file) */
void generate_cumulative_hash(char *hash,int sha_one){
    DEBUG_LOG("\nIncoming Hash : %s\n",hash);
#ifdef _WIN32
	calc_and_update_hash_CNG_api(hash);
#elif __linux__
	char ob[65];
    if(sha_one){
	   strncpy(cHash,d1,SHA_DIGEST_LENGTH);
	   DEBUG_LOG("\n%s %s", "Cumulative Hash before:", sha1_hash_string(cHash, SHA_DIGEST_LENGTH,ob));
		  
	   SHA1_Init(&csha1);
	   SHA1_Update(&csha1,d1,SHA_DIGEST_LENGTH);
	   SHA1_Update(&csha1,hash,strlen(hash));
	   SHA1_Final(d1,&csha1);
		   
	   strncpy(cHash,d1,SHA_DIGEST_LENGTH);
	   DEBUG_LOG("\n%s %s", "Cumulative Hash after is:", sha1_hash_string(cHash, SHA_DIGEST_LENGTH,ob));
	   
	   memset(ob,'\0',strlen(ob));
	   return;
	}
	
	else{
	   
	   strncpy(cHash2,d2,SHA256_DIGEST_LENGTH);
	   DEBUG_LOG("\n%s %s", "Cumulative Hash before:", sha256_hash_string(cHash2, SHA256_DIGEST_LENGTH,ob));
	   
	   SHA256_Init(&csha256);
	   SHA256_Update(&csha256,d2,SHA256_DIGEST_LENGTH);
	   SHA256_Update(&csha256,hash,strlen(hash));
	   SHA256_Final(d2, &csha256);
	  
	   strncpy(cHash2,d2,SHA256_DIGEST_LENGTH);
	   DEBUG_LOG("\n%s %s", "Cumulative Hash after is:", sha256_hash_string(cHash2, SHA256_DIGEST_LENGTH,ob));
	   
	   memset(ob,'0',strlen(ob));
	   
	   return;
		
	}
#endif	   
}

#ifdef _WIN32

/*
*next_available_logical_dirve(): generate a next valid dirve name in case of windows where drive can be mounted
*return: next available valid Drive letter in char
*/ 
char next_available_logical_drive() {
	int sizeof_drive_buf = 128;
	char drive_name_present[128];
	memset(drive_name_present, 0, sizeof_drive_buf);
	int total_drive_size = GetLogicalDriveStrings(sizeof_drive_buf, drive_name_present);
	if (total_drive_size == 0) {
		return NULL;
	}
	char drives[24];
	memset(drives, 0, 24);
	int drives_count = 0;
	int i,j = -1;
	for (i = 0 ; i < total_drive_size; i++) {
		if (drive_name_present[i] == '\0') {
			//drives[drives_count] = (char *)malloc(sizeof(char) * (i - j));
			//memcpy(drives[drives_count], drive_name_present, i - j);
			drives[drives_count] = drive_name_present[j + 1];
			j = i;
			drives_count++;
		}
	}
	
	char drive_char = NULL, drive_str[2];
	drive_str[0] = 'D';
	drive_str[1] = '\0';
	for (drive_char = 'D'; drive_char <= 90; drive_char++, drive_str[0] = drive_char) {
		if (strstr(drives, drive_str) == NULL) {
			return drive_char;
		}
	}
	return NULL;
}

/*
*ISLINK(): check whether passed path is link or not 
*@path : pointer to path 
*return : return 0, if path is link otherwise 1. If error occured it will return negative value
*/
int ISLINK(char *path) {
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	int islink = 1;
	hFind = FindFirstFile(path, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		ERROR_LOG("\nFindFirstFile failed (%d)\n", GetLastError());
		return -1;
	}
	else {
		DEBUG_LOG("\nFOUND FILE : %s", FindFileData.cFileName);
		if (FindFileData.dwFileAttributes == FILE_ATTRIBUTE_REPARSE_POINT) {
			DEBUG_LOG("\nfile contains reparse point ...");
			islink = 0;
		}
		else if (FindFileData.dwFileAttributes == FILE_ATTRIBUTE_ARCHIVE || FindFileData.dwFileAttributes == 33) {
			DEBUG_LOG("\nfile contains directory reparse point ...");
			islink = 0;
		}
		else if (FindFileData.dwReserved0 == IO_REPARSE_TAG_SYMLINK) {
			DEBUG_LOG("\nfile is a symbolic link to file ...");
			islink = 0;
		}
		else if (IO_REPARSE_TAG_MOUNT_POINT == FindFileData.dwReserved0) {
			DEBUG_LOG("\nthis file is JUNCTION ...");
			islink = 0;
		}
		DEBUG_LOG("%d\n", FindFileData.dwFileAttributes);
	}
	return islink;
}

/*
*readlink(): read target of link passed 
*@path: path of the file whose target link we want
*@target_buf : char * buffer for target, if target buff is not long enough to store it reallocates memory for it,
*@target_buf_size : size of char * buffer passed
*retur : if successfull size of target in terms of char, else return negative value in case of error
*/
int readlink(char *path, char *target_buf, int target_buf_size) {
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	hFind = FindFirstFile(path, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		ERROR_LOG("\nFindFirstFile failed (%d)\n", GetLastError());
		return -1;
	}
	else {
		DEBUG_LOG("\nFOUND FILE : %s", FindFileData.cFileName);
		if (FindFileData.dwFileAttributes == FILE_ATTRIBUTE_REPARSE_POINT) {
			DEBUG_LOG("\nfile contains reparse point ...");
		}
		else if (FindFileData.dwFileAttributes == FILE_ATTRIBUTE_ARCHIVE) {
			DEBUG_LOG("\nfile contains directory reparse point ...");
		}
		else if (FindFileData.dwReserved0 == IO_REPARSE_TAG_SYMLINK) {
			DEBUG_LOG("\nfile is a symbolic link to file ...");
		}
		else if (IO_REPARSE_TAG_MOUNT_POINT == FindFileData.dwReserved0) {
			DEBUG_LOG("\nthis file is JUNCTION ...");
		}
		DEBUG_LOG("%d\n", FindFileData.dwFileAttributes);
		HANDLE target_handle = CreateFile(path, FILE_GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL, NULL);
		if (target_handle == INVALID_HANDLE_VALUE) {
			ERROR_LOG("couldn't get handle to file");
			return -2;
		}
		int req_size = 32767 + 8;
		char *_buffer;
		_buffer = (char *)malloc(sizeof(wchar_t)* req_size + sizeof(REPARSE_DATA_BUFFER));
		REPARSE_DATA_BUFFER *reparse_buffer;
		reparse_buffer = (REPARSE_DATA_BUFFER *)(_buffer);
		DWORD reparse_buffer_read_size = 0;
		DeviceIoControl(target_handle, FSCTL_GET_REPARSE_POINT, NULL, 0, reparse_buffer, sizeof(REPARSE_DATA_BUFFER) + req_size, &reparse_buffer_read_size, NULL);
		WCHAR *w_complete_path_pname = NULL, *w_complete_path_sname = NULL;
		char *complete_path_pname = NULL, *complete_path_sname = NULL;
		int clength = -1, wlength = -1;
		if (reparse_buffer->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
			//its a symbolic link
			DEBUG_LOG("\n unparsed length : %d", reparse_buffer->Reserved);
			if (reparse_buffer->SymbolicLinkReparseBuffer.Flags == 0) {
				DEBUG_LOG("\nabsolute path : length : %d", reparse_buffer->SymbolicLinkReparseBuffer.Flags);
			}
			else {
				DEBUG_LOG("\nrelative path : length : %d", reparse_buffer->SymbolicLinkReparseBuffer.Flags);
			}
			wlength = reparse_buffer->SymbolicLinkReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1;
			w_complete_path_pname = (WCHAR *)malloc(sizeof(WCHAR) * wlength);
			lstrcpynW(w_complete_path_pname, reparse_buffer->SymbolicLinkReparseBuffer.PathBuffer + (reparse_buffer->SymbolicLinkReparseBuffer.PrintNameOffset / sizeof(WCHAR)),
				reparse_buffer->SymbolicLinkReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1);
			wprintf(L"\n wide char Path : %s", w_complete_path_pname);
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, 0, 0, 0, 0);
			complete_path_pname = (char *)malloc(sizeof(CHAR)* clength);
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, complete_path_pname, clength, 0, 0);
			if (clength == 0) {
				ERROR_LOG("\n conversion from wchar to char fails");
				target_buf_size = -1;
				goto return_target_link;
			}
			DEBUG_LOG("\nchar path print name : %s", complete_path_pname);

			//appending unparsed path
			if (strlen(target_buf) > 0) {				
				int target_buf_length = strlen(complete_path_pname) + (strlen(path) - reparse_buffer->Reserved);
				if (target_buf_length > target_buf_size) {
					realloc(target_buf, target_buf_length);
					target_buf_size = target_buf_length;
				}
				//target_buf = (char *)malloc(target_buf_length * sizeof(char));
				strcpy(target_buf, complete_path_pname);		
				strcat(target_buf, (path + (strlen(path) - reparse_buffer->Reserved)));
				//return target_buf_size;
				goto return_target_link;
			}

			//extract name from substitutestring
			wlength = reparse_buffer->SymbolicLinkReparseBuffer.SubstituteNameLength;
			w_complete_path_sname = (WCHAR *)malloc(sizeof(WCHAR)*wlength);
			lstrcpynW(w_complete_path_sname, reparse_buffer->SymbolicLinkReparseBuffer.PathBuffer + (reparse_buffer->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)),
				reparse_buffer->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR) + 1);

			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, 0, 0, 0, 0);
			complete_path_sname = (char *)malloc(sizeof(CHAR) * clength);
			if (complete_path_sname == NULL) {
				ERROR_LOG(" can't allocate memory for sustitute string name");
				target_buf_size = -3;
				goto return_target_link;
				//return -3;
			}
			memset(complete_path_sname, 0, clength);
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, complete_path_sname, clength, 0, 0);
			if (clength == 0) {
				ERROR_LOG("\n conversion from wchar to char failed");
				if (strlen(complete_path_pname) == 0) {
					target_buf_size = -3;
					goto return_target_link;
				}
				//	return -3;
			}
			DEBUG_LOG("\nchar path substitute name : %s", complete_path_sname);
			
			//need to remove \\?\ from path
			int target_buf_length = strlen(complete_path_sname) + (strlen(path) - reparse_buffer->Reserved);
			if (target_buf_length > target_buf_size) {
				realloc(target_buf, target_buf_length);
				target_buf_size = target_buf_length;
			}
			//target_buf = (char *)malloc(target_buf_length * sizeof(char));
			if (strstr(complete_path_sname, "\\\\?\\") != NULL) {
				// if it contains windows convention of preceding "\\?\" in path
				strcpy(target_buf, &complete_path_sname[4]);
			}
			else {
				//if its a relative path
				strcpy(target_buf, complete_path_sname);
			}
			strcat(target_buf, (path + (strlen(path) - reparse_buffer->Reserved)));
			DEBUG_LOG("\nafter adding unparsed path : %s", target_buf);
		}
		else if (reparse_buffer->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
			// its junction or mount point
			DEBUG_LOG("\n unparsed length : %d", reparse_buffer->Reserved);
			wlength = reparse_buffer->MountPointReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1;
			w_complete_path_pname = (WCHAR *)malloc(sizeof(WCHAR) * wlength);
			lstrcpynW(w_complete_path_pname, reparse_buffer->MountPointReparseBuffer.PathBuffer + (reparse_buffer->MountPointReparseBuffer.PrintNameOffset / sizeof(WCHAR)),
				reparse_buffer->MountPointReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1);
			wprintf(L"\n wide char Path : %s", w_complete_path_pname);

			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, 0, 0, 0, 0);
			if (clength > target_buf_size) {
				realloc(target_buf, clength);
				if (target_buf == NULL) {
					target_buf_size = -3;
					goto return_target_link;
					//return -3;
				}
				target_buf_size = clength;
			}
			//complete_path_pname = (char *)malloc(sizeof(CHAR)* clength);
			memset(target_buf, 0, clength);
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, target_buf, clength, 0, 0);
			if (clength == 0) {
				ERROR_LOG("\n conversion from wchar to char fails");
				target_buf_size = -1;
				goto return_target_link;
				//return -1;
			}
			DEBUG_LOG("\nchar path print name : %s", target_buf);
			if (strlen(target_buf) > 0) {
				goto return_target_link;
				//return target_buf_size;
			}
			//extract name from substitutestring
			wlength = reparse_buffer->MountPointReparseBuffer.SubstituteNameLength;
			w_complete_path_sname = (WCHAR *)malloc(sizeof(WCHAR)*wlength);
			lstrcpynW(w_complete_path_sname, reparse_buffer->MountPointReparseBuffer.PathBuffer + (reparse_buffer->MountPointReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)),
				reparse_buffer->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR) + 1);

			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, 0, 0, 0, 0);
			if (clength > target_buf_size) {
				realloc(target_buf, clength);
				target_buf_size = clength;
			}
			//complete_path_sname = (char *)malloc(sizeof(CHAR) * clength);
			if (target_buf == NULL) {
				ERROR_LOG("reallocation for memroy failed");
				target_buf_size = -3;
				goto return_target_link;
				//return -3;
			}
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, target_buf, clength, 0, 0);
			if (clength == 0) {
				ERROR_LOG("\n conversion from wchar to char failed");
				target_buf_size = -2;
				goto return_target_link;
				//return -2;
			}
			//TODO remove \\?\ from target_buf
			if (strstr("\\\\?\\", target_buf) != NULL) {
				memmove(target_buf, target_buf + 4, clength - 4);
			}
			DEBUG_LOG("\nchar path substitute name : %s", target_buf);

		}
		else{
			//this gives the complete path when path contains an junction in it
			int target_len = GetFinalPathNameByHandle(target_handle, target_buf, target_buf_size, VOLUME_NAME_DOS);
			if (target_len >= target_buf_size){
				realloc(target_buf, target_len);
				target_buf_size = target_len;
				if (target_buf == NULL){
					ERROR_LOG("\ncan't reallocate memory for target buff");
					target_buf_size = -3;
					goto return_target_link;
					//return -3;
				}
				target_len = GetFinalPathNameByHandle(target_handle, target_buf, target_buf_size, VOLUME_NAME_DOS);
				//todo remove \\?\ from target
			}
			if (strstr("\\\\?\\", target_buf) != NULL) {
				memmove(target_buf, target_buf + 4, target_len - 3);
			}
			DEBUG_LOG("size of target : %d \ntarget of link is : %s", target_len, target_buf);
		}
	return_target_link:
		if (_buffer) {
			free(_buffer);
		}
		if (w_complete_path_pname) {
			free(w_complete_path_pname);
		}
		if (w_complete_path_sname) {
			free(w_complete_path_sname);
		}
		if (complete_path_pname) {
			free(complete_path_pname);
		}
		if (complete_path_sname){
			free(complete_path_sname);
		}
		return target_buf_size;
	}
}
#endif

/* 
 * getSymLinkValue:
 * @path : path of the file/symbolic link
 *
 * Returns the actual value for the symbolic link provided as input
 */
int getSymLinkValue(char *path) {
    struct stat p_statbuf;
    //char symlinkpath[512];
	char *symlinkpath;
	int symlinkpath_size = 512;
            // Check if the file path is a symbolic link
	symlinkpath = (char *)malloc(sizeof(char)*symlinkpath_size);
#ifdef __linux__
	if (lstat(path, &p_statbuf) < 0) {  /* if error occured */
		ERROR_LOG("\n%s %s", "Not valid path -", path);
		return -1;
	}
    if (S_ISLNK(p_statbuf.st_mode) ==1) {
            // If symbolic link doesn't exists read the path its pointing to
            int len = readlink(path, symlinkpath, symlinkpath_size);
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
            strcpy(path, sympathroot);
            return getSymLinkValue(path);
    }
#elif _WIN32
	if (ISLINK(path) == 0) {
		// If symbolic link doesn't exists read the path its pointing to
		int len = readlink(path, symlinkpath, symlinkpath_size);
		if (len < 0) {
			ERROR_LOG("Error occured in reading link");
			return 0;
		}
		DEBUG_LOG("\n%s %s %s %s", "Symlink", path, " points to", symlinkpath);
		//("Symlink '%s' points to '%s' \n", path, symlinkpath);
		char *sympathroot;
		sympathroot = (char *)malloc(sizeof(char)* len);
		if (sympathroot == NULL) {
			return 0;
		}
		// If the path is starting with "/" and 'fs_mount_path' is not appended
		if (((strstr(symlinkpath, ":") - symlinkpath) == 1) && (strstr(symlinkpath, fs_mount_path) == NULL)) {
			snprintf(sympathroot, len, "%s%s", fs_mount_path, symlinkpath + 2);
			DEBUG_LOG("\n%s %s %s %s", "Absolute symlink path", symlinkpath, "points to", sympathroot);
			//printf("Absolute symlink path '%s' points to '%s'\n", symlinkpath, sympathroot);
		}
		else {
			char* last_backslash = strrchr(path, '\\');
			if (last_backslash) {
				*last_backslash = '\0';
			}
			snprintf(sympathroot, len, "%s%s%s", path, "/", symlinkpath);
			DEBUG_LOG("\n%s %s %s %s", "Relative symlink path", symlinkpath, "points to", sympathroot);
			//printf("Relative symlink path '%s' point to '%s'\n", symlinkpath, sympathroot);
		}
		strcpy(path, sympathroot);
		return getSymLinkValue(path);
	}
#endif
    return 0;
}
 /*
 * calculate:
 * @path : path of the file
 * @output : character array for storing the resulted file hash
 *
 * Calculate hash of file
 */
char* calculate(char *path, char output[65]) {
	const int bufSize = 65000;
	char *buffer = malloc(bufSize);
	int bytesRead = 0;
	if (!buffer) return NULL;

    char hash_in[65];
    char value[512];
    /*We append the mount path before the filepath first, 
	 and then pass that address to calculate the hash */

    strcpy(value, fs_mount_path);
    strcat(value,path);//Value = Mount Path + Path in the image/disk
#ifdef __linux__
    int retval = getSymLinkValue(value);
    if(retval != 0) {
        ERROR_LOG("\n%s %s %s","File:",path,"doesn't exist");
        return NULL;
    }
	DEBUG_LOG("\n%s %s %s %s","Mounted file path for file",path,"is",value);
#endif
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
#ifdef _WIN32
	BCRYPT_ALG_HANDLE       handle_Alg = NULL;
	BCRYPT_HASH_HANDLE      handle_Hash_object = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   out_data_size = 0,
		hash_size = 0,
		hashObject_size = 0;
	PBYTE                   hashObject_ptr = NULL;
	PBYTE                   hash_ptr = NULL;

	status = setup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hashObject_size, &hash_ptr, &hash_size);
	if (!NT_SUCCESS(status)) {
		return NULL;
	}
	while ((bytesRead = fread(buffer, 1, bufSize, file))) {
		// calculate hash of bytes read
		status = BCryptHashData(handle_Hash_object, buffer, bytesRead, 0);
		if (!NT_SUCCESS(status)) {
			cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
			return NULL;
		}
	}
	//Dump the hash in variable and finish the Hash Object handle
	status = BCryptFinishHash(handle_Hash_object, hash_ptr, hash_size, 0);
	cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
	if (!NT_SUCCESS(status)) {
		return NULL;
	}
	if (strcmp(hashType, "sha256") == 0) {
		output = sha256_hash_string(hash_ptr, hash_size, output);
		strcpy(hash_in, output);
		generate_cumulative_hash(output, 0);
	}
	else {
		output = sha256_hash_string(hash_ptr, hash_size, output);
		strcpy(hash_in, output);
		generate_cumulative_hash(output, 1);
	}
#elif __linux__

    if(strcmp(hashType, "sha256") == 0) {
     //For SHA 256 hash**Hard dependency on exact usage of 'sha256'   
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        const int bufSize = 65000;
        char *buffer = malloc(bufSize);
       
        int bytesRead = 0;
        if(!buffer) return NULL;
        while((bytesRead = fread(buffer, 1, bufSize, file))) {
              SHA256_Update(&sha256, buffer, bytesRead);
        }
        SHA256_Final(hash, &sha256);
		output = sha256_hash_string(hash, output);						
		strcpy(hash_in,output);
        generate_cumulative_hash(output,0);
        
    }
    else {
        // Using SHA1 algorithm for hash calculation
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA_CTX sha1;
        SHA1_Init(&sha1);
        const int bufSize = 32768;
        char *buffer = malloc(bufSize);
        int bytesRead = 0;
        if(!buffer) return NULL;
        while((bytesRead = fread(buffer, 1, bufSize, file))) {
            SHA1_Update(&sha1, buffer, bytesRead);
        }
        SHA1_Final(hash, &sha1);
        output = sha1_hash_string(hash, output);
	    strcpy(hash_in,output);
		generate_cumulative_hash(output,1);        
    }
#endif
	fclose(file);
	free(buffer);
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
        strcpy(key,line);
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
		strcpy(NodeValue,start);
        
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
    char include[50];
    char exclude[100];
    size_t len = 0;
    char calc_hash[256];
    char ma_result_path[100];
	memset(ma_result_path,'\0',sizeof(ma_result_path));
    char ma_result_path_default[100]="/var/log/trustagent/measurement.xml";
    int digest_check  = 0;

    if(strcmp(verificationType,"HOST") == 0)
      sprintf(ma_result_path, "%s%s", MOUNTPATH_HOST, ma_result_path_default);
    else
      sprintf(ma_result_path,"%s%s",hash_file,"xml");

    
	DEBUG_LOG("%s %s","Manifest Path",origManifestPath);
    fp=fopen(origManifestPath,"r");
    fq=fopen(ma_result_path,"w");

    fprintf(fq,"<?xml version=\"1.0\"?>\n");
#ifdef _WIN32
	DEBUG_LOG("\nsetting up CNG api algorithm provider");
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	status = setup_CNG_api();
	if (!NT_SUCCESS(status)){
		ERROR_LOG("\nCould not inititalize CNG Provider : 0x%x", status);
		return;
	}	
#endif
   //Open Manifest to get list of files to hash
	len = 32767 + 1;
	line = (BYTE *)malloc(sizeof(byte) * len);
	
    //while (getline(&line, &len, fp) != -1) { 
	while (fgets(line, len, fp) != NULL) {
		if (feof(fp)) {
			break;
		}
     strcpy(include,"");
     strcpy(exclude,"");
    
          if(strstr(line,"DigestAlg=") != NULL){
		   /*Get the type of hash */	  
           tagEntry(strstr(line,"DigestAlg="));
           strcpy(hashType,NodeValue);
		   digest_check = 1;
		   DEBUG_LOG("\n%s %s","Type of Hash used :",hashType);
		   fprintf(fq,"<Measurements xmlns=\"mtwilson:trustdirector:measurements:1.1\" DigestAlg=\"%s\">\n",hashType);
         }


     //File Hashes
          if(strstr(line,"<File Path=")!= NULL && digest_check){
            tagEntry(line);
            fprintf(fq,"<File Path=\"%s\">",NodeValue);
           
            fprintf(fq,"%s</File>\n",calculate(NodeValue,calc_hash));    
            DEBUG_LOG("\n%s %s %s %s","File :",NodeValue,"Hash Measured:",calc_hash);			
          }

     //Directory Hashes
		  
          if(strstr(line,"<Dir ")!= NULL && digest_check){
                
                tagEntry(strstr(line,"Path="));
                char dir_path[500];
                strcpy(dir_path,NodeValue); 
                DEBUG_LOG("\n%s %s","Directory :",NodeValue);
			    if(strstr(line,"Include=")!= NULL){
                         tagEntry(strstr(line,"Include="));
                         strcpy(include,NodeValue);
                         DEBUG_LOG("\n%s %s","Include type :",NodeValue);
                }

                if(strstr(line,"Exclude=") != NULL){
                         tagEntry(strstr(line,"Exclude="));
                         strcpy(exclude,NodeValue);
                         DEBUG_LOG("\n%s %s","Exclude type :",NodeValue);
                }
            
	        char Dir_Str[1024];
            
            char mDpath[256];
            strcpy(mDpath,fs_mount_path);
            strcat(mDpath,dir_path);//path of dir in the VM
            strcat(mDpath,"\0");
	       
            int slen = strlen(fs_mount_path); //to remove mount path from the find command output. 
            char hash_algo[15] = {'\0'};
	        sprintf(hash_algo,"%ssum",hashType); 
            if(strcmp(include,"") != 0 && strcmp(exclude,"") != 0 )
               sprintf(Dir_Str,"find \"%s\" ! -type d | grep -E  \"%s\" | grep -vE \"%s\" | sed -r 's/.{%d}//' | %s",mDpath,include,exclude,slen,hash_algo);  
            else if(strcmp(include,"") != 0)
               sprintf(Dir_Str,"find \"%s\" ! -type d | grep -E  \"%s\"| sed -r 's/.{%d}//' | %s",mDpath,include,slen,hash_algo);
            else if(strcmp(exclude,"") != 0)
               sprintf(Dir_Str,"find \"%s\" ! -type d | grep -vE \"%s\"| sed -r 's/.{%d}//' | %s",mDpath,exclude,slen,hash_algo);
            else
               sprintf(Dir_Str,"find \"%s\" ! -type d| sed -r 's/.{%d}//' | %s",mDpath,slen,hash_algo);

            char ops[200];
            sprintf(ops,"find \"%s\"/ ! -type d | sed -r 's/.{%d}//'",mDpath,slen);
            
            DEBUG_LOG("\n%s %s %s %s","********mDpath is ----------",mDpath," and command is ",Dir_Str);
 
		    FILE *dir_file = popen(Dir_Str,"r");
            char *dhash = NULL;
			int dhash_len = 65565;
			dhash = (char *)malloc(sizeof(char) * dhash_len);
			memset(dhash, 0, dhash_len);
            //getline(&dhash, &len, dir_file);
			fgets(dhash, dhash_len, dir_file);
	        strtok(dhash," ");
            fprintf(fq,"<Dir Path=\"%s\">",dir_path);
            fprintf(fq,"%s</Dir>\n",dhash);
			char outputBuffer[65];
			if(strcmp(hashType, "sha256") == 0)
			   generate_cumulative_hash(dhash,0);
		    else
			   generate_cumulative_hash(dhash,1);
			if (feof(dir_file)) {
				pclose(dir_file);
				DEBUG_LOG("\nSuccessfully read the file names in directory");
			}
			else {
				ERROR_LOG("\nCan not read the file names in directory");
			}

          }//Dir hash ends
		  
    }//While ends
    
	if(!digest_check){
		ERROR_LOG("%s","Hash Algorithm not specified!");
		//return -1 ?
	}
	
    fprintf(fq,"</Measurements>");
    fclose(fp);
    fclose(fq);
    strcat(hash_file,hashType);
    /*Write the Cumulative Hash calculated to the file*/
    FILE *fc = fopen(hash_file,"w");
    char *ptr;
#ifdef _WIN32
	status = finalize_hash_CNG_api();
	if( !NT_SUCCESS(status)){
		ERROR_LOG("\nCould not dump the hash on memory. Error : 0x%x", status);
	}
	ptr = (char *)malloc(65*sizeof(BYTE));
	memset(ptr, 0, 65*sizeof(BYTE));
#endif
	if (strcmp(hashType, "sha256") == 0)
#ifdef _WIN32	
	ptr = sha256_hash_string(hash_ptr, hash_size, ptr);
#elif __linux__
		ptr = sha256_hash_string(d2, SHA256_DIGEST_LENGTH ,cH2);
#endif
    else
#ifdef _WIN32	
		ptr = sha1_hash_string(hash_ptr, hash_size, ptr);
#elif __linux__
		ptr = sha1_hash_string(d1, SHA_DIGEST_LENGTH, cH2);
#endif
    fprintf(fc,"%s",ptr);
    fclose(fc);
}

/*
 * Main function which checks for the different input parameters 
 * provided to the verifier and calls a xml parsing function
 */
int main(int argc, char **argv) {

    int imageMountingRequired = 0; //IMVM = 1 /HOST = 0
    char manifest_file[100];
#ifdef _WIN32
	DWORD pid = GetCurrentProcessId();
	char power_shell[] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	char power_shell_prereq_command[] = "-noprofile -executionpolicy bypass -file";
	char* mount_script = "C:\\MOUNT-EXTVM.ps1";
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
#elif __linux__
    pid_t pid = getpid();
	char* mount_script = "../scripts/mount_vm_image.sh";
	char verifierpid[64] = { 0 };
	sprintf(verifierpid, "%d", pid);
	memset(cHash, 0, strlen(cHash));
#endif
    //xmlDocPtr Doc;
    if(argc != 4) {
        ERROR_LOG("\n%s %s %s","Usage:",argv[0]," <manifest_path> <disk_path> <IMVM/HOST>");
        return EXIT_FAILURE;
    }
    DEBUG_LOG("\n%s %s","MANIFEST-PATH :", argv[1]);
    DEBUG_LOG("\nARGS %s %s\n",argv[1],argv[2]);
	DEBUG_LOG("\n%s %s","DISK-PATH :", argv[2]);
  
	strcpy(manifest_file,argv[1]);

    if (strcmp(argv[3], "IMVM") == 0) {
#ifdef _WIN32
		char next_logical_drive_char;
		int sleep_count = 0;
		//try to get next available drive letter, if not available wait for 5 sec
		while (1) {
			next_logical_drive_char = next_available_logical_drive();
			if (next_logical_drive_char == NULL && sleep_count < 5) {
				DEBUG_LOG("wait till some drive is unmounted ");
				Sleep(1000);
				sleep_count++;
			}
			else if (sleep_count == 5 && next_logical_drive_char == NULL ) {
				ERROR_LOG("\ncan't get drive letter for disk");
				return;
			}
			else {
				//sprintf(fs_mount_path, "%c:", next_logical_drive_char);
				printf("\nnext available drive char : %c", next_logical_drive_char);
				sprintf(fs_mount_path, "z:");
				break;
			}
		}
#elif __linux__
		strcpy(fs_mount_path, MOUNTPATH_IMVM);
		strcat(fs_mount_path, verifierpid);
#endif
        strncpy(hash_file,manifest_file,strlen(manifest_file)-strlen("/manifestlist.xml"));
        sprintf(hash_file,"%s%s",hash_file,"/measurement.");
		DEBUG_LOG("\n%s", hash_file);
        imageMountingRequired = 1;
    } else if (strcmp(argv[3], "HOST") == 0) {
		//TODO handle case of HOST measurement
#ifdef __linux__
        strcpy(fs_mount_path, MOUNTPATH_HOST);
#endif
        sprintf(hash_file, "%s/var/log/trustagent/measurement.", fs_mount_path);
        imageMountingRequired = 0;
    } else { 
        ERROR_LOG("\n%s","Invalid verification_type.Valid options are IMVM/HOST\n");
        return EXIT_FAILURE;
    }

    if (imageMountingRequired) {
#ifdef _WIN32
		char *command = (char*)malloc( ( strlen(power_shell) + strlen(power_shell_prereq_command) + strlen(mount_script)+strlen(argv[2])+strlen(fs_mount_path) + 64)*sizeof(char));
		sprintf(command,"%s %s %s -Path %s -DriveLetter %s", power_shell, power_shell_prereq_command, mount_script, argv[2], fs_mount_path);
		// dirctory which will be the working directory of powershell
		DEBUG_LOG("\ncommand : %s", command);
		char current_dir_of_power_shell[] = "C:\\";
		//int res = (int)ShellExecute(NULL, "RunAs", power_shell, command, "C:\\", 0);
		int res = CreateProcess(NULL, command, NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS, NULL, current_dir_of_power_shell, &si, &pi);
//		int res = system(command);
		printf("\nafter create process");
		free(command);
		if (res == 0) {
			ERROR_LOG("\nCreateProcess failed (%d).\n", GetLastError());
			ERROR_LOG("\n Mounting of image failed");
			//exit(EXIT_FAILURE);
			return EXIT_FAILURE;
		}
		
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(si.hStdError);
		CloseHandle(si.hStdInput);
		CloseHandle(si.hStdOutput);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		DEBUG_LOG("\nSuccessfully mounted the image");
#elif __linux__
		char *command = (char*)malloc(strlen(mount_script) + strlen(argv[2]) + strlen(fs_mount_path) + 2)*sizeof(char));
		sprintf(command, "%s %s %s", mount_script, argv[2], fs_mount_path);
		int res = system(command);
		if (res != 0) {
			ERROR_LOG("\n%s", "Error in mounting the image!!!!");
			exit(1);
		}
		strcat(fs_mount_path,"/mount");	    
#endif
    }
    //Doc = xmlParseFile(argv[1]); 
	
	/*This will save the XML file in a correct format, as desired by our parser. 
	We dont use libxml tools to parse but our own pointer legerdemain for the time being
	Main advantage is simplicity and speed ~O(n) provided space isn't an issue */
	//xmlSaveFormatFile (argv[1], Doc, 1); /*This would render even inline XML perfect for line by line parsing*/  
    //xmlFreeDoc(Doc);  
    generateLogs(argv[1], argv[2], argv[3]);
    
	if (strcmp(argv[3], "IMVM") == 0) {
	   char command[1024]={'\0'};
#ifdef _WIN32
	   sprintf(command, "%s %s %s -Path %s", power_shell, power_shell_prereq_command, mount_script, argv[2]);
	   char current_dir_of_power_shell[] = "C:\\";
	   ZeroMemory(&si, sizeof(si));
	   si.cb = sizeof(si);
	   ZeroMemory(&pi, sizeof(pi));
	   int res = CreateProcess(NULL, command, NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS, NULL, current_dir_of_power_shell, &si, &pi);
	   if (res == 0) {
		   ERROR_LOG("CreateProcess failed (%d).\n", GetLastError());
		   ERROR_LOG("\n Mounting of image failed");
		   //exit(EXIT_FAILURE);
		   return EXIT_FAILURE;
	   }
	   WaitForSingleObject(pi.hProcess, INFINITE);
	   CloseHandle(si.hStdError);
	   CloseHandle(si.hStdInput);
	   CloseHandle(si.hStdOutput);
	   CloseHandle(pi.hProcess);
	   CloseHandle(pi.hThread);
#elif __linux__
	   sprintf(command,"%s %s",mount_script,fs_mount_path);  
	   system(command);
#endif
	   DEBUG_LOG("\nSuccessfully unmounted the image");
    }   
    return 0;
}