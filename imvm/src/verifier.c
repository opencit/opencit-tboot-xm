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
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#include <WinBase.h>
#include <bcrypt.h>
#include <WinIoCtl.h>
#include <io.h>
#include <errors.h>
#include <xmllite.h>
#include <shlwapi.h>
#elif __linux__
#include <linux/limits.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include "safe_lib.h"
#include <dirent.h>
#include <sys/param.h>
#include <libxml/xmlreader.h>
#endif
#include "char_converter.h"

//#define MOUNTPATH_IMVM  "/tmp/"
//#define MOUNTPATH_HOST  "/tmp/root"
#define DEBUG_LOG(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
#define ERROR_LOG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define byte unsigned char
#define MAX_LEN 4096
#define MAX_HASH_LEN 65

char cH2[MAX_HASH_LEN];
char hashType[10]; //SHA1 or SHA256
char NodeValue[500]; //XML Tag value
char hash_file[256];
char fs_mount_path[1024];

#ifdef _WIN32
//For xml parsing using xmllite
#define CHKHR(stmt)					do { hr = (stmt); if (FAILED(hr)) goto CleanUp; } while(0) 
#define HR(stmt)					do { hr = (stmt); goto CleanUp; } while(0) 
#define SAFE_RELEASE(I)				do { if (I){ I->lpVtbl->Release(I); } I = NULL; } while(0)

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)


#define malloc(size) HeapAlloc(GetProcessHeap(), 0, size)
#define free(mem_ptr) HeapFree(GetProcessHeap(),0, mem_ptr)
#define snprintf sprintf_s

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

/*These global variables are required for calculating the cumulative hash */

#ifdef _WIN32
unsigned char cH[MAX_HASH_LEN] = { '\0' };
int cumulative_hash_size = 0;
#elif __linux__
unsigned char d1[SHA_DIGEST_LENGTH]={'\0'};
unsigned char d2[SHA256_DIGEST_LENGTH]={'\0'};
#endif

#ifdef _WIN32
/*
Cleanup the CNG api
return : 0 for success or failure status

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


open Crypto Algorithm Handle, allocate buffer for hashObject and hash buffer,
and create hash object
return : 0 for success or failure status

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
	status = BCryptGetProperty(handle_Alg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObject_size, sizeof(DWORD), &out_data_size, 0);
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
		return status;
	}
	return status;
}
*/
/*
Cleaup the CNG api,
Close and Destroy the handle, free the allocated memory for hash Object and hash buffer
return: error number
*/
void cleanup_CNG_api_args(BCRYPT_ALG_HANDLE * handle_Alg, BCRYPT_HASH_HANDLE *handle_Hash_object, PBYTE* hashObject_ptr, PBYTE* hash_ptr) {
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
int setup_CNG_api_args(BCRYPT_ALG_HANDLE * handle_Alg, BCRYPT_HASH_HANDLE *handle_Hash_object, PBYTE* hashObject_ptr, int * hashObject_size, PBYTE* hash_ptr, int * hash_size) {
	// Open algorithm
	int out_data_size;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
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
		return status;
	}
	return status;
}

/*
Check if file exist on file system or not.
It automatically resolves the symlink, hardlink and open target file mentioned in filename,
and also resolves junctions in if exist in filename path
filename: Full path of file which you want to check
return 0 if file exist, non zero if file does not exist or can't be found
*/
int fileExist(char * filename) {
	FILE *fp = NULL;
	errno_t err_code;
	err_code = fopen_s(&fp, filename, "r");
	if (err_code != 0) {
		return err_code;
	}
	if (fp) fclose(fp);
	return 0;
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
			DEBUG_LOG("\n%s", "file contains reparse point ...");
			islink = 0;
		}
		else if (FindFileData.dwFileAttributes == FILE_ATTRIBUTE_ARCHIVE || FindFileData.dwFileAttributes == 33) {
			DEBUG_LOG("\n%s", "file contains directory reparse point ...");
			islink = 0;
		}
		else if (FindFileData.dwReserved0 == IO_REPARSE_TAG_SYMLINK) {
			DEBUG_LOG("\n%s", "file is a symbolic link to file ...");
			islink = 0;
		}
		else if (IO_REPARSE_TAG_MOUNT_POINT == FindFileData.dwReserved0) {
			DEBUG_LOG("\n%s", "this file is JUNCTION ...");
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
			DEBUG_LOG("\n%s", "file contains reparse point ...");
		}
		else if (FindFileData.dwFileAttributes == FILE_ATTRIBUTE_ARCHIVE) {
			DEBUG_LOG("\n%s", "file contains directory reparse point ...");
		}
		else if (FindFileData.dwReserved0 == IO_REPARSE_TAG_SYMLINK) {
			DEBUG_LOG("\n%s", "file is a symbolic link to file ...");
		}
		else if (IO_REPARSE_TAG_MOUNT_POINT == FindFileData.dwReserved0) {
			DEBUG_LOG("\n%s", "this file is JUNCTION ...");
		}
		DEBUG_LOG("%d\n", FindFileData.dwFileAttributes);
		HANDLE target_handle = CreateFile(path, FILE_GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL, NULL);
		if (target_handle == INVALID_HANDLE_VALUE) {
			ERROR_LOG("\n%s", "couldn't get handle to file");
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
			strncpy_s(w_complete_path_pname, wlength, reparse_buffer->SymbolicLinkReparseBuffer.PathBuffer + (reparse_buffer->SymbolicLinkReparseBuffer.PrintNameOffset / sizeof(WCHAR)),
				reparse_buffer->SymbolicLinkReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1);
			wprintf(L"\n wide char Path : %s", w_complete_path_pname);
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, 0, 0, 0, 0);
			complete_path_pname = (char *)malloc(sizeof(CHAR)* clength);
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, complete_path_pname, clength, 0, 0);
			if (clength == 0) {
				ERROR_LOG("\n%s", "conversion from wchar to char fails");
				target_buf_size = -1;
				goto return_target_link;
			}
			DEBUG_LOG("\nchar path print name : %s", complete_path_pname);

			//appending unparsed path
			if (strnlen_s(target_buf, target_buf_size) > 0) {
				int target_buf_length = strnlen_s(complete_path_pname, clength) + (strnlen_s(path, MAX_LEN) - reparse_buffer->Reserved);
				if (target_buf_length > target_buf_size) {
					realloc(target_buf, target_buf_length);
					target_buf_size = target_buf_length;
				}
				//target_buf = (char *)malloc(target_buf_length * sizeof(char));
				strcpy_s(target_buf, target_buf_size, complete_path_pname);
				strcat_s(target_buf, target_buf_size, (path + (strnlen_s(path, MAX_LEN) - reparse_buffer->Reserved)));
				//return target_buf_size;
				goto return_target_link;
			}

			//extract name from substitutestring
			wlength = reparse_buffer->SymbolicLinkReparseBuffer.SubstituteNameLength;
			w_complete_path_sname = (WCHAR *)malloc(sizeof(WCHAR)*wlength);
			strncpy_s(w_complete_path_sname, wlength, reparse_buffer->SymbolicLinkReparseBuffer.PathBuffer + (reparse_buffer->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)),
				reparse_buffer->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR) + 1);

			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, 0, 0, 0, 0);
			complete_path_sname = (char *)malloc(sizeof(CHAR) * clength);
			if (complete_path_sname == NULL) {
				ERROR_LOG("\n%s", "can't allocate memory for sustitute string name");
				target_buf_size = -3;
				goto return_target_link;
				//return -3;
			}
			memset(complete_path_sname, 0, clength);
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, complete_path_sname, clength, 0, 0);
			if (clength == 0) {
				ERROR_LOG("\n%s", "conversion from wchar to char failed");
				if (strnlen_s(complete_path_pname, clength) == 0) {
					target_buf_size = -3;
					goto return_target_link;
				}
				//	return -3;
			}
			DEBUG_LOG("\nchar path substitute name : %s", complete_path_sname);

			//need to remove \\?\ from path
			int target_buf_length = strnlen_s(complete_path_sname, clength) + (strnlen_s(path, MAX_LEN) - reparse_buffer->Reserved);
			if (target_buf_length > target_buf_size) {
				realloc(target_buf, target_buf_length);
				target_buf_size = target_buf_length;
			}
			//target_buf = (char *)malloc(target_buf_length * sizeof(char));
			if (strstr(complete_path_sname, "\\\\?\\") != NULL) {
				// if it contains windows convention of preceding "\\?\" in path
				strcpy_s(target_buf, target_buf_size, &complete_path_sname[4]);
			}
			else {
				//if its a relative path
				strcpy_s(target_buf, target_buf_size, complete_path_sname);
			}
			strcat_s(target_buf, target_buf_size, (path + (strnlen_s(path, MAX_LEN) - reparse_buffer->Reserved)));
			DEBUG_LOG("\nafter adding unparsed path : %s", target_buf);
		}
		else if (reparse_buffer->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
			// its junction or mount point
			DEBUG_LOG("\n unparsed length : %d", reparse_buffer->Reserved);
			wlength = reparse_buffer->MountPointReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1;
			w_complete_path_pname = (WCHAR *)malloc(sizeof(WCHAR) * wlength);
			strncpy_s(w_complete_path_pname, wlength, reparse_buffer->MountPointReparseBuffer.PathBuffer + (reparse_buffer->MountPointReparseBuffer.PrintNameOffset / sizeof(WCHAR)),
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
			memset(target_buf, 0, target_buf_size);
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, target_buf, clength, 0, 0);
			if (clength == 0) {
				ERROR_LOG("\n%s", "conversion from wchar to char fails");
				target_buf_size = -1;
				goto return_target_link;
				//return -1;
			}
			DEBUG_LOG("\nchar path print name : %s", target_buf);
			if (strnlen_s(target_buf, target_buf_size) > 0) {
				goto return_target_link;
				//return target_buf_size;
			}
			//extract name from substitutestring
			wlength = reparse_buffer->MountPointReparseBuffer.SubstituteNameLength;
			w_complete_path_sname = (WCHAR *)malloc(sizeof(WCHAR)*wlength);
			strncpy_s(w_complete_path_sname, wlength, reparse_buffer->MountPointReparseBuffer.PathBuffer + (reparse_buffer->MountPointReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)),
				reparse_buffer->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR) + 1);

			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, 0, 0, 0, 0);
			if (clength > target_buf_size) {
				realloc(target_buf, clength);
				target_buf_size = clength;
			}
			//complete_path_sname = (char *)malloc(sizeof(CHAR) * clength);
			if (target_buf == NULL) {
				ERROR_LOG("\n%s", "reallocation for memroy failed");
				target_buf_size = -3;
				goto return_target_link;
				//return -3;
			}
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, target_buf, clength, 0, 0);
			if (clength == 0) {
				ERROR_LOG("\n%s", "conversion from wchar to char failed");
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
					ERROR_LOG("\n%s", "can't reallocate memory for target buff");
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

static void formatManifest(const char * origManifest, const char *formattedManifest){
	HRESULT hr = S_OK;
	XmlNodeType nodeType;
	IStream *pFileStream = NULL;
	IStream *pOutFileStream = NULL;
	IXmlReader *pReader = NULL;
	IXmlWriter *pWriter = NULL;

	//Open read-only input stream 
	if (FAILED(hr = SHCreateStreamOnFile(origManifest, STGM_READ, &pFileStream)))
	{
		ERROR_LOG("Error creating file reader, error is %08.8lx", hr);
		HR(hr);
	}

	//Open writeable output stream 
	if (FAILED(hr = SHCreateStreamOnFile(formattedManifest, STGM_CREATE | STGM_WRITE, &pOutFileStream)))
	{
		ERROR_LOG("Error creating file writer, error is %08.8lx", hr);
		HR(hr);
	}

	if (FAILED(hr = CreateXmlReader(&IID_IXmlReader, (void**)&pReader, NULL)))
	{
		ERROR_LOG("Error creating xml reader, error is %08.8lx", hr);
		HR(hr);
	}

	if (FAILED(hr = CreateXmlWriter(&IID_IXmlWriter, (void**)&pWriter, NULL)))
	{
		ERROR_LOG("Error creating xml writer, error is %08.8lx", hr);
		HR(hr);
	}

	if (FAILED(hr = pReader->lpVtbl->SetProperty(pReader, XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit)))
	{
		ERROR_LOG("Error setting indent property in reader, error is %08.8lx", hr);
		HR(hr);
	}

	if (FAILED(hr = pWriter->lpVtbl->SetProperty(pWriter, XmlWriterProperty_Indent, TRUE)))
	{
		ERROR_LOG("Error setting indent property in writer, error is %08.8lx", hr);
		HR(hr);
	}

	if (FAILED(hr = pReader->lpVtbl->SetInput(pReader, pFileStream)))
	{
		ERROR_LOG("Error setting input for reader, error is %08.8lx", hr);
		HR(hr);
	}

	if (FAILED(hr = pWriter->lpVtbl->SetOutput(pWriter, pOutFileStream)))
	{
		ERROR_LOG("Error setting output for writer, error is %08.8lx", hr);
		HR(hr);
	}

	//read until there are no more nodes 
	while (S_OK == (hr = pReader->lpVtbl->Read(pReader, &nodeType)))
	{
		switch (nodeType)
		{
		case XmlNodeType_EndElement:
			if (FAILED(hr = pWriter->lpVtbl->WriteFullEndElement(pWriter)))
			{
				ERROR_LOG("Error writing WriteFullEndElement, error is %08.8lx", hr);
				HR(hr);
			}
			break;
		default:
			if (FAILED(hr = pWriter->lpVtbl->WriteNodeShallow(pWriter, pReader, FALSE)))
			{
				ERROR_LOG("Error writing WriteNodeShallow, error is %08.8lx", hr);
				HR(hr);
			}
			break;
		}
	}

CleanUp:
	SAFE_RELEASE(pFileStream);
	SAFE_RELEASE(pOutFileStream);
	SAFE_RELEASE(pReader);
	SAFE_RELEASE(pWriter);
}
#endif

/*This function keeps track of the cumulative hash and stores it in a global variable (which is later written to a file) */
void generate_cumulative_hash(char *hash, int sha_one){
	DEBUG_LOG("\nIncoming Hash : %s\n", hash);
	char ob[MAX_HASH_LEN]= {'\0'};
	char cur_hash[MAX_HASH_LEN] = {'\0'};

	int hexstr_len = hex2bin(hash, strnlen_s(hash, MAX_LEN), (unsigned char *)cur_hash, sizeof(cur_hash));
#ifdef _WIN32
	BCRYPT_ALG_HANDLE       handle_Alg = NULL;
	BCRYPT_HASH_HANDLE      handle_Hash_object = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   out_data_size = 0,
		hash_size = 0,
		hashObject_size = 0;
	PBYTE                   hashObject_ptr = NULL;
	PBYTE                   hash_ptr = NULL;
	unsigned char cHash_buffer[MAX_HASH_LEN] = { '\0' };

	strncpy_s((char *)cHash_buffer,sizeof(cHash_buffer),(char *)cH,strnlen_s(cH, MAX_HASH_LEN));
	bin2hex(cHash_buffer, strnlen_s(cHash_buffer, MAX_HASH_LEN), ob, sizeof(ob));
    DEBUG_LOG("\n%s %s","Cumulative Hash before:",ob);
	
	status = setup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hashObject_size, &hash_ptr, &hash_size);
	if (!NT_SUCCESS(status)) {
		ERROR_LOG("\nCould not inititalize CNG args Provider : 0x%x", status);
		return NULL;
	}
	cumulative_hash_size = hash_size;
	status = BCryptHashData(handle_Hash_object, cH, hash_size, 0);
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
		return NULL;
	}

	if (hexstr_len == hash_size) {
		status = BCryptHashData(handle_Hash_object, cur_hash, hash_size, 0);
		if (!NT_SUCCESS(status)) {
			cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
			return NULL;
		}
	}
	else {
		DEBUG_LOG("\n length of string converted from hex is : %d not equal to expected hash digest length : %d", hexstr_len, hash_size);
		ERROR_LOG("\n ERROR: current hash is not being updated in cumulative hash");
	}
	//Dump the hash in variable and finish the Hash Object handle
	status = BCryptFinishHash(handle_Hash_object, hash_ptr, hash_size, 0); 
	//strncpy_s(cH, sizeof(cH), hash_ptr, hash_size);
	memcpy_s(cH, sizeof(cH), hash_ptr, hash_size);
	//strncpy_s( (char *)cHash_buffer,sizeof(cHash_buffer), (char *)cH,strnlen_s(cH, MAX_HASH_LEN));
	memcpy_s(cHash_buffer, sizeof(cHash_buffer), hash_ptr, hash_size);
	bin2hex(cHash_buffer, hash_size, ob, sizeof(ob));
	DEBUG_LOG("\n%s %s","Cumulative Hash after is:",ob);
	cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
#elif __linux__
	unsigned char cHash[SHA_DIGEST_LENGTH] = { '\0' }; //Cumulative hash
	unsigned char cHash2[SHA256_DIGEST_LENGTH] = { '\0' };
    if(sha_one){
	   strncpy_s((char *)cHash,sizeof(cHash),(char *)d1,SHA_DIGEST_LENGTH);
	   bin2hex(cHash, sizeof(cHash), ob, sizeof(ob));
       //DEBUG_LOG("\n%s %s","Cumulative Hash before:",sha1_hash_string(cHash,ob));
	   DEBUG_LOG("\n%s %s","Cumulative Hash before:",ob);
	   SHA_CTX csha1;
	   SHA1_Init(&csha1);
	   SHA1_Update(&csha1,d1,SHA_DIGEST_LENGTH);
	   if (hexstr_len == SHA_DIGEST_LENGTH) {
		   SHA1_Update(&csha1,cur_hash, SHA_DIGEST_LENGTH);
	   }
	   else {
		   DEBUG_LOG("\n length of string converted from hex is not equal to SHA1 digest length");
	   }
	   SHA1_Final(d1,&csha1);
	   
	   //strncpy_s( (char *)cHash,sizeof(cHash), (char *)d1,SHA_DIGEST_LENGTH);
	   memcpy_s((char *)cHash, sizeof(cHash), (char *)d1,SHA_DIGEST_LENGTH);
	   bin2hex(cHash, sizeof(cHash), ob, sizeof(ob));
	   //DEBUG_LOG("\n%s %s","Cumulative Hash after is:",sha1_hash_string(cHash,ob));
	   DEBUG_LOG("\n%s %s","Cumulative Hash after is:",ob);
	   memset(ob,'\0',strnlen_s(ob,sizeof(ob)));
	   
	   return;
	}
	
	else{
	   strncpy_s(( char *)cHash2,sizeof(cHash2), (char *)d2,SHA256_DIGEST_LENGTH);
	   bin2hex(cHash2, sizeof(cHash2), ob, sizeof(ob));
       //DEBUG_LOG("\n%s %s","Cumulative Hash before:",sha256_hash_string(cHash2,ob));
       DEBUG_LOG("\n%s %s","Cumulative Hash before:",ob);
	   SHA256_CTX csha256;
	   SHA256_Init(&csha256);
	   SHA256_Update(&csha256,d2,SHA256_DIGEST_LENGTH);
	   if (hexstr_len == SHA256_DIGEST_LENGTH) {
		   SHA256_Update(&csha256,cur_hash, SHA256_DIGEST_LENGTH);
	   }
	   else {
		   DEBUG_LOG("\n length of string converted from hex is not equal to SHA256 digest length");
	   }
	   SHA256_Final(d2, &csha256);
	   strncpy_s((char *)cHash2,sizeof(cHash2), (char *) d2,SHA256_DIGEST_LENGTH);
	   memcpy_s((char *)cHash2,sizeof(cHash2), (char *) d2,SHA256_DIGEST_LENGTH);
	   bin2hex(cHash2, sizeof(cHash2), ob, sizeof(ob));
	   //DEBUG_LOG("\n%s %s","Cumulative Hash after is:",sha256_hash_string(cHash2,ob));
	   DEBUG_LOG("\n%s %s","Cumulative Hash after is:",ob);
	   memset(ob,'\0',strnlen_s(ob,sizeof(ob)));
	   
	   return;
	}
#endif
}

/*
* getSymLinkValue:
* @path : path of the file/symbolic link
*
* Returns the actual value for the symbolic link provided as input
*/
int getSymLinkValue(char *path) {
	//char symlinkpath[512];
	char *symlinkpath;
	int symlinkpath_size = 512;
	// Check if the file path is a symbolic link
	symlinkpath = (char *)malloc(sizeof(char)*symlinkpath_size);

#ifdef _WIN32
	if (ISLINK(path) == 0) {
		// If symbolic link doesn't exists read the path its pointing to
		int len = readlink(path, symlinkpath, symlinkpath_size);
		if (len < 0) {
			ERROR_LOG("\n%s", "Error occured in reading link");
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
		strcpy_s(path, strnlen_s(sympathroot, len) + 1, sympathroot);
		return getSymLinkValue(path);
	}
#elif __linux__
    struct stat p_statbuf;
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
char* calculate(char *path, char output[MAX_HASH_LEN]) {
	const int bufSize = 65000;
	char *buffer = malloc(bufSize);
	int bytesRead = 0;
	if (!buffer) return NULL;

    char value[1056] = {'\0'};
    /*We append the mount path before the filepath first, 
	 and then pass that address to calculate the hash */

    strcpy_s(value, sizeof(value), fs_mount_path);
    strcat_s(value,sizeof(value),path);//Value = Mount Path + Path in the image/disk
	DEBUG_LOG("\n%s %s %s %s","Mounted file path for file",path,"is",value);
   
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

	FILE* file;
	errno_t error_code;
	error_code = fopen_s(&file, value, "rb");
	if ( (!file) || error_code) {
		ERROR_LOG("\n%s %s", "File not found-", value);
		return NULL;
	}
	status = setup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hashObject_size, &hash_ptr, &hash_size);
	if (!NT_SUCCESS(status)) {
		ERROR_LOG("\nCould not inititalize CNG args Provider : 0x%x", status);
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
	bin2hex(hash_ptr, hash_size, output, MAX_HASH_LEN);
	cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
	if (strcmp(hashType, "sha256") == 0) {
		//output = sha256_hash_string(hash_ptr, hash_size, output);
		generate_cumulative_hash(output, 0);
	}
	else {
		//output = sha1_hash_string(hash_ptr, hash_size, output);
		generate_cumulative_hash(output, 1);
	}
#elif __linux__
	FILE* file = fopen(value, "rb");
	if (!file) {
		ERROR_LOG("\n%s %s", "File not found-", value);
		return NULL;
	}
    if(strcmp(hashType, "sha256") == 0) {
     //For SHA 256 hash**Hard dependency on exact usage of 'sha256'   
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        while((bytesRead = fread(buffer, 1, bufSize, file))) {
             
              SHA256_Update(&sha256, buffer, bytesRead);
        }
        SHA256_Final(hash, &sha256);
        //output = sha256_hash_string(hash, output);
        bin2hex(hash, sizeof(hash), output, MAX_HASH_LEN);
		//strcpy_s(hash_in,sizeof(hash_in),output);
        generate_cumulative_hash(output,0);
    }
    else {
        // Using SHA1 algorithm for hash calculation
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA_CTX sha1;
        SHA1_Init(&sha1);
        while((bytesRead = fread(buffer, 1, bufSize, file))) {
            SHA1_Update(&sha1, buffer, bytesRead);
        }
        SHA1_Final(hash, &sha1);
        //output = sha1_hash_string(hash, output);
        bin2hex(hash, sizeof(hash), output, MAX_HASH_LEN);
	    //strcpy_s(hash_in,sizeof(hash_in),output);
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
void tagEntry(char* line){    
	char key[500];
	/*We use a local string 'key' here so that we dont make any changes
	to the line pointer passed to the function.
	This is useful in a line containing more than 1 XML tag values.
	E.g :<Dir Path="/etc" include="*.bin" exclude="*.conf">
	*/
	int i = 0;
	strcpy_s(key,sizeof(key),line);
	char  *start, *end;
	while (key[i] != '\"')
		i++;
	start = &key[++i];
	end = start;
	while (*end != '\"')
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
Recursive ****  Hard Dependency
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
	FILE *fp, *fq;
	char *line = NULL;
    char include[128] = {'\0'};
    char exclude[128] = { '\0'};
	char recursive[16] = {'\0'};
#ifdef _WIN32
	// "/S" switch in dir command search recursively
	char recursive_cmd[32] = "-Recurse";
#elif __linux__
	char recursive_cmd[32] = {'\0'};
#endif
	size_t len = 32768;
    char calc_hash[MAX_HASH_LEN] = {'\0'};
    char ma_result_path[256] = {'\0'};
	//memset_s(ma_result_path,sizeof(ma_result_path),'/0');
    char ma_result_path_default[100]="/var/log/trustagent/measurement.xml";
	int dhash_len = 256;
	int digest_check = 0;

    if(strcmp(verificationType,"HOST") == 0)
      snprintf(ma_result_path, sizeof(ma_result_path), "%s%s", fs_mount_path, ma_result_path_default);
    else
      snprintf(ma_result_path, sizeof(ma_result_path), "%s%s",hash_file,"xml");
	DEBUG_LOG("\n%s %s", "Manifest Path", origManifestPath);
    fp=fopen(origManifestPath,"r");
    if (fp != NULL) {
		fq=fopen(ma_result_path,"w");
#ifdef _WIN32
		_chmod(ma_result_path, _S_IREAD | _S_IWRITE);
#elif __linux__
		chmod(ma_result_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif
		if (fq != NULL) {
			fprintf(fq,"<?xml version=\"1.0\"?>\n");
			char * temp_ptr = NULL;
			//Open Manifest to get list of files to hash
			line = (char *)malloc(sizeof(char) * len);
			while (fgets(line, len, fp) != NULL) {
				if (feof(fp)) {
					break;
				}
				strcpy_s(include,sizeof(include),"");
				strcpy_s(exclude,sizeof(exclude),"");
				strcpy_s(recursive,sizeof(recursive),"");
				temp_ptr = NULL;
				//Extract Digest Algo
				if (!digest_check) {
					temp_ptr = strstr(line,"DigestAlg=");				
					if(temp_ptr != NULL){
						/*Get the type of hash */
						tagEntry(temp_ptr);
						strcpy_s(hashType,sizeof(hashType),NodeValue);
						digest_check = 1;
						DEBUG_LOG("\n%s %s","Type of Hash used :",hashType);
						fprintf(fq,"<Measurements xmlns=\"mtwilson:trustdirector:measurements:1.1\" DigestAlg=\"%s\">\n",hashType);
						DEBUG_LOG("\n%s %s", "Type of Hash used :", hashType);
/*
#ifdef _WIN32
						DEBUG_LOG("\n%s", "setting up CNG api algorithm provider");
						NTSTATUS status = STATUS_UNSUCCESSFUL;

						status = setup_CNG_api();
						if (!NT_SUCCESS(status)){
							ERROR_LOG("\nCould not inititalize CNG Provider : 0x%x", status);
							return;
						}
#endif
*/
					}
				}
				//File Hashes
				if(strstr(line,"<File Path=")!= NULL && digest_check){
					tagEntry(line);
					char file_name_buff[1024] = {'\0'};
					snprintf(file_name_buff, sizeof(file_name_buff), "%s/%s", fs_mount_path, NodeValue);
					DEBUG_LOG("\nfile path : %s\n", file_name_buff);
#ifdef _WIN32
					int retval = fileExist(file_name_buff);
#elif __linux__
					int retval = getSymLinkValue(file_name_buff);
#endif
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
							//Hard coded to check "false" string
							if ( strcmp(recursive,"false") == 0) {
#ifdef _WIN32
								memset(recursive_cmd, 0, sizeof(recursive_cmd));
#elif __linux__
								snprintf(recursive_cmd, sizeof(recursive_cmd), "-maxdepth 1");
#endif
							}
						}

					char Dir_Str[1024];
					char mDpath[256] = {'\0'};
					char *dhash = NULL;
					dhash = (char *)malloc(sizeof(char) * dhash_len);
					memset(dhash, 0, dhash_len);
					strcpy_s(mDpath,sizeof(mDpath),fs_mount_path);
					strcat_s(mDpath,sizeof(mDpath),dir_path);//path of dir in the VM
					int slen = strnlen_s(mDpath, sizeof(mDpath)) + 1;
#ifdef _WIN32
					//TODO need to write in sync with linux 
					//char temp_dir_file_list[32] = "/tmp/dir_file.txt";
					if (strcmp(include, "") != 0 && strcmp(exclude, "") != 0)
						snprintf(Dir_Str, sizeof(Dir_Str), "Powershell \"Get-ChildItem '%s' %s | Where-Object {! $_.PSIsContainer} | Where-Object { $_.FullName.remove(0, %d) -cmatch '%s' -and $_.FullName.remove(0, %d) -notmatch '%s' } | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"", mDpath, recursive_cmd, slen, include, slen, exclude, slen);
					else if (strcmp(include, "") != 0)
						snprintf(Dir_Str, sizeof(Dir_Str), "Powershell \"Get-ChildItem '%s' %s | Where-Object {! $_.PSIsContainer} | Where-Object { $_.FullName.remove(0, %d) -cmatch '%s' } | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"", mDpath, recursive_cmd, slen, include, slen);
					else if (strcmp(exclude, "") != 0)
						snprintf(Dir_Str, sizeof(Dir_Str), "Powershell \"Get-ChildItem '%s' %s | Where-Object {! $_.PSIsContainer} | Where-Object { $_.FullName.remove(0, %d) -notmatch '%s' } | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"", mDpath, recursive_cmd, slen, exclude, slen);
					else
						snprintf(Dir_Str, sizeof(Dir_Str), "Powershell \"Get-ChildItem '%s' %s | Where-Object {! $_.PSIsContainer} | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"", mDpath, recursive_cmd, slen);

					/*char file[64] = {0};
					strcpy_s(file, sizeof(file), fs_mount_path);
					strcat_s(file, sizeof(file), temp_dir_file_list);*/

					FILE *dir_file = _popen(Dir_Str, "r");
					/*FILE *fd = NULL;
					errno_t error_code = fopen_s(&fd, file, "wb");
					if ( !fd || error_code) {
						ERROR_LOG("\n%s %s", "File not found-", file);
						return;
					}
					while (fgets(dhash, dhash_len, dir_file))
						fputs(dhash, fd);
					fclose(fd);
					dhash = calculate(temp_dir_file_list, calc_hash);*/

					//char output[MAX_HASH_LEN];
					const int bufSize = 65000;
					char *buffer = malloc(bufSize);
					int bytesRead = 0;
					if (!buffer) return; 
					
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
						ERROR_LOG("\nCould not inititalize CNG args Provider : 0x%x", status);
						return NULL;
					}
					while ((bytesRead = fread(buffer, 1, bufSize, dir_file))) {
						// calculate hash of bytes read
						status = BCryptHashData(handle_Hash_object, buffer, bytesRead, 0);
						if (!NT_SUCCESS(status)) {
							cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
							return NULL;
						}
					}

					//Dump the hash in variable and finish the Hash Object handle
					status = BCryptFinishHash(handle_Hash_object, hash_ptr, hash_size, 0);
					bin2hex(hash_ptr, hash_size, dhash, dhash_len);
					cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
					_pclose(dir_file);
					/*if (remove(file) == -1) {
						ERROR_LOG("\nFailed to remove the temproray created file %s", file);
					}*/
#elif __linux__
					//to remove mount path from the find command output and directory path and +1 is to remove the additional / after directory
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
					if (dir_file != NULL ) {
						getline(&dhash, &len, dir_file);
						size_t dhash_max = 128;
						char *next_token;
						strtok_s(dhash,&dhash_max," ",&next_token);
						pclose(dir_file);
					}
#endif
					if (strcmp(hashType, "sha256") == 0)
						generate_cumulative_hash(dhash, 0);
					else
						generate_cumulative_hash(dhash, 1);

					DEBUG_LOG("\n%s %s %s %s", "mDpath is ", mDpath, " and command is ", Dir_Str);
					DEBUG_LOG("\n%s %s %s %s", "Dir :", mDpath, "Hash Measured:", dhash);
					fprintf(fq, "<Dir Path=\"%s\">", dir_path);
					fprintf(fq, "%s</Dir>\n", dhash);
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
#ifdef _WIN32
	if (_chmod(hash_file, _S_IREAD | _S_IWRITE) == -1) {
		ERROR_LOG("Failed to provide read write permissions to cumulative hash file %s ", hash_file);
	}
#elif __linux__
	chmod(hash_file, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif
    if (fc == NULL ) {
    	ERROR_LOG("Can not open file: %s, to write cumulative hash", hash_file);
    	return;
    }
#ifdef _WIN32
	if (bin2hex(cH, cumulative_hash_size, cH2, sizeof(cH2)) < 0) {
		ERROR_LOG("\n Failed to convert binary hash to hex");
		return;
	}
#elif __linux__
	if(strcmp(hashType, "sha256") == 0){
		if (bin2hex(d2, sizeof(d2), cH2, sizeof(cH2)) < 0 ) {
			ERROR_LOG("\n Failed to convert binary hash to hex");
			return;
		}
    }
    else {
		if (bin2hex(d1, sizeof(d1), cH2, sizeof(cH2)) < 0) {
			ERROR_LOG("\n Failed to convert binary hash to hex");
			return;
		}
    }
#endif
	DEBUG_LOG("\n%s %s\n", "Hash Measured:", cH2);
	fprintf(fc, "%s", cH2);
	fclose(fc);
}

/*
* Main function which checks for the different input parameters
* provided to the verifier and calls a xml parsing function
*/
int main(int argc, char **argv) {
    char manifest_file[512] = {'\0'};
	char fmanifest_file[512] = { '\0' };
    if(argc != 4) {
        ERROR_LOG("\n%s %s %s","Usage:",argv[0]," <manifest_path> <mounted_path> <IMVM/HOST>");
        return EXIT_FAILURE;
    }
    DEBUG_LOG("\n%s %s","MANIFEST-PATH :", argv[1]);
	DEBUG_LOG("\n%s %s","MOUNTED-PATH :", argv[2]);
	DEBUG_LOG("\n MODE : %s\n", argv[3]);
  
	strcpy_s(manifest_file,sizeof(manifest_file),argv[1]);
	strcpy_s(fs_mount_path,sizeof(fs_mount_path),argv[2]);
	//strcat_s(fs_mount_path,sizeof(fs_mount_path),"/");
	if (strcmp(argv[3], "IMVM") == 0) {
    	char* last_oblique_ptr = strrchr(manifest_file, '/');
		strncpy_s(hash_file,sizeof(hash_file),manifest_file,strnlen_s(manifest_file,sizeof(manifest_file))-strnlen_s(last_oblique_ptr + 1,sizeof("/manifest.xml")));
#ifdef _WIN32
		strcpy_s(fmanifest_file,sizeof(fmanifest_file),hash_file);
		strcat_s(fmanifest_file,sizeof(fmanifest_file),"/fmanifest.xml");
		DEBUG_LOG("\n%s", fmanifest_file);
#endif
    	strcat_s(hash_file,sizeof(hash_file),"measurement.");
		DEBUG_LOG("\n%s", hash_file);
	}
	else if (strcmp(argv[3], "HOST") == 0) {
        snprintf(hash_file, sizeof(hash_file), "%s/var/log/trustagent/measurement.", fs_mount_path);
		DEBUG_LOG("\n%s", hash_file);
	}
	else {
		ERROR_LOG("\n%s", "Invalid verification_type.Valid options are IMVM/HOST");
		return EXIT_FAILURE;
	}

	/*This will save the XML file in a correct format, as desired by our parser.
	We dont use libxml tools to parse but our own pointer legerdemain for the time being
	Main advantage is simplicity and speed ~O(n) provided space isn't an issue */
	/*This would render even inline XML perfect for line by line parsing*/
#ifdef _WIN32
	formatManifest(argv[1], fmanifest_file);
	if (_chmod(fmanifest_file, _S_IREAD | _S_IWRITE) == -1) {
		ERROR_LOG("Failed to provide read write permissions to formatted manifest file %s ", fmanifest_file);
		return EXIT_FAILURE;
	}
	generateLogs(fmanifest_file, argv[2], argv[3]);
	DeleteFile(fmanifest_file);
#elif __linux__
	xmlDocPtr Doc = xmlParseFile(argv[1]);
	xmlSaveFormatFile (argv[1], Doc, 1);
    xmlFreeDoc(Doc);  
	generateLogs(argv[1], argv[2], argv[3]);
#endif
	return 0;
}
