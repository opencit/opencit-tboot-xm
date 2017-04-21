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

#define DEBUG_LOG(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
#define ERROR_LOG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define byte unsigned char
#define MAX_LEN 4096
#define NODE_LEN 512
#define MAX_HASH_LEN 65

char hashType[10];
char hashFile[NODE_LEN];
char hashBinFilePath[NODE_LEN];
char node_value[NODE_LEN];
char fs_mount_path[NODE_LEN];
int version = 1;

/*These global variables are required for calculating the cumulative hash */
#ifdef _WIN32
unsigned char cH[MAX_HASH_LEN] = {'\0'};
unsigned char uH[MAX_HASH_LEN] = {0};
#elif __linux__
unsigned char cHash256[SHA256_DIGEST_LENGTH] = {'\0'};
unsigned char uHash256[SHA256_DIGEST_LENGTH]={0};
#endif

#ifdef _WIN32
//For xml parsing using xmllite
#define CHKHR(stmt)		do { hr = (stmt); if (FAILED(hr)) goto CleanUp; } while(0) 
#define HR(stmt)		do { hr = (stmt); goto CleanUp; } while(0) 
#define SAFE_RELEASE(I)		do { if (I){ I->lpVtbl->Release(I); } I = NULL; } while(0)

#define NT_SUCCESS(Status)      (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL     ((NTSTATUS)0xC0000001L)

#define malloc(size) 		HeapAlloc(GetProcessHeap(), 0, size)
#define free(mem_ptr) 		HeapFree(GetProcessHeap(),0, mem_ptr)
#define snprintf		sprintf_s

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

#ifdef _WIN32
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
	if (*hashObject_ptr == NULL) {
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
		ERROR_LOG("\nFindFirstFile failed (%ld)\n", GetLastError());
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
		DEBUG_LOG("%ld\n", FindFileData.dwFileAttributes);
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
		ERROR_LOG("\nFindFirstFile failed (%ld)\n", GetLastError());
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
		DEBUG_LOG("%ld\n", FindFileData.dwFileAttributes);
		HANDLE target_handle = CreateFile(path, FILE_GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL, NULL);
		if (target_handle == INVALID_HANDLE_VALUE) {
			ERROR_LOG("\n%s", "couldn't get handle to file");
			return -2;
		}
		int req_size = 32767 + 8;
		char *_buffer;
		_buffer = (char *)malloc(sizeof(wchar_t)* req_size + sizeof(REPARSE_DATA_BUFFER));
		if (_buffer == NULL) {
			ERROR_LOG("Can't allocate memory for _buffer");
			CloseHandle(target_handle);
			return -3;
		}
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
				DEBUG_LOG("\nabsolute path : length : %ld", reparse_buffer->SymbolicLinkReparseBuffer.Flags);
			}
			else {
				DEBUG_LOG("\nrelative path : length : %ld", reparse_buffer->SymbolicLinkReparseBuffer.Flags);
			}
			wlength = reparse_buffer->SymbolicLinkReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1;
			w_complete_path_pname = (WCHAR *)malloc(sizeof(WCHAR) * wlength);
			if (w_complete_path_pname == NULL) {
				ERROR_LOG("Can't allocate memory for w_complete_path_pname");
				target_buf_size = -3;
				goto return_target_link;
			}
			strncpy_s(w_complete_path_pname, wlength, reparse_buffer->SymbolicLinkReparseBuffer.PathBuffer + (reparse_buffer->SymbolicLinkReparseBuffer.PrintNameOffset / sizeof(WCHAR)),
				reparse_buffer->SymbolicLinkReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1);
			wprintf(L"\n wide char Path : %s", w_complete_path_pname);
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, 0, 0, 0, 0);
			complete_path_pname = (char *)malloc(sizeof(CHAR)* clength);
			if (complete_path_pname == NULL) {
				ERROR_LOG("Can't allocate memory for complete_path_pname");
				target_buf_size = -3;
				goto return_target_link;
			}
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
					target_buf = realloc(target_buf, target_buf_length);
					target_buf_size = target_buf_length;
				}
				if (target_buf == NULL) {
					target_buf_size = -3;
					goto return_target_link;
					//return -3;
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
			if (w_complete_path_sname == NULL) {
				ERROR_LOG("Can't allocate memory for w_complete_path_sname");
				target_buf_size = -3;
				goto return_target_link;
			}
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
				target_buf = realloc(target_buf, target_buf_length);
				target_buf_size = target_buf_length;
			}
			if (target_buf == NULL) {
				target_buf_size = -3;
				goto return_target_link;
				//return -3;
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
			if (w_complete_path_pname == NULL) {
				ERROR_LOG("Can't allocate memory for w_complete_path_pname");
				target_buf_size = -3;
				goto return_target_link;
			}
			strncpy_s(w_complete_path_pname, wlength, reparse_buffer->MountPointReparseBuffer.PathBuffer + (reparse_buffer->MountPointReparseBuffer.PrintNameOffset / sizeof(WCHAR)),
				reparse_buffer->MountPointReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1);
			wprintf(L"\n wide char Path : %s", w_complete_path_pname);

			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, 0, 0, 0, 0);
			if (clength > target_buf_size) {
				target_buf = realloc(target_buf, clength);
				target_buf_size = clength;
			}
			//complete_path_pname = (char *)malloc(sizeof(CHAR)* clength);
			if (target_buf == NULL) {
				target_buf_size = -3;
				goto return_target_link;
				//return -3;
			}
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
			if (w_complete_path_sname == NULL) {
				ERROR_LOG("Can't allocate memory for w_complete_path_sname");
				target_buf_size = -3;
				goto return_target_link;
			}
			strncpy_s(w_complete_path_sname, wlength, reparse_buffer->MountPointReparseBuffer.PathBuffer + (reparse_buffer->MountPointReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)),
				reparse_buffer->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR) + 1);

			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, 0, 0, 0, 0);
			if (clength > target_buf_size) {
				target_buf = realloc(target_buf, clength);
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
				memmove_s(target_buf, target_buf_size, target_buf + 4, clength - 4);
			}
			DEBUG_LOG("\nchar path substitute name : %s", target_buf);

		}
		else{
			//this gives the complete path when path contains an junction in it
			int target_len = GetFinalPathNameByHandle(target_handle, target_buf, target_buf_size, VOLUME_NAME_DOS);
			if (target_len >= target_buf_size){
				target_buf = realloc(target_buf, target_len);
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
				memmove_s(target_buf, target_buf_size, target_buf + 4, target_len - 3);
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
		CloseHandle(target_handle);
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
void generate_cumulative_hash(char *hash) {

    DEBUG_LOG("\nIncoming Hash : %s",hash);
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

	strncpy_s((char *)cH,sizeof(cH),(char *)uH,strnlen_s(uH, MAX_HASH_LEN));
	bin2hex(cH, strnlen_s(cH, MAX_HASH_LEN), ob, sizeof(ob));
	DEBUG_LOG("\n%s %s","Cumulative Hash before:",ob);
	
	status = setup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hashObject_size, &hash_ptr, &hash_size);
	if (!NT_SUCCESS(status)) {
		ERROR_LOG("\nCould not inititalize CNG args Provider : 0x%x", status);
		return;
	}
	status = BCryptHashData(handle_Hash_object, uH, hash_size, 0);
	if (!NT_SUCCESS(status)) {
		ERROR_LOG("\nCould not calculate hash : 0x%x", status);
		cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
		return;
	}

	if (hexstr_len == hash_size) {
		status = BCryptHashData(handle_Hash_object, cur_hash, hash_size, 0);
		if (!NT_SUCCESS(status)) {
			ERROR_LOG("\nCould not calculate hash : 0x%x", status);
			cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
			return;
		}
	}
	else {
		DEBUG_LOG("\n length of string converted from hex is : %d not equal to expected hash digest length : %ld", hexstr_len, hash_size);
		ERROR_LOG("\n ERROR: current hash is not being updated in cumulative hash");
	}
	//Dump the hash in variable and finish the Hash Object handle
	status = BCryptFinishHash(handle_Hash_object, hash_ptr, hash_size, 0); 
	memcpy_s(uH, sizeof(uH), hash_ptr, hash_size);
	memcpy_s(cH, sizeof(cH), hash_ptr, hash_size);
	bin2hex(cH, hash_size, ob, sizeof(ob));
	DEBUG_LOG("\n%s %s\n","Cumulative Hash after is:",ob);
	cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
#elif __linux__
	strncpy_s((char *)cHash256,sizeof(cHash256),(char *)uHash256,SHA256_DIGEST_LENGTH);
	bin2hex(cHash256, sizeof(cHash256), ob, sizeof(ob));
	DEBUG_LOG("\n%s %s","Cumulative Hash before:",ob);

	SHA256_CTX csha256;
	SHA256_Init(&csha256);
	SHA256_Update(&csha256,uHash256,SHA256_DIGEST_LENGTH);
	if (hexstr_len == SHA256_DIGEST_LENGTH) {
	    SHA256_Update(&csha256,cur_hash, SHA256_DIGEST_LENGTH);
	}
	else {
	DEBUG_LOG("\n length of string converted from hex is not equal to SHA256 digest length");
	}
	SHA256_Final(uHash256,&csha256);
	   
	memcpy_s((char *)cHash256, sizeof(cHash256), (char *)uHash256,SHA256_DIGEST_LENGTH);
	bin2hex(cHash256, sizeof(cHash256), ob, sizeof(ob));
	DEBUG_LOG("\n%s %s\n","Cumulative Hash after is:",ob);
#endif
}

/*
* getSymLinkValue:
* @path : path of the file/symbolic link
*
* Returns the actual value for the symbolic link provided as input
*/
int getSymLinkValue(char *path) {
	char symlinkpath[512];
        char sympathroot[512];
	//int symlinkpath_size = 512;
	/*char *symlinkpath;
	symlinkpath = (char *)malloc(sizeof(char)*symlinkpath_size);
	if (symlinkpath == NULL) {
		ERROR_LOG("Can't allocate memory for symlinkpath");
		return -1;
	}*/
#ifdef _WIN32
	// Check if the file path is a symbolic link
	if (ISLINK(path) == 0) {
		// If symbolic link doesn't exists read the path its pointing to
		int len = readlink(path, symlinkpath, sizeof(symlinkpath));
		if (len < 0) {
			ERROR_LOG("\n%s", "Error occured in reading link");
			return -1;
		}
		DEBUG_LOG("\n%s %s %s %s", "Symlink", path, " points to", symlinkpath);
		//("Symlink '%s' points to '%s' \n", path, symlinkpath);
		/*char *sympathroot;
		sympathroot = (char *)malloc(sizeof(char)* len);
		if (sympathroot == NULL) {
			ERROR_LOG("Can't allocate memory for sympathroot");
			return -1;
		}*/
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
		//free(symlinkpath);
		//free(sympathroot);
		return getSymLinkValue(path);
        	if(version == 2) {
            	    strcpy_s(path, MAX_LEN, symlinkpath);
		} else {
	    	    return getSymLinkValue(path);
		}
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
#endif
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
    DEBUG_LOG("\nfile path : %s", file_name_buff);
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
		ERROR_LOG("\nCould not inititalize CNG args Provider : 0x%x", status);
		goto cleanup;
	}
	status = BCryptHashData(handle_Hash_object, hash_str, strnlen_s(hash_str, sizeof(hash_str)), 0);
	if (!NT_SUCCESS(status)) {
		ERROR_LOG("\nCould not calculate hash : 0x%x", status);
		cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
		goto cleanup;
	}

	//Dump the hash in variable and finish the Hash Object handle
	status = BCryptFinishHash(handle_Hash_object, hash_ptr, hash_size, 0); 
	bin2hex(hash_ptr, hash_size, output, MAX_HASH_LEN);
	cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
	generate_cumulative_hash(output);
#elif __linux__
    //For SHA 256 hash**Hard dependency on exact usage of 'sha256'
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, hash_str, strnlen_s(hash_str, sizeof(hash_str)));
    SHA256_Final(hash, &sha256);
    bin2hex(hash, sizeof(hash), output, MAX_HASH_LEN);
    generate_cumulative_hash(output);
#endif
	cleanup:
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
    DEBUG_LOG("\nfile path : %s", file_name_buff);
#ifdef _WIN32
    retval = fileExist(file_name_buff);
#elif __linux__
    retval = getSymLinkValue(file_name_buff);
#endif
    if( retval == 0 ) {
	fprintf(fq,"<File Path=\"%s\">",node_value);
	DEBUG_LOG("\n%s %s %s %s","Mounted file path for file",node_value,"is",file_name_buff);
   
	FILE* file = fopen(file_name_buff, "rb");
	if (!file) {
		ERROR_LOG("\n%s %s", "File not found-", file_name_buff);
		goto cleanup;
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

	const int bufSize = 65000;

        buffer = (char *)malloc(bufSize);
        if(!buffer) {
			ERROR_LOG("Can't allocate memory for buffer");
            goto cleanup;
        }

	status = setup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hashObject_size, &hash_ptr, &hash_size);
	if (!NT_SUCCESS(status)) {
		ERROR_LOG("\nCould not inititalize CNG args Provider : 0x%x", status);
		goto cleanup;
	}
	while ((bytesRead = fread(buffer, 1, bufSize, file))) {
		// calculate hash of bytes read
		status = BCryptHashData(handle_Hash_object, buffer, bytesRead, 0);
		if (!NT_SUCCESS(status)) {
			ERROR_LOG("\nCould not calculate hash : 0x%x", status);
			cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
			goto cleanup;
		}
	}

	//Dump the hash in variable and finish the Hash Object handle
	status = BCryptFinishHash(handle_Hash_object, hash_ptr, hash_size, 0); 
	bin2hex(hash_ptr, hash_size, output, MAX_HASH_LEN);
	cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
	generate_cumulative_hash(output);
#elif __linux__
	//For SHA 256 hash**Hard dependency on exact usage of 'sha256'
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 65000;

    buffer = (char *)malloc(bufSize);
    if(!buffer) {
		ERROR_LOG("Can't allocate memory for buffer");
        goto cleanup;
    }
    while((bytesRead = fread(buffer, 1, bufSize, file))) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(hash, &sha256);
    bin2hex(hash, sizeof(hash), output, MAX_HASH_LEN);
    generate_cumulative_hash(output);
#endif
    cleanup:
	if(file) fclose(file);
	if(buffer) free(buffer);

    fprintf(fq,"%s</File>\n", output);
	DEBUG_LOG("\n%s %s %s %s","File :",node_value,"Hash Measured:",output);
    }
}

char* calculateDirHashV1(char *line, FILE *fq) {

#ifdef __linux__
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
	pclose(dir_file);
    }
    else {
	dhash = "\0";
    }
    fprintf(fq,"<Dir Path=\"%s\">",dir_path);
    fprintf(fq,"%s</Dir>\n",dhash);
    generate_cumulative_hash(dhash);
#endif
}

char* calculateDirHashV2(char *line, FILE *fq) {

    int slen = 0;
    int is_wildcard = 0;
    size_t len = 0;
    size_t dhash_max = 128;
    char *dhash = NULL;
    char *temp_ptr = NULL;
    char *next_token = NULL;
	char output[MAX_HASH_LEN] = { '\0' };
	char dir_path[NODE_LEN] = { '\0' };
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
#ifdef _WIN32
    //TODO need to write in sync with linux 
    //char temp_dir_file_list[32] = "/tmp/dir_file.txt";
    if (strcmp(include, "") != 0 && strcmp(exclude, "") != 0)
	snprintf(Dir_Str, sizeof(Dir_Str), "Powershell \"Get-ChildItem '%s' | Where-Object {! $_.PSIsContainer}" 
					" | Where-Object { $_.FullName.remove(0, %d) -cmatch '%s' -and $_.FullName.remove(0, %d) -cnotmatch '%s' }" 
					" | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"",
					mDpath, slen, include, slen, exclude, slen);
    else if (strcmp(include, "") != 0)
	snprintf(Dir_Str, sizeof(Dir_Str), "Powershell \"Get-ChildItem '%s' | Where-Object {! $_.PSIsContainer}" 
					" | Where-Object { $_.FullName.remove(0, %d) -cmatch '%s' }" 
					" | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"",
					mDpath, slen, include, slen);
    else if (strcmp(exclude, "") != 0)
	snprintf(Dir_Str, sizeof(Dir_Str), "Powershell \"Get-ChildItem '%s' | Where-Object {! $_.PSIsContainer}"
					" | Where-Object { $_.FullName.remove(0, %d) -cnotmatch '%s' }"
					" | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"",
					mDpath, slen, exclude, slen);
    else
	snprintf(Dir_Str, sizeof(Dir_Str), "Powershell \"Get-ChildItem '%s' | Where-Object {! $_.PSIsContainer}"
					" | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"",
					mDpath, slen);


    dir_file = _popen(Dir_Str, "r");
	if (dir_file != NULL) {
		const int bufSize = 65000;
		char *buffer = malloc(bufSize);
		int bytesRead = 0;
		if (!buffer){
			ERROR_LOG("Can't allocate memory for buffer");
			goto cleanup;
		}

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
			goto cleanup;
		}
		while ((bytesRead = fread(buffer, 1, bufSize, dir_file))) {
			// calculate hash of bytes read
			status = BCryptHashData(handle_Hash_object, buffer, bytesRead, 0);
			if (!NT_SUCCESS(status)) {
				ERROR_LOG("\nCould not calculate hash : 0x%x", status);
				cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
				goto cleanup;
			}
		}

		//Dump the hash in variable and finish the Hash Object handle
		status = BCryptFinishHash(handle_Hash_object, hash_ptr, hash_size, 0);
		bin2hex(hash_ptr, hash_size, output, MAX_HASH_LEN);
		cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
	cleanup:
		if (buffer) free(buffer);
		_pclose(dir_file);
	}
#elif __linux__
    snprintf(hash_algo,sizeof(hash_algo),"%ssum",hashType);

    if(strcmp(include,"") != 0 && strcmp(exclude,"") != 0 )
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | grep -vE \"%s\" | sort | %s",mDpath, slen, include, exclude, hash_algo);
    else if(strcmp(include,"") != 0)
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | sort | %s",mDpath, slen, include, hash_algo);
    else if(strcmp(exclude,"") != 0)
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -vE \"%s\" | sort | %s",mDpath, slen, exclude, hash_algo);
    else
        snprintf(Dir_Str, sizeof(Dir_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | sort | %s",mDpath, slen, hash_algo);

    DEBUG_LOG("\n%s %s %s %s","********mDpath is ----------",mDpath," and command is ",Dir_Str);

    dir_file = popen(Dir_Str,"r");
    if (dir_file != NULL ) {
		getline(&dhash, &len, dir_file);
		strtok_s(dhash,&dhash_max," ",&next_token);
		strcpy_s(output, MAX_HASH_LEN, dhash);
		pclose(dir_file);
    }
#endif
    fprintf(fq,"<Dir Path=\"%s\">",dir_path);
    fprintf(fq,"%s</Dir>\n",output);
    generate_cumulative_hash(output);
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
void generateMeasurementLogs(const char *origManifestPath, char *imagePath, char *verificationType) {

    int digest_check = 0;
	int cumulative_hash_size = 32;
    size_t len = 32768;
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
	if (fp == NULL) {
		ERROR_LOG("Can not open Manifest file: %s", origManifestPath);
		return;
	}
	fq = fopen(ma_result_path,"w");
	if (fq == NULL) {
		ERROR_LOG("Can not open file: %s to write the measurement", ma_result_path);
		fclose(fp);
		return;
	}
#ifdef _WIN32
	_chmod(ma_result_path, _S_IREAD | _S_IWRITE);
#elif __linux__
	chmod(ma_result_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif
    fprintf(fq,"<?xml version=\"1.0\"?>\n");
	//Open Manifest to get list of files to hash
	line = (char *)malloc(sizeof(char) * len);
	while (fgets(line, len, fp) != NULL) {
		DEBUG_LOG("\n%s %s","Line Read",line);
		if(feof(fp)) {
			DEBUG_LOG("%s","End of file found\n");
		    break;
		}
		if(strstr(line,"<Manifest ") != NULL) {
		    temp_ptr = strstr(line,"DigestAlg=");
		    if(temp_ptr != NULL){
		        /*Get the type of hash */
		        tagEntry(temp_ptr);
		        strcpy_s(hashType,sizeof(hashType),node_value);		    
		        digest_check = 1;
		        DEBUG_LOG("\n%s %s","Type of Hash used :",hashType);
		    }
		    temp_ptr = NULL;
		    temp_ptr = strstr(line,"xmlns=");
		    if(temp_ptr != NULL){
		        /*Get the type of version */
		        tagEntry(temp_ptr);
				version = node_value[strnlen_s("mtwilson:trustdirector:manifest:1.1", 256) - 1] - '0';
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
	fprintf(fq, "</Measurements>");
	fclose(fq);
	fclose(fp);

	if(!digest_check){
		ERROR_LOG("\n%s","Hash Algorithm not specified!");
		return;
	}
	
	// File name for hash file binary data
	strcat_s(hashBinFilePath, sizeof(hashBinFilePath), hashFile);
	strcat_s(hashBinFilePath, sizeof(hashBinFilePath), "bin");
	
	strcat_s(hashFile, sizeof(hashFile), hashType);
    /*Write the Cumulative Hash calculated to the file*/
    FILE *fc = fopen(hashFile, "w");
	if (fc == NULL) {
		ERROR_LOG("\n%s %s", "Can not open file to write cumulative hash :", hashFile);
		return;
	}
#ifdef _WIN32
	_chmod(hashFile, _S_IREAD | _S_IWRITE);
	bin2hex(uH, cumulative_hash_size, cH, sizeof(cH));
#elif __linux__
    chmod(hashFile, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	bin2hex(uHash256, sizeof(uHash256), cH, sizeof(cH));
	
	// Write to binary hash file
	DEBUG_LOG("\n%s %s","Attempting to write hash binary data to file :", hashBinFilePath);
	FILE *hashBinFile = fopen(hashBinFilePath, "w");
	if (hashBinFile == NULL) {
		ERROR_LOG("\n%s %s", "Can not open file to write binary cumulative hash :", hashBinFilePath);
		return;
	}
	fwrite(uHash256, 1, SHA256_DIGEST_LENGTH, hashBinFile);
	//fprintf(hashBinFile, "%s", uHash256);
	fclose(hashBinFile);
#endif
	DEBUG_LOG("\n%s %s", "Hash Measured :", cH);
	fprintf(fc, "%s", cH);
	fclose(fc);
}

/*
* Main function which checks for the different input parameters
* provided to the verifier and calls a xml parsing function
*/
int main(int argc, char **argv) {
    char manifest_file[512] = {'\0'};
    char fmanifest_file[512] = { '\0' };
    char* last_oblique_ptr = NULL;

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
#ifdef __linux__
    memset_s((char *)cHash256,strnlen_s((char *)cHash256,sizeof(cHash256)),0);
#endif
    if (strcmp(argv[3], "IMVM") == 0) {
    	last_oblique_ptr = strrchr(manifest_file, '/');
	strncpy_s(hashFile,sizeof(hashFile),manifest_file,strnlen_s(manifest_file,sizeof(manifest_file))-strnlen_s(last_oblique_ptr + 1,sizeof("/manifest.xml")));
#ifdef _WIN32
	strcpy_s(fmanifest_file,sizeof(fmanifest_file),hashFile);
	strcat_s(fmanifest_file,sizeof(fmanifest_file),"/fmanifest.xml");
	DEBUG_LOG("\n%s", fmanifest_file);
#endif
    	strcat_s(hashFile,sizeof(hashFile),"measurement.");
	DEBUG_LOG("\n%s %s", "Hash File", hashFile);
    }
    else if (strcmp(argv[3], "HOST") == 0) {
        snprintf(hashFile, sizeof(hashFile), "%s/var/log/trustagent/measurement.", fs_mount_path);
	DEBUG_LOG("\n%s", hashFile);
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
	generateMeasurementLogs(fmanifest_file, argv[2], argv[3]);
	DeleteFile(fmanifest_file);
#elif __linux__
	xmlDocPtr Doc = xmlParseFile(argv[1]);
	xmlSaveFormatFile (argv[1], Doc, 1);
	xmlFreeDoc(Doc);  
	generateMeasurementLogs(argv[1], argv[2], argv[3]);
#endif
	return 0;
}
