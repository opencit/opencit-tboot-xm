#define INITGUID
#include <ntifs.h>
#include <ntddk.h>

#define NTSTRSAFE_LIB
#include<ntstrsafe.h>
#include<ntdddisk.h>
#include<wmilib.h>
#include<bcrypt.h>
#include<tbs.h>

#define	MAX_LEN				512
#define DISK_MAXSTR			64
#define MAX_HASH_LEN		65

#define malloc(size) ExAllocatePool(PagedPool, size)
#define free(mem_ptr) ExFreePool(mem_ptr)

#define hash_algo_tag "DigestAlg"
#define path_tag "Path"
#define dir_include_tag "Include"
#define dir_exclude_tag "Exclude"
#define dir_recursive_tag "Recursive"

struct ManifestHeader{
	char * DigestAlg;
};

struct ManifestFile{
	char * Path;
};

struct ManifestDirectory{
	char * Path;
	char * Include;
	char * Exclude;
	char * Recursive;
};

enum TagType
{
	Manifest,
	File,
	Directory
};

void cleanup_CNG_api_args(BCRYPT_ALG_HANDLE * handle_Alg, BCRYPT_HASH_HANDLE *handle_Hash_object, PBYTE* hashObject_ptr, PBYTE* hash_ptr);

int setup_CNG_api_args(BCRYPT_ALG_HANDLE * handle_Alg, BCRYPT_HASH_HANDLE *handle_Hash_object, PBYTE* hashObject_ptr, int * hashObject_size, PBYTE* hash_ptr, int * hash_size);

char *GetTagValue(char *line, char *tag, char **sub_line);

void PopulateElementAttribues(void **structure, enum TagType tag, char *line);

void bin2hex(unsigned char *byte_buffer, int byte_buffer_len, char *hex_str, int hex_str_len);

void WriteMeasurementFile(char *line, char *hash, HANDLE handle1, IO_STATUS_BLOCK ioStatusBlock1, enum TagType tag);

void generate_cumulative_hash(char *hash);

char* calculate(char *path, char *output);

void ListDirectory(char *path, char *include, char *exclude, char *recursive, char *files_buffer, BCRYPT_HASH_HANDLE *handle_Hash_object);