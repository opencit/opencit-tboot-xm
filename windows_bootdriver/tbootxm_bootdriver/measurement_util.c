#include "measurement_util.h"

char cH2[MAX_HASH_LEN];
char hashType[10]; //SHA1 or SHA256
char fs_root_path[1024] = "\\DosDevices\\";
unsigned char cH[MAX_HASH_LEN] = { '\0' };

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
	DWORD out_data_size;
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

char *GetTagValue(char *line, char *tag, char **sub_line)
{
	size_t cb_tag;
	RtlStringCbLengthA(tag, MAX_LEN, &cb_tag);
	DbgPrint("tag length : %d\n", cb_tag);

	int i = cb_tag + 2;
	*sub_line = strstr(line, tag);
	if (*sub_line == NULL)
	{
		DbgPrint("%s does not contain %s\n", line, tag);
		return NULL;
	}
	char *start = &(sub_line[0])[i];
	while ((*sub_line)[i] != '\"')
		i++;
	char *end = &(sub_line[0])[i];

	int buffer_size = (int)(end - start + 1);
	char *value = (char *)malloc(buffer_size);
	RtlZeroMemory(value, buffer_size);
	RtlMoveMemory(value, start, end - start);
	return value;
}

void PopulateElementAttribues(void **structure, enum TagType tag, char *line)
{
	char *subline;
	if (tag == Manifest)
	{
		DbgPrint("Manifest element found %s\n", line);
		struct ManifestHeader *header = ((struct ManifestHeader *) *structure);
		header->xmlns = GetTagValue(line, xmlns_tag, &subline);
		DbgPrint("Policy Version to be used : %s\n", header->xmlns);
		header->DigestAlg = GetTagValue(line, hash_algo_tag, &subline);
		DbgPrint("Digest Algorithm to be used : %s\n", header->DigestAlg);
	}

	if (tag == File)
	{
		DbgPrint("File element found %s\n", line);
		struct ManifestFile *file = ((struct ManifestFile *) *structure);
		file->Path = GetTagValue(line, path_tag, &subline);
		DbgPrint("Path of the file is : %s\n", file->Path);
	}

	if (tag == Directory)
	{
		DbgPrint("Dir element found %s\n", line);
		struct ManifestDirectory *dir = ((struct ManifestDirectory *) *structure);
		dir->Include = GetTagValue(line, dir_include_tag, &subline);
		DbgPrint("Include tag : %s\n", dir->Include);
		dir->Exclude = GetTagValue(line, dir_exclude_tag, &subline);
		DbgPrint("Exclude tag : %s\n", dir->Exclude);
		//dir->Recursive = GetTagValue(line, dir_recursive_tag, &subline);
		//DbgPrint("Recursive tag : %s\n", dir->Recursive);
		dir->FilterType = GetTagValue(line, dir_filter_type_tag, &subline);
		DbgPrint("FilterType tag : %s\n", dir->FilterType);
		dir->Path = GetTagValue(line, path_tag, &subline);
		DbgPrint("Path tag : %s\n", dir->Path);
	}
}

void bin2hex(unsigned char *byte_buffer, int byte_buffer_len, char *hex_str, int hex_str_len)
{
	RtlZeroMemory(hex_str, hex_str_len);
	const char bin_char_map[] = "0123456789abcdef";
	int index;
	for (index = 0; index < byte_buffer_len; index++) {
		hex_str[2 * index] = bin_char_map[(byte_buffer[index] >> 4) & 0x0F];
		hex_str[2 * index + 1] = bin_char_map[byte_buffer[index] & 0x0F];
	}
}

void WriteMeasurementFile(char *line, char *hash, HANDLE handle1, IO_STATUS_BLOCK ioStatusBlock1, enum TagType tag)
{
	NTSTATUS ntstatus;
	size_t cb_line, cb_hash;
	char *new_line = NULL;
	//int buffer_size;
	//char *buffer = NULL;

	if (hash != NULL)
	{
		int end_tag_max_size = 12;
		RtlStringCbLengthA(line, MAX_LEN, &cb_line);
		DbgPrint("line length : %d\n", cb_line);

		RtlStringCbLengthA(hash, MAX_LEN, &cb_hash);
		DbgPrint("hash length : %d\n", cb_hash);

		int new_line_size = cb_line + cb_hash + end_tag_max_size;
		int old_size = cb_line;
		new_line = (char *)malloc(new_line_size);
		RtlZeroMemory(new_line, new_line_size);
		RtlMoveMemory(new_line, line, old_size);
		line = new_line;
		line[old_size - 3] = '>';
		line[old_size - 2] = '\0';
		RtlStringCbCatA(line, new_line_size, hash);
		if (tag == File)
		{
			RtlStringCbCatA(line, new_line_size, "</File>\r\n");
		}
		if (tag == Directory)
		{
			RtlStringCbCatA(line, new_line_size, "</Dir>\r\n");
		}
	}

	RtlStringCbLengthA(line, MAX_LEN, &cb_line);
	DbgPrint("line length : %d\n", cb_line);

	ntstatus = ZwWriteFile(handle1, NULL, NULL, NULL, &ioStatusBlock1, line, cb_line, NULL, NULL);
	DbgPrint("ZwWriteFile returns : 0x%x\n", ntstatus);
	if(new_line)
		free(new_line);
}

/*This function keeps track of the cumulative hash and stores it in a global variable (which is later written to a file) */
void generate_cumulative_hash(char *hash){
	DbgPrint("Incoming Hash : %s\n", hash);
	//char ob[MAX_HASH_LEN] = { '\0' };
	//unsigned char cHash_buffer[MAX_HASH_LEN] = { '\0' };

	BCRYPT_ALG_HANDLE       handle_Alg = NULL;
	BCRYPT_HASH_HANDLE      handle_Hash_object = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD					hash_size = 0, hashObject_size = 0;
	PBYTE                   hashObject_ptr = NULL, hash_ptr = NULL;

	//strncpy_s((char *)cHash_buffer, sizeof(cHash_buffer), (char *)cH, strnlen_s(cH, MAX_HASH_LEN));
	//bin2hex(cHash_buffer, strnlen_s(cHash_buffer, MAX_HASH_LEN), ob, sizeof(ob));
	//DbgPrint("Cumulative Hash before : %s\n", ob);

	status = setup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hashObject_size, &hash_ptr, &hash_size);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Could not inititalize CNG args Provider : 0x%x\n", status);
		return;
	}

	status = BCryptHashData(handle_Hash_object, cH, hash_size, 0);
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
		return;
	}

	status = BCryptHashData(handle_Hash_object, hash, hash_size, 0);
	if (!NT_SUCCESS(status)) {
		cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
		return;
	}

	//Dump the hash in variable and finish the Hash Object handle
	status = BCryptFinishHash(handle_Hash_object, hash_ptr, hash_size, 0);
	RtlZeroMemory(cH, MAX_HASH_LEN); 
	RtlMoveMemory(cH, hash_ptr, hash_size);
	cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);

	//strncpy_s((char *)cHash_buffer, sizeof(cHash_buffer), (char *)cH, strnlen_s(cH, MAX_HASH_LEN));
	//bin2hex(cHash_buffer, strnlen_s(cHash_buffer, MAX_HASH_LEN), ob, sizeof(ob));
	//DbgPrint("Cumulative Hash after is : %s\n", ob);
}

/*
* calculate:
* @path : path of the file
* @output : character array for storing the resulted file hash
*
* Calculate hash of file
*/
char* calculate(char *path, char *output) {
	char value[1056] = { '\0' };
	/*We append the mount path before the filepath first,
	and then pass that address to calculate the hash */

	HANDLE				handle;
	NTSTATUS			ntstatus;
	ANSI_STRING			ntName;
	UNICODE_STRING		uniName;
	IO_STATUS_BLOCK		ioStatusBlock;
	OBJECT_ATTRIBUTES	objAttr;

	DbgPrint("path : %s\n", path);
	RtlStringCbCopyA(value, sizeof(value), fs_root_path);
	RtlStringCbCatA(value, sizeof(value), path); //Value = Mount Path + Path in the image/disk
	DbgPrint("Mounted file path for file %s is %s\n", path, value);

	/*How the process works:
	1. Open the file pointed by value
	2. Read the file contents into char * buffer
	3. Pass those to SHA function.(Output to char output passed to the function)
	4. Return the Output string.
	*/

	BCRYPT_ALG_HANDLE       handle_Alg = NULL;
	BCRYPT_HASH_HANDLE      handle_Hash_object = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   hash_size = 0, hashObject_size = 0;
	PBYTE                   hashObject_ptr = NULL, hash_ptr = NULL;

	RtlInitAnsiString(&ntName, value);
	RtlAnsiStringToUnicodeString(&uniName, &ntName, TRUE);
	InitializeObjectAttributes(&objAttr, &uniName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	ntstatus = ZwCreateFile(&handle,
		GENERIC_READ,
		&objAttr, &ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	DbgPrint("ZwCreateFile returns 0x%x\n", ntstatus);

	if (!NT_SUCCESS(ntstatus)) {
		DbgPrint("File not found - %s\n", value);
		return NULL;
	}

	char *buffer = (char *)malloc(MAX_LEN);
	if (!buffer) {
		DbgPrint("Buffer could not be allocated\n");
		return NULL;
	}

	status = setup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hashObject_size, &hash_ptr, &hash_size);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Could not inititalize CNG args Provider : 0x%x\n", status);
		goto close_handle;
	}

	while (TRUE) {
		RtlZeroMemory(buffer, MAX_LEN);
		ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock, buffer, MAX_LEN, NULL, NULL);

		if (NT_SUCCESS(ntstatus) || ntstatus == STATUS_END_OF_FILE) {
			DbgPrint("buffer : %s\n", buffer);
			DbgPrint("bytesRead : %d\n", ioStatusBlock.Information);
			if (ioStatusBlock.Information == 0) {
				DbgPrint("No more data to hash\n");
				break;
			}

			status = BCryptHashData(handle_Hash_object, buffer, ioStatusBlock.Information, 0);
			if (!NT_SUCCESS(status)) {
				DbgPrint("Could not calculate hash : 0x%x\n", status);
				cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);
				goto close_handle;
			}
		}
		else {
			DbgPrint("File reading error\n");
			break;
		}
	}

	//Dump the hash in variable and finish the Hash Object handle
	status = BCryptFinishHash(handle_Hash_object, hash_ptr, hash_size, 0);
	DbgPrint("Calculated Hash Bin : %s\n", hash_ptr);
	bin2hex(hash_ptr, hash_size, output, MAX_HASH_LEN);
	DbgPrint("Calculated Hash Hex : %s\n", output);
	generate_cumulative_hash(hash_ptr);
	cleanup_CNG_api_args(&handle_Alg, &handle_Hash_object, &hashObject_ptr, &hash_ptr);

close_handle:
	ZwClose(handle);
	free(buffer);
	return output;
}

int ListDirectory(char *path, char *include, char *exclude, char *files_buffer, BCRYPT_HASH_HANDLE *handle_Hash_object) {
	int status = 0;
	char value[1056] = { '\0' };
	/*We append the mount path before the filepath first,
	and then pass that address to calculate the hash */

	HANDLE				handle, event;
	NTSTATUS			ntstatus;
	ANSI_STRING			ntName, ntInclude, ntExclude;
	UNICODE_STRING		uniName, uniInclude, uniExclude;
	IO_STATUS_BLOCK		ioStatusBlock;
	OBJECT_ATTRIBUTES	objAttr;

	DbgPrint("path : %s\n", path);
	RtlStringCbCopyA(value, sizeof(value), fs_root_path);
	RtlStringCbCatA(value, sizeof(value), path); //Value = Mount Path + Path in the image/disk
	DbgPrint("Mounted file path for file %s is %s\n", path, value);

	RtlInitAnsiString(&ntName, value);
	RtlAnsiStringToUnicodeString(&uniName, &ntName, TRUE);
	InitializeObjectAttributes(&objAttr, &uniName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	ntstatus = ZwCreateFile(&handle,
		SYNCHRONIZE,
		&objAttr, &ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_DIRECTORY,
		0,
		FILE_OPEN,
		FILE_DIRECTORY_FILE,
		NULL, 0);
	DbgPrint("ZwCreateFile returns 0x%x\n", ntstatus);

	if (!NT_SUCCESS(ntstatus)) {
		DbgPrint("File not found - %s\n", value);
		return -1;
	}

	ntstatus = ZwCreateEvent(&event, GENERIC_ALL, 0, NotificationEvent, FALSE);
	DbgPrint("ZwCreateEvent returns : 0x%x\n", ntstatus);

	if (!NT_SUCCESS(ntstatus)) {
		DbgPrint("NotificationEvent could not be created\n");
		ZwClose(handle);
		return -1;
	}

	ANSI_STRING as;
	UNICODE_STRING entryName;
	PFILE_DIRECTORY_INFORMATION dirInfo;
	PUCHAR Buffer[MAX_LEN] = { '\0' };
	size_t cb_path, cb_files_buffer;

	RtlInitAnsiString(&ntInclude, include);
	RtlAnsiStringToUnicodeString(&uniInclude, &ntInclude, TRUE);
	RtlInitAnsiString(&ntExclude, exclude);
	RtlAnsiStringToUnicodeString(&uniExclude, &ntExclude, TRUE);

	ntstatus = ZwQueryDirectoryFile(handle,
		event, NULL,
		NULL,
		&ioStatusBlock,
		Buffer,
		sizeof(Buffer),
		FileDirectoryInformation,
		FALSE,
		NULL, FALSE);
	DbgPrint("ZwQueryDirectoryFile returns 0x%x\n", ntstatus);

	if (ntstatus == STATUS_PENDING) {
		ntstatus = ZwWaitForSingleObject(event, TRUE, 0);
		DbgPrint("ZwWaitForSingleObject returns : 0x%x\n", ntstatus);
	}

	if (!NT_SUCCESS(ntstatus)) {
		DbgPrint("Could not get directory information\n");
		status = -1;
		goto close_handle;
	}

	if (*Buffer == 0) {
		DbgPrint("Buffer is Empty\n");
		status = -1;
		goto close_handle;
	}

	dirInfo = (PFILE_DIRECTORY_INFORMATION)Buffer;
	RtlStringCbLengthA(path, MAX_LEN, &cb_path);
	DbgPrint("path length : %d\n", cb_path);

	while (TRUE) {
		entryName.MaximumLength = entryName.Length = (USHORT)dirInfo->FileNameLength;
		entryName.Buffer = &dirInfo->FileName[0];
		RtlUnicodeStringToAnsiString(&as, &entryName, TRUE);
		DbgPrint("FileName : %s\n", as.Buffer);
		DbgPrint("Next Entry Offest : %d\n", dirInfo->NextEntryOffset);
		DbgPrint("File Attributes : %d\n", dirInfo->FileAttributes);
		
		int path_len = cb_path + as.MaximumLength + 2;
		DbgPrint("path_len : %d\n", path_len);
		char *file_path = (char *)malloc(path_len);
		RtlStringCbPrintfA(file_path, path_len, "%s\\%s", path, as.Buffer);
		DbgPrint("file_path : %s\n", file_path);

		if (dirInfo->FileAttributes != FILE_ATTRIBUTE_DIRECTORY) {

			if (FsRtlIsNameInExpression(&uniInclude, &entryName, FALSE, NULL) && !FsRtlIsNameInExpression(&uniExclude, &entryName, FALSE, NULL)) {

				RtlStringCbLengthA(files_buffer, MAX_LEN, &cb_files_buffer);
				DbgPrint("files_buffer length : %d\n", cb_files_buffer);

				if ((cb_files_buffer + path_len - 2) > MAX_LEN) {
					int offset = MAX_LEN - cb_files_buffer - 1;
					RtlStringCbCatNA(files_buffer, MAX_LEN, file_path, offset);

					ntstatus = BCryptHashData(handle_Hash_object, files_buffer, MAX_LEN - 1, 0);
					if (!NT_SUCCESS(ntstatus)) {
						DbgPrint("ListDirectory: Could not calculate directory hash : 0x%x\n", ntstatus);
						free(file_path);
						status = -1;
						goto close_handle;
					}

					RtlZeroMemory(files_buffer, MAX_LEN);
					RtlStringCbCopyA(files_buffer, MAX_LEN, file_path + offset);
					RtlStringCbCatA(files_buffer, MAX_LEN, "\n");
				}
				else {
					RtlStringCbCatNA(files_buffer, MAX_LEN, file_path, path_len);
					RtlStringCbCatA(files_buffer, MAX_LEN, "\n");
				}
				DbgPrint("files_buffer : %s\n", files_buffer);
			}
		}
		free(file_path);

		if (dirInfo->NextEntryOffset == 0) {
			DbgPrint("No more files to show\n");
			break;
		}
		else {
			dirInfo = (PFILE_DIRECTORY_INFORMATION)(((PUCHAR)dirInfo) + dirInfo->NextEntryOffset);
		}
	}

close_handle:
	ZwClose(handle);
	ZwClose(event);
	return status;
}