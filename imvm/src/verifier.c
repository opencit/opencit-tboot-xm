/* Measurement Agent - Lite 
@SRK 
Intel Corp - CSS-DCG 
What it does: Creates Logs for files/Directories. Handles Incl/Excl case
                                                  Directory Hashes calculated differently as compared to TD (TD passes the file object to calculate(), here we pass file path instead)----> Discuss 
                                                  XML format agnostic. As long as the tag's there, it should rock. 												  
											  

Keywords in the Policy should match with those in this code.
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

#define MOUNTPATH_IMVM  "/tmp/"
#define MOUNTPATH_HOST  "/tmp/root"

char fs_mount_path[1024];
char hashType[10]; //SHA1 or SHA256
char value[512];
char NodeValue[500]; //XML Tag value


/*These global variables are required for calculating the cumulative hash */
unsigned char cHash[SHA_DIGEST_LENGTH]; //Cumulative hash
unsigned char d1[SHA_DIGEST_LENGTH];
unsigned char d2[SHA256_DIGEST_LENGTH];
unsigned char c2[SHA256_DIGEST_LENGTH];
char cH2[65];
char hash_file[256];

int process_started = 0;
SHA256_CTX csha256;
SHA_CTX csha1;

/* May need this one for Sym Link thing 
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


/*May need this function for Cumulative Hash? 
 * sha256_hash_string:
 * @hash : hash value for the file
 *
 * Store hash of file in "fileHashes.txt"
 */
char* sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]) {
    int i;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    
    return outputBuffer;
}


/* See line 40. 
 * sha1_hash_string:
 * @hash : hash value for the file
 *
 * Store hash of file in "fileHashes.txt"
 */
char* sha1_hash_string (unsigned char hash[SHA_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;
    for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
   
    return outputBuffer;
}



/*This function keeps track of the cumulative hash and stores it in a global variable (which is later written to a file)

  

*/

unsigned char* Hex2Bin(char *HexString,int sha1){
	
  BIGNUM *input = BN_new();
  int input_length = BN_hex2bn(&input, HexString);
  input_length = (input_length + 1) / 2; // BN_hex2bn() returns number of hex digits
  unsigned char *input_buffer = (unsigned char*)malloc(input_length);
  int retval = BN_bn2bin(input, input_buffer);
  char ob[65];
  
  return sha1_hash_string(input_buffer,ob); 
 
}

/*This function keeps track of the cumulative hash and stores it in a global variable (which is later written to a file) */

void generate_cumulative_hash(char *hash,int sha_one, int type){
	
	unsigned char hash_c1[SHA_DIGEST_LENGTH];
	unsigned char hash_c2[SHA256_DIGEST_LENGTH];
	unsigned char digest[SHA256_DIGEST_LENGTH];
	
	
	//char *ptr;
	char ob[65];
    if(sha_one){
	/*process_started tells us whether to initialize the SHA st. or not */	
	 
	   if(!process_started){
	   
	   SHA1_Init(&csha1);
	   SHA1_Update(&csha1,hash,strlen(hash));
	   SHA1_Final(d1,&csha1);
	   process_started = 1;
	   
	   }
	   
	   else{
		  
		   SHA1_Init(&csha1);
	   SHA1_Update(&csha1,d1,SHA_DIGEST_LENGTH);
	   SHA1_Update(&csha1,hash,strlen(hash));
	   SHA1_Final(d1,&csha1);
		   
	   }
       
	   
	   
	  
	   
       strncpy(cHash,d1,SHA_DIGEST_LENGTH);
	
	   
	   memset(ob,'\0',strlen(ob));
	   
	   return;
	}
	
	else{
	   
	  
	   if(!process_started){
	   
	   SHA256_Init(&csha256);
	   
	   SHA256_Update(&csha256,hash,strlen(hash));
	   SHA256_Final(d2, &csha256);
	   process_started = 1;
	   
	   }
	   else {
		   SHA256_Init(&csha256);
	   SHA256_Update(&csha256,d2,SHA256_DIGEST_LENGTH);
	   SHA256_Update(&csha256,hash,strlen(hash));
	   SHA256_Final(d2, &csha256);
	   process_started = 1;
		   
	   }
	  
       
	   memset(ob,'0',strlen(ob));
	   
	   return;
		
	}
	
}




/*
 * calculate:
 * @path : path of the file
 * @output : character array for storing the resulted file hash
 *
 * Calculate hash of file
 */
char* calculate(char *path, char output[65], int type) {
    
    char buf[512];
    char hash_in[65];
    /*We append the mount path before the filepath first, 
	 and then pass that address to calculate the hash */
    
   // getSymLinkValue(path);

    strcpy(buf, fs_mount_path);
    strcpy(value, fs_mount_path);
    strcat(buf, path);
    strcat(value,path);//Value = Mount Path + Path in the image/disk
    
    FILE* file = fopen(value, "rb");
    if(!file) return NULL;
   
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
        char *buffer = malloc(bufSize);
       
        int bytesRead = 0;
        if(!buffer) return NULL;
        while((bytesRead = fread(buffer, 1, bufSize, file))) {
             
              SHA256_Update(&sha256, buffer, bytesRead);
        }
        SHA256_Final(hash, &sha256);
        output = sha256_hash_string(hash, output);
		strcpy(hash_in,output);
        generate_cumulative_hash(output,0,type);
        fclose(file);
      
        free(buffer);
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
	generate_cumulative_hash(output,1,type);
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
										  <Whitelist DigestAlg= **** Hard Dependency
										  Include **** Hard Dependency     
										  Exclude **** Hard Dependency
and generates appropriate logs. 

Maybe we can have a to_upper/lower kinda function here that can take care of format issues.(Not covered in the Lite version)

Manifest path is passed as the argument to the function.
Log path is currently hardcoded as /root/MA_Hash.xml -----> Configurable. 

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
	memset(ma_result_path,'\0',strlen(ma_result_path));
    char ma_result_path_default[100]="/var/log/trustagent/measurement.xml";
   

    if(strcmp(verificationType,"HOST") == 0)
    {
            sprintf(ma_result_path, "%s%s", MOUNTPATH_HOST, ma_result_path_default);
            
    }
    else
    {
        
        sprintf(ma_result_path,"%s%s",hash_file,"xml");

		
    }
    
	
    fp=fopen(origManifestPath,"r");
    fq=fopen(ma_result_path,"w");

   fprintf(fq,"<?xml version=\"1.0\"?>\n");
    

   //Open Manifest to get list of files to hash
    while (getline(&line, &len, fp) != -1) { 
   
     strcpy(include,"");
     strcpy(exclude,"");
    
          if(strstr(line,"DigestAlg=") != NULL){
		   /*Get the type of hash */	  
           tagEntry(strstr(line,"DigestAlg="));
           strcpy(hashType,NodeValue);
		  
		   fprintf(fq,"<Measurements xmlns=\"mtwilson:trustdirector:measurements:1.1\" DigestAlg=\"%s\">\n",hashType);
         }


     //File Hashes
          if(strstr(line,"<File Path=")!= NULL){
            tagEntry(line);
            fprintf(fq,"<File Path=\"%s\">",NodeValue);
            fprintf(fq,"%s</File>\n",calculate(NodeValue,calc_hash,1));          
          }

     //Directory Hashes
   
          if(strstr(line,"<Dir ")!= NULL){
                
                tagEntry(strstr(line,"Path="));
                char dir_path[500];
                strcpy(dir_path,NodeValue); 
                
			 if(strstr(line,"Include=")!= NULL){
                         tagEntry(strstr(line,"Include="));
                         strcpy(include,NodeValue);
                         
                }

                if(strstr(line,"Exclude=") != NULL){
                         tagEntry(strstr(line,"Exclude="));
                         strcpy(exclude,NodeValue);
                         
                 }
            
	    char Dir_Str[256];
            
            char mDpath[256];
            strcpy(mDpath,fs_mount_path);
            strcat(mDpath,dir_path);//path of dir in the VM
            
	    char *df = "Dirfiles.txt"; 
            /*df is used to hold the temporary file that stores the directory hash (after we get it using openssl) */
            
            if(strcmp(include,"") != 0 && strcmp(exclude,"") != 0 )
               sprintf(Dir_Str,"find %s ! -type d | grep -E  \"%s\" | grep -vE \"%s\" | openssl dgst -%s >%s",mDpath,include,exclude,hashType,df);  
            else if(strcmp(include,"") != 0)
               sprintf(Dir_Str,"find %s ! -type d | grep -E  \"%s\" | openssl dgst -%s >%s",mDpath,include,hashType,df);
            else if(strcmp(exclude,"") != 0)
               sprintf(Dir_Str,"find %s ! -type d | grep -vE \"%s\" | openssl dgst -%s >%s",mDpath,exclude,hashType,df);
            else
               sprintf(Dir_Str,"find %s ! -type d | openssl dgst -%s >%s",mDpath,hashType,df);

          	
            system(Dir_Str);
	        
			/*Calculate the hash of the directory files using openssl and o/p the stdout to Dirfiles.txt file 
			then read that value from the file. 
			In this file, the result is stored as stdout  = "Hash",
			so we just take the values after '='
			*/
			
            FILE *fy;
            fy=fopen(df,"r");
            char *dhash = NULL;
            getline(&dhash, &len, fy);
            char *dp = strstr(dhash,"= ");
            dp++;
            dp++; /* Navigate until you reach the actual hash, after spaces */
            dhash = dp;
           
            fprintf(fq,"<Dir Path=\"%s\">",dir_path);
            fprintf(fq,"%s</Dir>\n",dhash);//call directory hash function here
			if(strcmp(hashType, "sha256") == 0)
			   generate_cumulative_hash(Hex2Bin(dhash,0),0,1);
		    else
			   generate_cumulative_hash(Hex2Bin(dhash,1),1,1);
            sprintf(Dir_Str,"rm -rf %s",df); //Remove the Directory file. 
            system(Dir_Str);
			fclose(fy);

          }//Dir hash ends




    }//While ends
    
    fprintf(fq,"</Measurements>");
    fclose(fp);
    fclose(fq);

   

    //strcat(hash_file,hashType);
     if(strcmp(verificationType,"HOST") == 0)
    {
         strcat(hash_file,"sha1");
    }
    else
       strcat(hash_file,"sha256"); 


    FILE *fc = fopen(hash_file,"w");
    
        char *ptr;
        if(strcmp(hashType, "sha256") == 0)
           ptr = sha256_hash_string(d2,cH2);
    else
           ptr = sha1_hash_string(d1,cH2);

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
   pid_t pid = getpid();
   char verifierpid[64] = {0};
   sprintf(verifierpid,"%d",pid);
   xmlDocPtr Doc;
	char* mount_script = "../../scripts/mount_vm_image.sh";
    if(argc != 4) {
        printf("Usage:\n%s <manifest_path> <disk_path> <IMVM/HOST>  \n", argv[0]);
        return EXIT_FAILURE;
    }


    printf("MANIFEST-PATH : %s\n", argv[1]);
    printf("DISK-PATH : %s\n", argv[2]);
	strcpy(manifest_file,argv[1]);
	
    memset(cHash,0,strlen(cHash));
   if (strcmp(argv[3], "IMVM") == 0) {
        strcpy(fs_mount_path, MOUNTPATH_IMVM);
	strcat(fs_mount_path,verifierpid);
        //strcpy(hash_file,"/var/log/trustagent/measurement.");
		strncpy(hash_file,manifest_file,strlen(manifest_file)-strlen("/manifestlist.xml"));
        sprintf(hash_file,"%s%s",hash_file,"/measurement.");
        

        imageMountingRequired = 1;
    } else if (strcmp(argv[3], "HOST") == 0) {
        strcpy(fs_mount_path, MOUNTPATH_HOST);
        sprintf(hash_file, "%s/var/log/trustagent/measurement.", fs_mount_path);
        imageMountingRequired = 0;
    } else { 
        printf("Invalid verification_type.Valid options are IMVM/HOST\n");
        return EXIT_FAILURE;
    }

  
    if (imageMountingRequired) {
            char command[512];
            sprintf(command,"%s %s %s", mount_script, argv[2], fs_mount_path);
            int res = system(command);
            if (res !=0) {
                printf("\nError in mounting the image!!!!\n");
                exit(1);
            }
	    strcat(fs_mount_path,"/mount");
    }

    Doc = xmlParseFile(argv[1]); 
	
	/*This will save the XML file in a correct format, as desired by our parser. 
	We dont use libxml tools to parse but our own pointer legerdemain for the time being
	Main advantage is simplicity and speed ~O(n) provided space isn't an issue */
	
    xmlSaveFormatFile (argv[1], Doc, 1); /*This would render even inline XML perfect for line by line parsing*/  
    xmlFreeDoc(Doc);  
    
    generateLogs(argv[1], argv[2], argv[3]);
    


    // Unmount the disk image after verification process completes Not sure about this
    if (strcmp(argv[3], "IMVM") == 0) {
	   char command[512]={'\0'};
	   sprintf(command,"%s %s",mount_script,fs_mount_path);  
	   system(command);    
    }   
    return 0;
}
































