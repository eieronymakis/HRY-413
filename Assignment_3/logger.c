#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <errno.h>
#include <linux/limits.h>

/*
	Useful links : 
	-> https://pubs.opengroup.org/onlinepubs/7908799/xsh/fopen.html
	-> https://man7.org/linux/man-pages/man3/realpath.3.html
	-> https://www.openssl.org/docs/man1.1.1/man3/MD5_Final.html
	-> 
*/

typedef enum {CREATION = 0, READ = 1, WRITE = 2, DELETION = 3} ACCESS;
typedef enum {FALSE = 0, TRUE = !FALSE} BOOL;


FILE * fopen(const char *path, const char *mode){
	
	ACCESS A_TYPE;

	// r gives read privilege
	if(* mode == 'r' ){
		A_TYPE = READ;
	}

	// r+ gives read/write privileges I log write privilege for this case. 
	if( strcmp( mode, "r+") ){
		A_TYPE = WRITE;
	}

	// w gives write privilege but w+ gives read/write privilege I log write privilege for both cases.
	if(strchr(mode, 'w')){
		// If file already exists then its contents are going to be erased (deletion) using w, w+.
		if(access(path, F_OK) == 0)
			A_TYPE = DELETION;
		else
		// If file doesn't exist and we use w, w+ the file is going to be created (creation).
			A_TYPE = CREATION;
	}

	// a gives write privilege but a+ gives read/write privilege I log write privilege for both cases.
	if(strchr(mode, 'a')){
		// If file already exists then its contents are going to stay the same using a, a+.
		if(access(path, F_OK) == 0)
			A_TYPE = WRITE;
		else
		// If file doesn't exist and we use a, a+ the file is going to be created (creation).
			A_TYPE = CREATION;
	}

	
	
	/* Setup original fopen() */
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	/* Use original fopen() for the encryption */
	BOOL isPrivateKey = strcmp(path,"private.key") == 0;
	BOOL isPublicKey = strcmp(path,"public.key") == 0;
	BOOL isLogFile = strcmp(path, "file_logging.log")  == 0;
	BOOL isEncryptedLogFile = strcmp(path, "encrypted_logging.log") == 0;

	/* If given file is one of the above then don't continue below */
	if(isPrivateKey || isPublicKey || isLogFile || isEncryptedLogFile){
		return original_fopen_ret;
	}

	/* Get UID and Current Datetime */
	int UID = (int) getuid();
	time_t now;
	char * ctime();
	(void) time(&now);

	/* Check if permission denied */
	BOOL DENIED = FALSE;

	/* If original fopen and the error code matches EACESS that means user got denied access */
	if(!original_fopen_ret && (errno == EACCES)){
		DENIED = TRUE;
	}

	/* Setup length variable and buffer for file read */
	int len = 0;
	char * buffer;
	
	/* 
		If someone without privileges tried to access the file then we can't get the MD5 hash
		I open the file as read in order to get the MD5 hash.
	*/

	BOOL FOPEN_WRITE_FAILED = FALSE;

	if(!original_fopen_ret){
		FOPEN_WRITE_FAILED = TRUE;
		original_fopen_ret = (*original_fopen)(path, "r");
	}

	if(original_fopen_ret){
		/* Get the current SEEK position */
		int SEEK_CURR = ftell (original_fopen_ret);
		/* SEEK to EOF */
		fseek(original_fopen_ret, 0, SEEK_END);
		/* Get the length of file */
		len = ftell(original_fopen_ret);
		/* SEEK to Start */
		fseek(original_fopen_ret, 0, SEEK_SET);
		buffer = malloc(len * sizeof(char));
		/* Read contents of file and write in the buffer */
		fread(buffer, 1, len, original_fopen_ret);
		/* Reset SEEK position */
		fseek(original_fopen_ret, 0, SEEK_CURR);
	}

	/* If fopen() failed then I still set the return value to null even though I read from file */
	if(FOPEN_WRITE_FAILED){
		fclose(original_fopen_ret);
		original_fopen_ret = NULL;
	}

	/* Generate the file fingerprint using MD5 Hash */
	unsigned char FILE_HASH[MD5_DIGEST_LENGTH];
	MD5_CTX context;
	MD5_Init(&context);
	/* Hash file content from buffer */
	MD5_Update(&context, buffer, len);
	/* Put computed hash in FILE_HASH */
	MD5_Final(FILE_HASH, &context);
	/* Export hash as string */
	char HASH_STRING[33];
	for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
		sprintf(&HASH_STRING[i*2], "%02x", (unsigned int) FILE_HASH[i]);
	}


	FILE * LOG_FILE = (*original_fopen)("file_logging.log","a");
	/* Give full permissions to all users for file_logging.log so the encryption tool can work on their side */
	chmod("file_logging.log", 0777);

	/* Log the event */

	fprintf(LOG_FILE, "%d\t%d\t%d\t%s\t%s\t%s", UID, A_TYPE, DENIED, path, HASH_STRING, ctime(&now));

	fclose(LOG_FILE);

	/* Call encryption tool after file is closed and generate the encrypted_logging.log */
	char command[100];
	strcpy(command,"./rsa -i file_logging.log -o encrypted_logging.log -k private.key -e");
	system(command);

	/* Give full permissions to all users for encrypted_logging.log so the encryption tool can work on their side */
	chmod("encrypted_logging.log", 0777);

	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	/* Setup orignal fwrite() */

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */

	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	
	/* Get base filename from file descriptor*/
	
	int fd;
	char fd_path[255];
	char * filename = malloc(255);
	ssize_t n;
	fd = fileno(stream);
	sprintf(fd_path, "/proc/self/fd/%d", fd);
	n = readlink(fd_path, filename, 255);
	filename[n] = '\0';
	char * filebname = basename(filename);
	
	/* Use original fwrite() for encryption */
	
	BOOL isPrivateKey = strcmp(filebname,"private.key") == 0;
	BOOL isPublicKey = strcmp(filebname,"public.key") == 0;
	BOOL isEncryptedLogFile = strcmp(filebname, "encrypted_logging.log") == 0;

	if(isPrivateKey || isPublicKey || isEncryptedLogFile){
		return original_fwrite_ret;
	}

	/* Get UID and Current Datetime */

	int UID = (int) getuid();

	time_t now;
	char * ctime();
	(void) time(&now);

	/* Check if permission denied */

	BOOL DENIED = FALSE;
	if(!original_fwrite_ret && (errno == EACCES)){
		DENIED = TRUE;
	}

	/* Get the current SEEK position */
	int SEEK_CURR = ftell(stream);
	/* SEEK to EOF */
	fseek(stream, 0, SEEK_END);
	/* Get the length of file */
	int len = ftell(stream);
	/* SEEK to Start */
	fseek(stream, 0, SEEK_SET);
	/* Create file content buffer based on length */
	char buffer[len];
	/* Read contents of file and write in the buffer */
	fread(buffer, 1, len, stream);
	/* Reset SEEK position */
	fseek(stream, 0, SEEK_CURR);


	unsigned char FILE_HASH[MD5_DIGEST_LENGTH];
	MD5_CTX context;
	MD5_Init(&context);
	MD5_Update(&context, buffer, len);
	MD5_Final(FILE_HASH, &context);
	char HASH_STRING[33];
	for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
		sprintf(&HASH_STRING[i*2], "%02x", (unsigned int) FILE_HASH[i]);
	}

	/* Call original fopen() to open the logging file with append mode */
	FILE* (*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	FILE* LOG_FILE = (*original_fopen)("file_logging.log", "a");

	chmod("file_logging.log", 0777);

	/* I log write access type whenever fwrite() is used */
	ACCESS A_TYPE = WRITE;

	fprintf(LOG_FILE, "%d\t%d\t%d\t%s\t%s\t%s", UID, A_TYPE, DENIED, filebname, HASH_STRING, ctime(&now));

	fclose(LOG_FILE);

	char command[100];
	strcpy(command,"./rsa -i file_logging.log -o encrypted_logging.log -k private.key -e");
	system(command);

	chmod("encrypted_logging.log", 0777);

	return original_fwrite_ret;
}




