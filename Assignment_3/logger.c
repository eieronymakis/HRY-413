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
*/

typedef enum {READ = 0, WRITE = 1} ACCESS;
typedef enum {FALSE = 0, TRUE = !FALSE} BOOL;
int ERROR = -1;


FILE * fopen(const char *path, const char *mode){
	//-----------------------------------------------------------------------------------------
	/* Setup original fopen() */
	//-----------------------------------------------------------------------------------------
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	//-----------------------------------------------------------------------------------------
	/* Use original fopen() for the encryption */
	//-----------------------------------------------------------------------------------------
	BOOL isPrivateKey = strcmp(path,"private.key") == 0;
	BOOL isPublicKey = strcmp(path,"public.key") == 0;
	BOOL isLogFile = strcmp(path, "file_logging.log")  == 0;
	BOOL isEncryptedLogFile = strcmp(path, "encrypted_logging.log") == 0;

	if(isPrivateKey != isPublicKey){
		return original_fopen_ret;
	}
	if(isLogFile != isEncryptedLogFile){
		return original_fopen_ret;
	}
	//-----------------------------------------------------------------------------------------

	int UID = (int) getuid();
	time_t now;
	char * ctime();
	(void) time(&now);

	ACCESS A_TYPE;

	if( access(path, F_OK) != ERROR || *mode == 'r'){
		A_TYPE = READ;
	}
	if(*mode == 'w'){
		A_TYPE = WRITE;
	}

	/* Check if permission denied */
	BOOL DENIED = FALSE;
	if(!original_fopen_ret && (errno == EACCES)){
		DENIED = TRUE;
	}

	char ABSOLUTE_PATH[PATH_MAX+1];
	realpath(path, ABSOLUTE_PATH);

	int len = 0;
	char * buffer;

	int open_flag = 0;

	if(!original_fopen_ret){
		open_flag = 1;
		original_fopen_ret = (*original_fopen)(path, "r");
	}

	if(original_fopen_ret){
		/* Get the current seek position */
		int SEEK_CURR = ftell (original_fopen_ret);

		/* Get the file size by seeking to the end of the file */
		fseek(original_fopen_ret, 0, SEEK_END);
		len = ftell(original_fopen_ret);
		
		/* Put file content into buffer */
		fseek(original_fopen_ret, 0, SEEK_SET);
		buffer = malloc(len);
		fread(buffer, 1, len, original_fopen_ret);

		/* Reset seek position */
		fseek(original_fopen_ret, 0, SEEK_CURR);
	}

	if(open_flag == 1){
		
		fclose(original_fopen_ret);
		original_fopen_ret = NULL;
	}

	/* File hash string */
	unsigned char FILE_HASH[MD5_DIGEST_LENGTH];
	
	MD5_CTX context;
	MD5_Init(&context);

	/* Hash file content from buffer */
	MD5_Update(&context, buffer, len);

	/* Put computed hash in FILE_HASH */
	MD5_Final(FILE_HASH, &context);

	FILE * LOG_FILE = (*original_fopen)("file_logging.log","a");

	/* Give full permissions to everyone */
	chmod("file_logging.log", 0777);

	char HASH_STRING[33];
	for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
		sprintf(&HASH_STRING[i*2], "%02x", (unsigned int) FILE_HASH[i]);
	}

	fprintf(LOG_FILE, "%d\t%d\t%d\t%s\t%s\t%s", UID, A_TYPE, DENIED, ABSOLUTE_PATH, HASH_STRING, ctime(&now));

	fclose(LOG_FILE);

	char command[100];
	strcpy(command,"./rsa -i file_logging.log -o encrypted_logging.log -k private.key -e");
	system(command);

	chmod("encrypted_logging.log", 0777);

	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	//-----------------------------------------------------------------------------------------
	/* Setup orignal fwrite() */
	//-----------------------------------------------------------------------------------------
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	//-----------------------------------------------------------------------------------------
	/* Get base filename from file descriptor*/
	//-----------------------------------------------------------------------------------------
	int fd;
	char fd_path[255];
	char * filename = malloc(255);
	ssize_t n;
	fd = fileno(stream);
	sprintf(fd_path, "/proc/self/fd/%d", fd);
	n = readlink(fd_path, filename, 255);
	filename[n] = '\0';
	char * filebname = basename(filename);
	//-----------------------------------------------------------------------------------------
	/* Use original fwrite() for encryption */
	//-----------------------------------------------------------------------------------------
	BOOL isPrivateKey = strcmp(filebname,"private.key") == 0;
	BOOL isPublicKey = strcmp(filebname,"public.key") == 0;
	BOOL isLogFile = strcmp(filebname, "file_logging.log");
	BOOL isEncryptedLogFile = strcmp(filebname, "encrypted_logging.log") == 0;

	if(isPrivateKey != isPublicKey){
		return original_fwrite_ret;
	}
	if(isLogFile != isEncryptedLogFile){
		return original_fwrite_ret;
	}
	//-----------------------------------------------------------------------------------------

	int UID = (int) getuid();

	time_t now;
	char * ctime();
	(void) time(&now);


	BOOL DENIED = FALSE;
	if(!original_fwrite_ret && (errno == EACCES)){
		DENIED = TRUE;
	}

	char ABSOLUTE_PATH[PATH_MAX+1];
	char proclnk[PATH_MAX+1];

	int FILE_DESC = fileno(stream);

	sprintf(proclnk, "/proc/self/fd/%d", FILE_DESC);
	ssize_t bytes = readlink(proclnk, ABSOLUTE_PATH, PATH_MAX);
	ABSOLUTE_PATH[bytes] = '\0';

	int SEEK_CURR = ftell(stream);

	fseek(stream, 0, SEEK_END);
	int len = ftell(stream);

	fseek(stream, 0, SEEK_SET);
	char buffer[len];
	fread(buffer, 1, len, stream);

	fseek(stream, 0, SEEK_CURR);


	unsigned char FILE_HASH[MD5_DIGEST_LENGTH];

	MD5_CTX context;
	MD5_Init(&context);
	MD5_Update(&context, buffer, len);
	MD5_Final(FILE_HASH, &context);

	FILE* (*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	FILE* LOG_FILE = (*original_fopen)("file_logging.log", "a");

	chmod("file_logging.log", 0777);

	char HASH_STRING[33];
	for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
		sprintf(&HASH_STRING[i*2], "%02x", (unsigned int) FILE_HASH[i]);
	}

	fprintf(LOG_FILE, "%d\t%d\t%d\t%s\t%s\t%s", UID, 2, DENIED, ABSOLUTE_PATH, HASH_STRING, ctime(&now));
	
	fclose(LOG_FILE);

	char command[100];
	strcpy(command,"./rsa -i file_logging.log -o encrypted_logging.log -k private.key -e");
	system(command);

	chmod("encrypted_logging.log", 0777);
	
	return original_fwrite_ret;
}




