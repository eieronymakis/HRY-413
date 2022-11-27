#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <pwd.h>

/* 
	Colors for stdout
*/
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

typedef struct entry {
	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */
	char * datetime;
	char * file; /* filename (string) */
	char * fingerprint; /* file fingerprint */
} entry;

typedef enum {FALSE = 0, TRUE = !FALSE} BOOL;


void usage(void){
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

void printEntry(entry e){
	printf("%d\t%d\t%d\t%s\t%s\t%s\n",e.uid,e.access_type,e.action_denied,e.datetime, e.file, e.fingerprint);
}

void importData(FILE * log, entry * data, int count){

	for(int i = 0; i < count; i++){
		char * l;
		size_t l_len = 0;
		getline(&l, &l_len, log);
		data[i].uid = atoi( strtok (l, "\t"));
		data[i].access_type = atoi (strtok (NULL, "\t"));
		data[i].action_denied = atoi(strtok (NULL, "\t"));
		data[i].file = strtok(NULL, "\t");
		data[i].fingerprint = strtok( NULL, "\t");
		data[i].datetime = strtok(NULL, "\t");
	}

	return;
}


void list_unauthorized_accesses(FILE *log){

	int entryCount = 0;
	while(EOF != (fscanf(log, "%*[^\n]"), fscanf(log, "%*c")))
		entryCount++;
	fseek(log, 0, SEEK_SET); 

	entry data[entryCount];
	importData(log, data, entryCount);

	int uniqueUsers = 0;
	int users[entryCount];

	for(int i = 0; i < entryCount; i++){
		BOOL exists = FALSE;
		for(int j = 0; j < uniqueUsers; j++)
			if(data[i].uid == users[j])
				exists = TRUE;
		if(!exists){
			users[uniqueUsers] = data[i].uid;
			uniqueUsers++;
		}
	}

	BOOL unAuthorized[uniqueUsers];
	for(int i = 0; i < uniqueUsers; i++)
		unAuthorized[i] = FALSE;
	printf(ANSI_COLOR_GREEN"--------------------------------------------------------------\n"ANSI_COLOR_RESET);
	printf("Malicious Users : \n");
	printf(ANSI_COLOR_GREEN"--------------------------------------------------------------\n"ANSI_COLOR_RESET);
	printf("UID\t|\tUser Name\n");
	printf(ANSI_COLOR_GREEN"--------------------------------------------------------------\n"ANSI_COLOR_RESET);

	for(int i = 0; i < uniqueUsers; i++){
		char files[8][100] = {'\0','\0','\0','\0','\0','\0','\0'};
		int forbiddenAccesses = 0;
		int entryIndex = 0;
		while(forbiddenAccesses < 8 && entryIndex < entryCount){
			if(data[entryIndex].uid==users[i] && data[entryIndex].action_denied == 1){
				BOOL exists = FALSE;
				for(int j = 0; j < 8; j++)
					if(strcmp(files[j],data[entryIndex].file) == 0)
						exists = TRUE;
				if(!exists){
					strcpy(files[forbiddenAccesses],data[entryIndex].file);
					forbiddenAccesses++;
				}
			}
			entryIndex++;
		}
		if(forbiddenAccesses >= 8){
			unAuthorized[i] = TRUE;
			printf(ANSI_COLOR_RED"%d"ANSI_COLOR_RESET"\t|\t"ANSI_COLOR_RED"%s\n"ANSI_COLOR_RESET, users[i] ,getpwuid( users[i] ) -> pw_name);
		}
	}

	printf(ANSI_COLOR_GREEN"--------------------------------------------------------------\n"ANSI_COLOR_RESET);

	return;
}


void list_file_modifications(FILE *log, char *file_to_scan){

	int entryCount = 0;
	while(EOF != (fscanf(log, "%*[^\n]"), fscanf(log, "%*c")))
		entryCount++;
	fseek(log, 0, SEEK_SET); 

	entry data[entryCount];
	importData(log, data, entryCount);

	int uniqueUsers = 0;
	int users[entryCount];

	for(int i = 0; i < entryCount; i++){
		BOOL exists = FALSE;
		for(int j = 0; j < uniqueUsers; j++)
			if(data[i].uid == users[j])
				exists = TRUE;
		if(!exists){
			users[uniqueUsers] = data[i].uid;
			uniqueUsers++;
		}
	}

	int accessedBy[uniqueUsers];
	for(int i = 0; i < uniqueUsers; i++)
		accessedBy[i] = 0;

	for(int i = 0; i < uniqueUsers; i++)
		for(int j = 0; j < entryCount; j++)
			if(strcmp(data[j].file,file_to_scan) == 0 && data[j].uid == users[i])
				accessedBy[i]++;

	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	printf("File "ANSI_COLOR_BLUE"%s"ANSI_COLOR_RESET" Accessed By :\n", file_to_scan);
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	printf("UID"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"%-20s"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"Times\n","User Name");
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	for(int i = 0; i < uniqueUsers; i++)
		if(accessedBy[i] > 0)
			printf("%d"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"%-20s"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"%d\n",users[i],getpwuid( users[i] ) -> pw_name,accessedBy[i]);
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);


	char originalMD5Hash[50];
	int initIndex = 0;

	for(int i = 0; i < entryCount; i++){
		if(strcmp(data[i].file, file_to_scan) == 0){
			strcpy(originalMD5Hash, data[i].fingerprint);
			initIndex = i;
			break;
		}
	}

	printf("Original file MD5 Hash (fingerprint) :\t"ANSI_COLOR_BLUE"%s\n"ANSI_COLOR_RESET, originalMD5Hash);
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);

	int timesModified[uniqueUsers];
	for(int i = 0; i < uniqueUsers; i++){
		timesModified[i] = 0;
	}

	for(int i = 0; i < uniqueUsers; i++){
		for(int j = initIndex; j < entryCount; j++){
			if(data[j].uid == users[i] && strcmp(data[j].file,file_to_scan) == 0 && j!=initIndex){
				char previousHash[50];
				for(int z = j-1; z >= initIndex; z--){
					if(strcmp(file_to_scan, data[z].file) == 0){
						strcpy(previousHash, data[z].fingerprint);
						break;
					}
				}
				if(strcmp(previousHash, data[j].fingerprint) != 0){
					timesModified[i]++;
				}
			}
		}
	}

	
	printf("Mofications done by users :\n");
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	printf("UID"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"%-20s"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"Times\n","User Name");
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	
	for(int i = 0; i < uniqueUsers; i++)
		if(timesModified[i] >= 0)
			printf("%d"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"%-20s"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"%d\n",users[i],getpwuid( users[i] ) -> pw_name,timesModified[i]);
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	return;
}



int main(int argc, char *argv[]){

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}

	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
