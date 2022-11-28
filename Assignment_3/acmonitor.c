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


/* Fill entry array data from file */
void importData(FILE * log, entry * data, int count){

	for(int i = 0; i < count; i++){
		char * line;
		size_t line_length = 0;
		/* Read one line */
		getline(&line, &line_length, log);
		/* Fill structure i with data from file line i*/
		data[i].uid = atoi(strtok (line, "\t"));
		data[i].access_type = atoi(strtok (NULL, "\t"));
		data[i].action_denied = atoi(strtok (NULL, "\t"));
		data[i].file = strtok(NULL, "\t");
		data[i].fingerprint = strtok( NULL, "\t");
		data[i].datetime = strtok(NULL, "\t");
	}

	return;
}


void list_unauthorized_accesses(FILE *log){
	/* Get line (entry) count */
	int entryCount = 0;
	while(EOF != (fscanf(log, "%*[^\n]"), fscanf(log, "%*c")))
		entryCount++;
	fseek(log, 0, SEEK_SET); 
	/* Create entry struct array */
	entry data[entryCount];
	/* Fill struct array */
	importData(log, data, entryCount);

	/* Get unique user uid's and save them into uniqueUsers array */
	int uniqueCount = 0;
	int uniqueUsers[entryCount];

	for(int i = 0; i < entryCount; i++){
		BOOL exists = FALSE;
		for(int j = 0; j < uniqueCount; j++)
			if(data[i].uid == uniqueUsers[j])
				exists = TRUE;
		if(!exists){
			uniqueUsers[uniqueCount] = data[i].uid;
			uniqueCount++;
		}
	}

	/* Set up unauthorized accesses array for each unique user */
	BOOL unAuthorized[uniqueCount];
	for(int i = 0; i < uniqueCount; i++)
		unAuthorized[i] = FALSE;
	/* Output ... */
	printf(ANSI_COLOR_GREEN"--------------------------------------------------------------\n"ANSI_COLOR_RESET);
	printf("Malicious Users : \n");
	printf(ANSI_COLOR_GREEN"--------------------------------------------------------------\n"ANSI_COLOR_RESET);
	printf("UID\t|\tUser Name\t|\tFiles\n");
	printf(ANSI_COLOR_GREEN"--------------------------------------------------------------\n"ANSI_COLOR_RESET);

	/* For each unique user */
	for(int i = 0; i < uniqueCount; i++){
		/* Create an array of 8 filenames to save the different filenames where he got denied access (we need > 7 so 8 filenames is enough )*/
		char files[8][100] = {'\0','\0','\0','\0','\0','\0','\0'};
		/* Setup forbidden accesses counter */
		int forbiddenAccesses = 0;
		/* Index counter for file lines (entries) */
		int entryIndex = 0;
		/* We will stop when denied accesses > 7 or when there are no more file lines */
		while(forbiddenAccesses < 8 && entryIndex < entryCount){
			/* Compare unique user uid with entry uid, if they match and action was denied*/
			if(data[entryIndex].uid==uniqueUsers[i] && data[entryIndex].action_denied == 1){
				/* Check if he got denied in a file he already was denied another time */
				BOOL exists = FALSE;
				for(int j = 0; j < 8; j++)
					if(strcmp(files[j],data[entryIndex].file) == 0)
						exists = TRUE;
				/* If this file is different from the other files he got denied earlier then increase the forbidden accesses counter and save file name*/
				if(!exists){
					strcpy(files[forbiddenAccesses],data[entryIndex].file);
					forbiddenAccesses++;
				}
			}
			entryIndex++;
		}
		/* If he got denied on MORE than 7 !DIFFERENT! files then print the uid and username of that user and the first 8 files he got denied in */
		if(forbiddenAccesses >= 8){
			unAuthorized[i] = TRUE;
			printf(ANSI_COLOR_RED"%d"ANSI_COLOR_RESET"\t|\t"ANSI_COLOR_RED"%s"ANSI_COLOR_RESET"\t|\t", uniqueUsers[i] ,getpwuid( uniqueUsers[i] ) -> pw_name);
			for(int z = 0; z < 8; z++)
				printf(ANSI_COLOR_RED"%s\t"ANSI_COLOR_RESET, files[z]);
			printf("\n");
		}
	}

	printf(ANSI_COLOR_GREEN"--------------------------------------------------------------\n"ANSI_COLOR_RESET);

	return;
}


void list_file_modifications(FILE *log, char *file_to_scan){
	/* Same as list_unauthorized_accesses() */
	int entryCount = 0;
	while(EOF != (fscanf(log, "%*[^\n]"), fscanf(log, "%*c")))
		entryCount++;
	fseek(log, 0, SEEK_SET); 

	entry data[entryCount];
	importData(log, data, entryCount);

	int uniqueCount = 0;
	int uniqueUsers[entryCount];

	for(int i = 0; i < entryCount; i++){
		BOOL exists = FALSE;
		for(int j = 0; j < uniqueCount; j++)
			if(data[i].uid == uniqueUsers[j])
				exists = TRUE;
		if(!exists){
			uniqueUsers[uniqueCount] = data[i].uid;
			uniqueCount++;
		}
	}


	/* Array to save how many times uniqueUser x accessed file_to_scan */
	int accessedBy[uniqueCount];
	for(int i = 0; i < uniqueCount; i++)
		accessedBy[i] = 0;
	/* For each user get accesses count on file_to_scan */
	for(int i = 0; i < uniqueCount; i++)
		for(int j = 0; j < entryCount; j++)
			if(strcmp(data[j].file,file_to_scan) == 0 && data[j].uid == uniqueUsers[i])
				accessedBy[i]++;

	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	printf("File "ANSI_COLOR_BLUE"%s"ANSI_COLOR_RESET" Accessed By :\n", file_to_scan);
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	printf("UID"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"%-20s"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"Times\n","User Name");
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	for(int i = 0; i < uniqueCount; i++)
		if(accessedBy[i] > 0)
			printf(ANSI_COLOR_YELLOW"%d"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_YELLOW"%-20s"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_YELLOW"%d\n"ANSI_COLOR_RESET,uniqueUsers[i],getpwuid( uniqueUsers[i] ) -> pw_name,accessedBy[i]);
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);

	/* Initial file hash of file_to_scan */
	char originalMD5Hash[50];
	int initIndex = 0;
	/* Save the initial file hash of file_to_scan */
	for(int i = 0; i < entryCount; i++){
		if(strcmp(data[i].file, file_to_scan) == 0){
			strcpy(originalMD5Hash, data[i].fingerprint);
			initIndex = i;
			break;
		}
	}

	printf("Original file MD5 Hash (fingerprint) :\t"ANSI_COLOR_BLUE"%s\n"ANSI_COLOR_RESET, originalMD5Hash);
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);

	/* Array to save how many times user x modified file (modified hash) */
	int timesModified[uniqueCount];
	for(int i = 0; i < uniqueCount; i++){
		timesModified[i] = 0;
	}

	/* For each unique user */
	for(int i = 0; i < uniqueCount; i++){
		/* Start from the line where file_to_scan (original hash) was created */
		for(int j = initIndex; j < entryCount; j++){
			/*If current line uid matches the current unique user uid and file name is the one we want and current line is not the file creation line */
			if(data[j].uid == uniqueUsers[i] && strcmp(data[j].file,file_to_scan) == 0 && j!=initIndex){
				/* Initialize previous hash */
				char previousHash[50];
				/* Traverse from current entry till the initial file_to_scan hash index */
				for(int z = j-1; z >= initIndex; z--){
					/* Get the first previous file_to_scan entry and save its MD5 hash*/
					if(strcmp(file_to_scan, data[z].file) == 0){
						strcpy(previousHash, data[z].fingerprint);
						break;
					}
				}
				/* If the first previous file_to_scan entry has different finger print then user modified it*/
				if(strcmp(previousHash, data[j].fingerprint) != 0){
					timesModified[i]++;
				}
			}
		}
	}

	/* Output ... */
	printf("Mofications done by users :\n");
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	printf("UID"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"%-20s"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_RESET"Times\n","User Name");
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	
	for(int i = 0; i < uniqueCount; i++)
		if(timesModified[i] >= 0)
			printf(ANSI_COLOR_YELLOW"%d"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_YELLOW"%-20s"ANSI_COLOR_GREEN"\t|\t"ANSI_COLOR_YELLOW"%d\n"ANSI_COLOR_RESET,uniqueUsers[i],getpwuid( uniqueUsers[i] ) -> pw_name,timesModified[i]);
	printf(ANSI_COLOR_GREEN"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
	return;
}



int main(int argc, char *argv[]){

	int ch;
	FILE *log;

	if (argc < 2)
		usage();


	/* Check if Encrypted logging file exists */

	FILE * encrypted_log;
	encrypted_log = fopen("encrypted_logging.log","r");

	if(encrypted_log == NULL){
		printf(ANSI_COLOR_RED"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Encrypted logging file doesn't exist!\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
		exit(-1);
	}else{
		fclose(encrypted_log);
	}

	/* Decrypt the Encrypted logging file */
	
	char command[50];
	strcpy(command, "make decrypt");
	system(command);

	/* Check if Decrypted logging file exists */

	FILE * decrypted_log;
	decrypted_log = fopen("decrypted_logging.log","r");

	if(decrypted_log == NULL){
		printf(ANSI_COLOR_RED"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Decrypted logging file doesn't exist!\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"-----------------------------------------------------------------------------\n"ANSI_COLOR_RESET);
		exit(-1);
	}else{
		fclose(decrypted_log);
	}
	
	/* Pass the Decrypted logging file for proccessing */

	log = fopen("decrypted_logging.log", "r");
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
