#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <pwd.h>

typedef struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char * date_time;

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */
} entry;

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


// void printEntry(entry e){
// 	printf("%d %d %d %s %s%s\n",e.uid,e.access_type,e.action_denied,e.date_time,e.file,e.fingerprint);
// }

void importEntries(FILE * log, entry * data, int count){

	for(int i = 0; i < count; i++){
		char * l;
		size_t l_len = 0;
		getline(&l, &l_len, log);
		data[i].uid = atoi( strtok (l, "\t"));
		data[i].access_type = atoi (strtok (NULL, "\t"));
		data[i].action_denied = atoi (strtok (NULL, "\t"));
		data[i].file = strtok( NULL, "\t");
		data[i].fingerprint = strtok( NULL, "\t");
		data[i].date_time = strtok(NULL, "\t");
	}

	return;
}


void list_unauthorized_accesses(FILE *log){

	int count = 0;
	while(EOF != (fscanf(log, "%*[^\n]"), fscanf(log, "%*c")))
		count++;
	fseek(log, 0, SEEK_SET); 

	entry data[count];
	importEntries(log, data, count);

	int num_users = 0;
	int users[count];

	for(int i = 0; i < count; i++){
		int dup = 0;

		for(int k = 0; k < num_users; k++){
			if(data[i].uid == users[k])
				dup = 1;
		}

		if(dup == 0){
			users[num_users] = data[i].uid;
			num_users++;
		}
	}

	int unauth[num_users];
	for(int i = 0; i < num_users; i++){
		unauth[i] = 0;
	}

	for(int i = 0; i < count; i++){
		if(data[i].action_denied == 1){
			for(int k = 0; k < num_users; k++){
				if(data[i].uid == users[k]){
					unauth[k]++;
				}
			}
		}
	}

	for(int i = 0; i < num_users; i++){
		if(unauth[i] > 7)
			printf("%s\n", getpwuid( users[i] ) -> pw_name);
	}

	return;

}


void list_file_modifications(FILE *log, char *file_to_scan){

	
	int count = 0;
	while(EOF != (fscanf(log, "%*[^\n]"), fscanf(log, "%*c")))
		count++;
	fseek(log, 0, SEEK_SET); 

	entry data[count];
	importEntries(log, data, count);

	int num_users = 0;
	int users[count];

	for(int i = 0; i < count; i++){
		int dup = 0;
		for(int k = 0; k <  num_users; k++){
			if(data[i].uid == users[k])
				dup = 1;
		}

		if(dup == 1){
			users[num_users] = data[i].uid;
			num_users++;
		}
	}

	int chan[num_users];
	for(int i = 0; i < num_users; i++){
		chan[i] = 0;
	}

	char actual_path;



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
