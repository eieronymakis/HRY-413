#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>

/*
	Create true, false enumeration
*/
typedef enum { FALSE = 0, TRUE = !FALSE} bool;

/*
	Globals
*/
bool GENERATE_KEYS = FALSE;
bool ENCRYPT = FALSE;
bool DECRYPT = FALSE;
char *INPUT_FILE = NULL;
char *OUTPUT_FILE = NULL;
char *KEY_FILE = NULL;

// Declare numbers as size_t to prevent size limitations
size_t Q;
size_t P;

/*
	Returns the greatest common denominator
*/
int gcd(int a, int b){
	if(b!=0)
	return gcd(b,a%b);
	else
	return a;
}

void process_args(){
	if(GENERATE_KEYS && !ENCRYPT && !DECRYPT && INPUT_FILE==NULL && OUTPUT_FILE==NULL && KEY_FILE ==NULL){
		printf("Generate Keys\n");
		printf("Enter the number Q : ");
		scanf("%zu", &Q);
		printf("Enter the number P : ");
		scanf("%zu", &P);
		printf("Q = %zu, P = %zu\n", Q, P);
	}else if(ENCRYPT && !GENERATE_KEYS && !DECRYPT && INPUT_FILE != NULL && OUTPUT_FILE != NULL && KEY_FILE !=NULL){
		printf("Encrypt\n");
	}else if(DECRYPT && !GENERATE_KEYS && !ENCRYPT && INPUT_FILE != NULL && OUTPUT_FILE != NULL && KEY_FILE !=NULL){
		printf("Decrypt\n");
	}else{
		printf("Wrong command. Please check your command and try again.\n");
	}
}

int main(int argc, char *argv[]){
	int opt;
	while((opt= getopt(argc, argv, "i:o:k:gdeh")) != -1){
		switch(opt){
			case 'i':
				INPUT_FILE = strdup(optarg);
				break;
			case 'o':
				OUTPUT_FILE = strdup(optarg);
				break;
			case 'k':
				KEY_FILE = strdup(optarg);
				break;
			case 'g':
				GENERATE_KEYS = TRUE;
				break;
			case 'd':
				DECRYPT = TRUE;
				break;
			case 'e':
				ENCRYPT = TRUE;
				break;
			case 'h':
				break;
			default:
				return 0;
		}
	}

	process_args(INPUT_FILE, OUTPUT_FILE, KEY_FILE, GENERATE_KEYS, DECRYPT, ENCRYPT);
}



