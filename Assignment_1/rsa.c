#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

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

/*
	Create true, false enum
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

/*
	Declare GMP variables
*/
mpz_t Q;
mpz_t P;
mpz_t N;
mpz_t L;
mpz_t E;
mpz_t D;

/*
	Declare GMP temporary variables used for calculations
*/
mpz_t tmpA;
mpz_t tmpB;
mpz_t tmpC;
mpz_t tmpD;

/*----------------------------------------------------------------------- 
						RSA IMPLEMENTATIONS
----------------------------------------------------------------------- */


/* 
	Check if a number is prime,
	using the GMP library function mpz_probap_prime(),
	which returns if 1 or 2 if number is prime or probably prime,
	0 if the number is defenitely not prime
*/
bool IS_PRIME(mpz_t a){
	/* GMP docs recommend 15 to 50 reps */
	int reps = 15;
	if(mpz_probab_prime_p(a, reps) != 0)
		return TRUE;
	else
		return FALSE;
}

void GET_FILE_CONTENT(char ** content, size_t* len){
	FILE *file = fopen(INPUT_FILE, "r");
	if(!file){
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Fopen Error : Input file doesn't exist\n"   ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		exit(-1);
	}
	/*Get file size*/
	fseek(file, 0, SEEK_END);
	*len = ftell(file);

	/*Seek back to the start*/
	rewind(file);
	*content = malloc( *len);
	fread(*content, 1, *len, file);
	
	fclose(file);
}

void SAVE_FILE_CONTENT(char* data, long length){
	FILE *file = fopen(OUTPUT_FILE, "w");
	if(!file){
		exit(-1);
	}
	fseek(file, 0, SEEK_SET);
	for(int i = 0; i < length; i++){
		fputc(data[i], file);
	}
	fclose(file);
}

/*	Save produced keys in the appropriate files
	Public Key 	-> public.key  (Format is N,D)
	Private Key	-> private.key (Format is N,E) */
void SAVE_KEYS(){
	
	char * public_key_fname = "public.key";
	char * private_key_fname = "private.key";

	FILE* fpub = fopen(public_key_fname, "w");
	FILE* fpriv = fopen(private_key_fname, "w");

	if(!(fpub && fpriv)){
		printf("Key Files Error !");
		exit(-1);
	}

	fseek(fpub, 0, SEEK_SET);
	fseek(fpriv, 0, SEEK_SET);

	/* 	
	Cast the keys to size_t before saving
	The keys are supposed to be saved in size_t format based on the assignment_1 document
	The gmp library uses unsigned long.
	(size_t) to (unsigned long int) conversion, may cause loss of data,
	but in my case this is safe
	*/

	size_t n = (size_t) mpz_get_ui(N), d = (size_t) mpz_get_si(D), e = (size_t) mpz_get_ui(E);

	/* Write Public Key */
	fwrite(&n, sizeof(size_t), 1, fpub);
	fwrite(&d, sizeof(size_t), 1, fpub);

	/* Write Private Key */
	fwrite(&n, sizeof(size_t), 1, fpriv);
	fwrite(&e, sizeof(size_t), 1, fpriv);

	fclose(fpub);
	fclose(fpriv);
}

void READ_KEYS(size_t* a, size_t* b){
	FILE* file = fopen(KEY_FILE, "r");
	
	if(!(file)){
		
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Fopen Error : Key file doesn't exist\n"   ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		exit(-1);
	}

	fseek(file, 0, SEEK_SET);
	fread(a, sizeof(size_t), 1, file);
	fread(b, sizeof(size_t), 1, file);

	fclose(file);
}

size_t FIND_E(){
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"Calculating e...\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	size_t cnt = 2;
	size_t lambda = mpz_get_ui(L);
	size_t mod,gcd;
	while(cnt < lambda){
		mpz_set_ui(tmpA, cnt);
		if(IS_PRIME(tmpA)){
			mpz_mod(tmpB, tmpA, L);
			mpz_gcd(tmpC, tmpA, L);
			mod = mpz_get_ui(tmpB);
			gcd = mpz_get_ui(tmpC);
			printf("e = %zu, lambda = %zu, mod = %zu, gcd = %zu\n",cnt,lambda,mod,gcd);
			if(mod != 0 && gcd == 1){
				mpz_set(E, tmpA);
				break;
			}
		}
		cnt++;
	}
}

/*	This function makes all the needed calculations
	in order to produce the private and public key
	using the gmp library	
*/
void PRODUCE_KEYS(){
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"Generate Keys\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);

	/*get Q and P then set the GMP variables*/
	size_t input_Q, input_P;
	
	printf("Enter the prime number Q : ");
	scanf("%zu", &input_Q);
	mpz_set_ui(Q, input_Q);

	while(!IS_PRIME(Q)){
		printf("Given Q is not a prime number, please type a prime : ");
		scanf("%zu", &input_Q);
		mpz_set_ui(Q, input_Q);
	}

	printf("Enter the prime number P : ");
	scanf("%zu", &input_P);
	mpz_set_ui(P, input_P);

	while(!IS_PRIME(P)){
		printf("Given P is not a prime number, please type a prime : ");
		scanf("%zu", &input_P);
		mpz_set_ui(P, input_P);
	}
	/*also set the gmp variables for Q-1 and P-1*/
	mpz_set_ui(tmpA, input_Q-1);
	mpz_set_ui(tmpB, input_P-1);
	/*calculate  (P * Q)*/
	mpz_mul(N, P, Q);
	/*calculate lamda */
	mpz_mul(L, tmpA, tmpB);
	FIND_E(L);
	/* E mod Lambda */
	mpz_mod(tmpA, E, L);
	/* GCD( E, Lambda ) */
	mpz_gcd(tmpB, E, L);
	/* Get the results of modulation and gcd to check*/
	size_t mod, gcd;
	mod = mpz_get_ui(tmpA);
	gcd = mpz_get_ui(tmpB);
	/* calculate modular inverse of E, lambda */
	mpz_invert(D, E, L);
	/* setting information */
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW "Settings\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	gmp_printf("Q =\t\t\t" ANSI_COLOR_GREEN "%Zd\n" ANSI_COLOR_RESET "P =\t\t\t"ANSI_COLOR_GREEN "%Zd\n" ANSI_COLOR_RESET, Q, P);
	gmp_printf("N =\t\t\t"ANSI_COLOR_GREEN"%Zd\n"ANSI_COLOR_RESET, N);
	gmp_printf("lambda(N) =\t\t"ANSI_COLOR_GREEN"%Zd\n"ANSI_COLOR_RESET, L);
	gmp_printf("e =\t\t\t"ANSI_COLOR_GREEN"%Zd\n"ANSI_COLOR_RESET,E);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"e constraints\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf("Mod(e, lambda(N)) =\t"ANSI_COLOR_GREEN"%zu\n"ANSI_COLOR_RESET,mod);
	printf("GCD(e, lambda(N)) =\t"ANSI_COLOR_GREEN"%zu\n"ANSI_COLOR_RESET,gcd);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	gmp_printf("D =\t\t\t"ANSI_COLOR_GREEN"%Zd\n"ANSI_COLOR_RESET, D);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);

	SAVE_KEYS();
}

void RSA_ENCRYPT(){
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"Encryption...\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	
	size_t p1, p2;
	/*Pull keys from file*/
	READ_KEYS(&p1, &p2);

	printf(ANSI_COLOR_YELLOW"Key parts\n(can be (P1,P2)=(n,d) or (P1,P2)=(n,e)\n,depending the key we want to use public/private) \n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf("P1 =\t\t\t"ANSI_COLOR_GREEN"%zu\n"ANSI_COLOR_RESET"P2 =\t\t\t"ANSI_COLOR_GREEN"%zu\n"ANSI_COLOR_RESET,p1,p2);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	
	mpz_set_ui(tmpA, p1);	
	mpz_set_ui(tmpB, p2);	

	char* plain_content;
	size_t plain_content_len;
	GET_FILE_CONTENT(&plain_content, &plain_content_len);

	size_t* cipher = malloc( sizeof(size_t) * plain_content_len);

	for(int i = 0; i < plain_content_len; i++){
		mpz_set_ui(tmpC, (size_t) plain_content[i]); 
		mpz_powm(tmpD, tmpC, tmpB, tmpA);
		cipher[i] = (size_t) mpz_get_ui(tmpD);
	}

	FILE *file = fopen(OUTPUT_FILE, "w");
	if(!file){
		exit(-1);
	}
	fseek(file, 0, SEEK_SET);
	fwrite(cipher, sizeof(size_t), plain_content_len, file);
	fclose(file);

	printf(ANSI_COLOR_YELLOW"Encryption Completed!\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
}

void RSA_DECRYPT(){
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"Decryption...\n"ANSI_COLOR_RESET);
	size_t p1, p2;
	READ_KEYS(&p1, &p2);

	mpz_set_ui(tmpA, p1); 
	mpz_set_ui(tmpB, p2); 

	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf("P1 =\t\t\t"ANSI_COLOR_GREEN"%zu\n"ANSI_COLOR_RESET"P2 =\t\t\t"ANSI_COLOR_GREEN"%zu\n"ANSI_COLOR_RESET,p1,p2);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	
	
	FILE *file = fopen(INPUT_FILE, "r");
	if(!file){
		exit(-1);
	}


	fseek(file, 0, SEEK_END);
	size_t cipher_bytes = ftell(file);
	fseek(file, 0, SEEK_SET);


	size_t plain_content_len = cipher_bytes / sizeof(size_t);
	size_t* ciphertext = malloc( sizeof(size_t) * plain_content_len);
	char* plain_content = malloc( sizeof(char) * plain_content_len);
	fread(ciphertext, sizeof(size_t), plain_content_len, file);

	for(int i = 0; i < plain_content_len; i++){
		mpz_set_ui(tmpC, (size_t) ciphertext[i]); 
		mpz_powm(tmpD, tmpC, tmpB, tmpA);
		plain_content[i] = (char) mpz_get_ui(tmpD);
	}
	SAVE_FILE_CONTENT(plain_content, plain_content_len);
	printf(ANSI_COLOR_YELLOW"Decryption Completed!\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
}

void CHECK_ARGS(){
	if(GENERATE_KEYS && !ENCRYPT && !DECRYPT && INPUT_FILE==NULL && OUTPUT_FILE==NULL && KEY_FILE ==NULL){
		PRODUCE_KEYS();
	}else if(ENCRYPT && !GENERATE_KEYS && !DECRYPT && INPUT_FILE != NULL && OUTPUT_FILE != NULL && KEY_FILE !=NULL){
		RSA_ENCRYPT();
	}else if(DECRYPT && !GENERATE_KEYS && !ENCRYPT && INPUT_FILE != NULL && OUTPUT_FILE != NULL && KEY_FILE !=NULL){
		RSA_DECRYPT();
	}else{
		printf("Wrong command. Please check your command and try again.\n");
	}
}

/*----------------------------------------------------------------------- 
								MAIN
----------------------------------------------------------------------- */
int main(int argc, char *argv[]){
	mpz_inits(Q, P, N, L, E, D, tmpA, tmpB, tmpC, tmpD, NULL);
	int opt;
	while((opt= getopt(argc, argv, "i:o:k:gdehr")) != -1){
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
	CHECK_ARGS();
}



