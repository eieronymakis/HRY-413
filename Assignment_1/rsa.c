#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

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
mpz_t Q;
mpz_t P;
mpz_t N;
mpz_t L;
mpz_t E;
mpz_t D;

// Temp variables used for calculations
mpz_t tmpA;
mpz_t tmpB;

/*----------------------------------------------------------------------- 
						RSA IMPLEMENTATIONS
----------------------------------------------------------------------- */


/*	CHECK IF A NUMBER IS PRIME USING GMP LIBRARY*/
bool IS_PRIME(mpz_t a){
	/* GMP DOCS RECOMMEND 15 TO 50 REPS */
	int reps = 15;
	if(mpz_probab_prime_p(a, reps) != 0)
		return TRUE;
	else
		return FALSE;
}

/*	SAVES KEYS PRODUCED EARLIER TO THE APPROPRIATE FILES
	PUBLIC KEY 	-> PUBLIC.KEY FILE (FORMAT IS N,D)
	PRIVATE KEY	-> PRIVATE.KEY FILE (FORMAT IS N,E) */
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

	unsigned long int n = mpz_get_ui(N), d = mpz_get_si(D), e = mpz_get_ui(E);

	/* Write Public Key */
	fwrite(&n, sizeof(unsigned long int), 1, fpub);
	fwrite(&d, sizeof(unsigned long int), 1, fpub);

	/* Write Private Key */
	fwrite(&n, sizeof(unsigned long int), 1, fpriv);
	fwrite(&e, sizeof(unsigned long int), 1, fpriv);

	fclose(fpub);
	fclose(fpriv);
}

void READ_KEYS(char* fname, unsigned long int* a, unsigned long int* b){
	FILE* file = fopen(fname, "r");
	
	if(!(file)){
		printf("_______________________________________\n");
		printf("Fopen Error : key file doesn't exist\n");
		printf("_______________________________________\n");
		exit(-1);
	}

	fseek(file, 0, SEEK_SET);
	fread(a, sizeof(unsigned long int), 1, file);
	fread(b, sizeof(unsigned long int), 1, file);

	fclose(file);
}

/*	THIS METHOD MAKES ALL THE NEEDED CALCULATIONS
	IN ORDER TO PRODUCE KEYS USING THE GMP LIBRARY */
void PRODUCE_KEYS(){
	printf("_______________________________________\n");
	printf("Generate Keys\n");
	printf("_______________________________________\n");
	/* GET Q & P*/
	/* MAKE SURE THEY ARE PRIMES AND SET GMP VARIABLES */
	unsigned long int input_Q, input_P;	
	printf("Enter the prime number Q : ");
	scanf("%lu", &input_Q);
	mpz_set_ui(Q, input_Q);
	while(!IS_PRIME(Q)){
		printf("Given Q is not a prime number, please type a prime : ");
		scanf("%lu", &input_Q);
		mpz_set_ui(Q, input_Q);
	}
	printf("Enter the prime number P : ");
	scanf("%lu", &input_P);
	mpz_set_ui(P, input_P);
	while(!IS_PRIME(P)){
		printf("Given P is not a prime number, please type a prime : ");
		scanf("%lu", &input_P);
		mpz_set_ui(P, input_P);
	}
	/* SET GMP VARIABLES FOR Q-1 & P-1 */
	mpz_set_ui(tmpA, input_Q-1);
	mpz_set_ui(tmpB, input_P-1);
	/* CALCULATE ( P * Q ) */
	mpz_mul(N, P, Q);
	/* CALCULATE LAMDA(N) */
	mpz_mul(L, tmpA, tmpB);
	/* I CHOSE E = 65537 (MOST COMMON VALUE FOR E) BECAUSE IT HAS 2 BITS SET AND IS IS EFFICIENT FOR MODULAR EXPONENTATION*/ 
	/* I COULD HAVE CHOSE E = 3 BUT IT IS SHOWN TO BE LESS SECURE IN SOME SETTINGS*/
	mpz_set_ui(E, 65537);
	/* E MOD LAMDA(N) */
	mpz_mod(tmpA, E, L);
	/* GCD( E, LAMDA(N) ) */
	mpz_gcd(tmpB, E, L);
	/* GET RESULTS OF MOD, GCD TO TEST */
	unsigned long int mod, gcd;
	mod = mpz_get_ui(tmpA);
	gcd = mpz_get_ui(tmpB);
	/* CALCULATE MODULAR INVERSE OF E,L */
	mpz_invert(D, E, L);
	/* SETTING INFORMATION */
	printf("_______________________________________\n");
	printf("Settings\n");
	printf("_______________________________________\n");
	gmp_printf("Q =\t\t\t%Zd\nP =\t\t\t%Zd\n", Q, P);
	gmp_printf("N =\t\t\t%Zd\n", N);
	gmp_printf("lambda(N) =\t\t%Zd\n", L);
	gmp_printf("e =\t\t\t%Zd\n",E);
	printf("_______________________________________\n");
	printf("E constaints\n");
	printf("_______________________________________\n");
	printf("Mod(e, lambda(N)) =\t%lu\n",mod);
	printf("GCD(e, lambda(N)) =\t%lu\n",gcd);
	printf("_______________________________________\n");
	gmp_printf("D =\t\t\t%Zd\n", D);
	printf("_______________________________________\n");

	SAVE_KEYS();
}


void RSA_ENCRYPT(){
	printf("_______________________________________\n");
	printf("Encrypt\n");
	printf("_______________________________________\n");
	unsigned long int n,d;
	/*Pull public keys from file*/
	printf("KEY INPUT FILE = %s\n",KEY_FILE);
	READ_KEYS(KEY_FILE, &n, &d);
	printf("n = %lu, d = %lu\n",n,d);
}


void CHECK_ARGS(){
	if(GENERATE_KEYS && !ENCRYPT && !DECRYPT && INPUT_FILE==NULL && OUTPUT_FILE==NULL && KEY_FILE ==NULL){
		PRODUCE_KEYS();
	}else if(ENCRYPT && !GENERATE_KEYS && !DECRYPT && INPUT_FILE != NULL && OUTPUT_FILE != NULL && KEY_FILE !=NULL){
		RSA_ENCRYPT();
	}else if(DECRYPT && !GENERATE_KEYS && !ENCRYPT && INPUT_FILE != NULL && OUTPUT_FILE != NULL && KEY_FILE !=NULL){
		printf("Decrypt\n");
	}else{
		printf("Wrong command. Please check your command and try again.\n");
	}
}



/*----------------------------------------------------------------------- 
								MAIN
----------------------------------------------------------------------- */

int main(int argc, char *argv[]){
	mpz_inits(Q, P, N, L, E, D, tmpA, tmpB, NULL);
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



