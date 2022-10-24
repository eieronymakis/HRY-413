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




/* 
	RSA IMPLEMENTATION
*/


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

/* 
	Saves the plain text read from the input file in the array which content ptr is pointing.
*/
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

/*
	Saves decrypted plain text to the output file
*/
void SAVE_FILE_CONTENT(char* data, long length){
	FILE *file = fopen(OUTPUT_FILE, "w");
	if(!file){
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Fopen Error : Output file doesn't exist\n"   ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		exit(-1);
	}
	fseek(file, 0, SEEK_SET);
	for(int i = 0; i < length; i++){
		fputc(data[i], file);
	}
	fclose(file);
}

/*	
	Save produced keys in the appropriate files
	Public Key 	-> public.key  (Format is N,D)
	Private Key	-> private.key (Format is N,E) 
*/
void SAVE_KEYS(){
	
	char * public_key_fname = "public.key";
	char * private_key_fname = "private.key";

	FILE* fpub = fopen(public_key_fname, "w");
	FILE* fpriv = fopen(private_key_fname, "w");

	if(!(fpub && fpriv)){
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Fopen Error : Public/Private key file doesn't exist\n"   ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
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

/* 
	Sets the keys read from the key input file
*/
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

/*
	From lectures we know that an e constraints are: 
		->		1 < e < lambda
		->		e is prime
		-> 		e % lambda != 0 
		->		gcd(e,lambda) = 1
	Given these using a for loop in range [2, lambda -1], I check if the number is prime using GMP lib,
	if it satisfies the last 2 constraints then I set e as that number.
	This method is not optimal since e is not random but it's enough for this case.
*/

void FIND_E(){
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"Calculating e...\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);

	mpz_set_ui(tmpA,2);
	while(mpz_cmp(tmpA,L) < 0){
		if(IS_PRIME(tmpA)){
			mpz_mod(tmpB, tmpA, L);
			mpz_gcd(tmpC, tmpA, L);
			gmp_printf("e = %Zd, lambda = %Zd, mod = %Zd, gcd = %Zd\n",tmpA,L,tmpB,tmpC);
			if(mpz_cmp_ui(tmpB, 0) != 0 && mpz_cmp_ui(tmpC, 1) == 0){
				mpz_set(E, tmpA);
				break;
			}
		}
		mpz_add_ui(tmpA, tmpA,1);
	}
}

/*	
	This function makes all the needed calculations
	in order to produce the private and public key
	using the gmp library	
*/
void PRODUCE_KEYS(){
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"Generate Keys\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);

	/*get Q and P*/
	
	printf("Enter the prime number Q : ");
	gmp_scanf("%Zd", Q);

	/* Q prime check */
	while(!IS_PRIME(Q)){
		printf("Given Q is not a prime number, please type a prime : ");
		gmp_scanf("%Zd", Q);
	}

	printf("Enter the prime number P : ");
	gmp_scanf("%Zd", P);

	/* P prime check */
	while(!IS_PRIME(P)){
		printf("Given P is not a prime number, please type a prime : ");
		gmp_scanf("%Zd", P);
	}

	/*also set the gmp variables for Q-1 and P-1*/
	mpz_sub_ui(tmpA, Q, 1);
	mpz_sub_ui(tmpB, P, 1);

	/*calculate  (P * Q)*/
	mpz_mul(N, P, Q);
	
	/*calculate lamda */
	mpz_mul(L, tmpA, tmpB);

	/*calculate E based on Lambda*/
	FIND_E();

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

	/* Print setting information */
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

/* 
	This method reads the keys from the given key file, then creates an encrypted object (size_t) array.
	Takes each character from the given plain text input file and uses GMP's modular exponentation method mpz_powm(result, base, exp, modulo) to encrypt it.
	Stores each encrypted object in the array I created and then writes the array in the output file.

	Warning: the key you use for encryption will be your private key.
*/

void RSA_ENCRYPT(){
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"Encryption...\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	
	/*Get keys from file*/
	size_t p1, p2;
	READ_KEYS(&p1, &p2);
	mpz_set_ui(tmpA, p1);	
	mpz_set_ui(tmpB, p2);	

	printf(ANSI_COLOR_YELLOW"Key parts\n(can be (P1,P2)=(n,d) or (P1,P2)=(n,e)\n,depending the key we want to use public/private) \n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf("P1 =\t\t\t"ANSI_COLOR_GREEN"%zu\n"ANSI_COLOR_RESET"P2 =\t\t\t"ANSI_COLOR_GREEN"%zu\n"ANSI_COLOR_RESET,p1,p2);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	
	/* Array storing the given input (text) */
	char* plain_content;
	size_t plain_content_len;
	/* Get plain text */
	GET_FILE_CONTENT(&plain_content, &plain_content_len);


	/* Array storing the encrypted objects, size of 8 (size_t) * n (n = number of characters in plain text) bytes */
	size_t* cipher = malloc( sizeof(size_t) * plain_content_len); 

	/* Encrypt each plain text character with modular exponentation and store it in the encrypted object array */
	for(int i = 0; i < plain_content_len; i++){
		mpz_set_ui(tmpC, (size_t) plain_content[i]); 
		mpz_powm(tmpD, tmpC, tmpB, tmpA);
		cipher[i] = (size_t) mpz_get_ui(tmpD);
	}

	FILE *file = fopen(OUTPUT_FILE, "w");
	if(!file){
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Fopen Error : could not open output file.\n"   ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		exit(-1);
	}

	/* Write the encrypted object array in the output file */
	/* Output file should have size of 8 * (plain text char count) bytes */
	fseek(file, 0, SEEK_SET);
	fwrite(cipher, sizeof(size_t), plain_content_len, file);
	fclose(file);

	printf(ANSI_COLOR_YELLOW"Encryption Completed!\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
}

/*
	This method firstly reads the keys from the file given in the command line as option k.
	Then reads the encrypted file and produces a an array of characters which will store the decrypted text.
	Using a for loop based on the number of encrypted size_t objects, each one of these objects gets decrypted to a char using the modular exponentation method.
	Modular exponent is produced with GMP's command mpz_powm(result, base, exp, modulo).
	After everything is done save the character array to the output file given in the command line which results to the original plain text.
	
	Warning : in order to decrypt the encrypted file, you have to use the public key if you used the private key for encryption (or the other way around).
*/
void RSA_DECRYPT(){
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"Decryption...\n"ANSI_COLOR_RESET);
	
	/* Set key values from file */
	size_t p1, p2;
	READ_KEYS(&p1, &p2);
	mpz_set_ui(tmpA, p1); 
	mpz_set_ui(tmpB, p2); 

	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf("P1 =\t\t\t"ANSI_COLOR_GREEN"%zu\n"ANSI_COLOR_RESET"P2 =\t\t\t"ANSI_COLOR_GREEN"%zu\n"ANSI_COLOR_RESET,p1,p2);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	
	
	FILE *file = fopen(INPUT_FILE, "r");
	if(!file){
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Fopen Error : could not open encrypted file.\n"   ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		exit(-1);
	}

	/* Get encypted file byte length */
	fseek(file, 0, SEEK_END);
	size_t cipher_bytes = ftell(file);
	fseek(file, 0, SEEK_SET);

	/* Get the amount of characters the output plain text file will have by dividing the bytes of encrypted file with the size of encrypted object*/
	size_t plain_content_len = cipher_bytes / sizeof(size_t);
	/* Array for the encrypted objects */
	size_t* cipher = malloc( sizeof(size_t) * plain_content_len);
	/* Initialize the char array for the decrypted characters */
	char* plain_content = malloc( sizeof(char) * plain_content_len);
	/* Get the encrypted objects */
	fread(cipher, sizeof(size_t), plain_content_len, file);
	

	/* Get the decrypted object (char) from the modular exponent of the encrypted object (size_t) */
	for(int i = 0; i < plain_content_len; i++){
		mpz_set_ui(tmpC, (size_t) cipher[i]); 
		mpz_powm(tmpD, tmpC, tmpB, tmpA);
		plain_content[i] = (char) mpz_get_ui(tmpD);
	}
	
	/* Save decrypted text to file */
	SAVE_FILE_CONTENT(plain_content, plain_content_len);

	printf(ANSI_COLOR_YELLOW"Decryption Completed!\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
}


/*
	Function used to process the inputs passed from the command line
*/
void CHECK_ARGS(){
	/* This combination means I want to generate keys */
	if(GENERATE_KEYS && !ENCRYPT && !DECRYPT && INPUT_FILE==NULL && OUTPUT_FILE==NULL && KEY_FILE ==NULL){
		PRODUCE_KEYS();
	/* This combination means I want to encrypt a plain text file */
	}else if(ENCRYPT && !GENERATE_KEYS && !DECRYPT && INPUT_FILE != NULL && OUTPUT_FILE != NULL && KEY_FILE !=NULL){
		RSA_ENCRYPT();
	/* This combination means I want to decrypt an encrypted file */
	}else if(DECRYPT && !GENERATE_KEYS && !ENCRYPT && INPUT_FILE != NULL && OUTPUT_FILE != NULL && KEY_FILE !=NULL){
		RSA_DECRYPT();
	/* What happens in every other case*/
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


	/* Get the arguments passed from the command line and initialize globals */
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

	CHECK_ARGS();
}



