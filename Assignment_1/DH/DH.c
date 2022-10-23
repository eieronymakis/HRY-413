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
char *OUTPUT_FILE = NULL;

mpz_t P;    /*  Prime number    */
mpz_t G;    /*  Must be a primitive root of P (above)   */
mpz_t A;    /*  Private key A   */
mpz_t B;    /*  Private key B   */

mpz_t PUBLIC_KEY_OF_A;
mpz_t PUBLIC_KEY_OF_B;

mpz_t SECRET_OF_A;
mpz_t SECRET_OF_B;


void SAVE_TO_FILE(){
    FILE *file = fopen(OUTPUT_FILE, "w");
    if(!file){
        printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Fopen Error : Could not write to output file\n"   ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
        return;
    }
    fseek(file, 0, SEEK_SET);
    
    size_t pa = (size_t) mpz_get_ui(PUBLIC_KEY_OF_A);
    size_t pb = (size_t) mpz_get_ui(PUBLIC_KEY_OF_B);
    size_t shared_secret = (size_t) mpz_get_ui(SECRET_OF_A);

    fwrite(&pa, sizeof(size_t), 1, file);
    fwrite(&pb, sizeof(size_t), 1, file);
    fwrite(&shared_secret, sizeof(size_t), 1, file);

    fclose(file);
}

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

void CREATE_PUBLIC_KEY(mpz_t SECRET, mpz_t OUTPUT){
    mpz_powm(OUTPUT, G, SECRET, P);
}

void COMPUTE_SECRET(mpz_t PUBLIC_KEY, mpz_t SECRET_NUMBER,mpz_t OUTPUT){
    mpz_powm(OUTPUT, PUBLIC_KEY, SECRET_NUMBER, P);
}

void PRODUCE_SECRET(){
    printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW "Settings\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
    gmp_printf("P =\t\t"ANSI_COLOR_GREEN"%Zd\n"ANSI_COLOR_RESET, P);
    gmp_printf("G =\t\t"ANSI_COLOR_GREEN"%Zd\n"ANSI_COLOR_RESET, G);
    gmp_printf("A =\t\t"ANSI_COLOR_GREEN"%Zd\n"ANSI_COLOR_RESET, A);
    gmp_printf("B =\t\t"ANSI_COLOR_GREEN"%Zd\n"ANSI_COLOR_RESET, B);
    printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW "Producing Secret...\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
    
    
    CREATE_PUBLIC_KEY(A, PUBLIC_KEY_OF_A);
    CREATE_PUBLIC_KEY(B, PUBLIC_KEY_OF_B);

	printf(ANSI_COLOR_YELLOW "Public keys\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	gmp_printf( "Public key of A =\t\t" ANSI_COLOR_GREEN "%Zd\n" ANSI_COLOR_RESET, PUBLIC_KEY_OF_A);
    gmp_printf( "Public key of B =\t\t" ANSI_COLOR_GREEN "%Zd\n" ANSI_COLOR_RESET, PUBLIC_KEY_OF_B);
    printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);

    COMPUTE_SECRET(PUBLIC_KEY_OF_B, A, SECRET_OF_A);
    COMPUTE_SECRET(PUBLIC_KEY_OF_A, B, SECRET_OF_B);

    printf(ANSI_COLOR_YELLOW "Secrets produced\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);
	gmp_printf( "Secret produced by A =\t\t" ANSI_COLOR_GREEN "%Zd\n" ANSI_COLOR_RESET, SECRET_OF_A);
    gmp_printf( "Secret produced by B =\t\t" ANSI_COLOR_GREEN "%Zd\n" ANSI_COLOR_RESET, SECRET_OF_B);
    printf(ANSI_COLOR_YELLOW"_______________________________________\n"ANSI_COLOR_RESET);


    if(mpz_cmp(SECRET_OF_A, SECRET_OF_B) == 0){
        printf(ANSI_COLOR_GREEN"_______________________________________\n"ANSI_COLOR_RESET);
	    printf(ANSI_COLOR_GREEN "Secrets match\n" ANSI_COLOR_RESET);
	    printf(ANSI_COLOR_GREEN"_______________________________________\n"ANSI_COLOR_RESET);

        SAVE_TO_FILE();

    }else{
        printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
	    printf(ANSI_COLOR_RED "Error : Secrets don't match\n" ANSI_COLOR_RESET);
	    printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
    }

    
}   

void CHECK_ARGS(){
    bool false_arguments = FALSE;
    if(!IS_PRIME(P)){
        printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Argument Error : P must be a prime.\n"   ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
        false_arguments = TRUE;
    }
    if(mpz_cmp(A,P) >= 0 ){
        printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Argument Error : Private key A must be less than P\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
        false_arguments = TRUE;
    }
    if(mpz_cmp(B,P) >= 0 ){
        printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"Argument Error : Private key B must be less than P\n"ANSI_COLOR_RESET);
		printf(ANSI_COLOR_RED"_______________________________________\n"ANSI_COLOR_RESET);
        false_arguments = TRUE;
    }

    if(false_arguments)
        return;

    PRODUCE_SECRET();
}

int main(int argc, char *argv[]){

    mpz_inits(P, G, A, B, PUBLIC_KEY_OF_A, PUBLIC_KEY_OF_B, SECRET_OF_A, SECRET_OF_B, NULL);

	int opt;
	while((opt= getopt(argc, argv, "o:p:g:a:b:h")) != -1){
		switch(opt){
			case 'o':
                OUTPUT_FILE = strdup(optarg);
				break;
            case 'p':
                mpz_set_ui(P,(size_t) atoi(optarg));
                break;
            case 'g':
                mpz_set_ui(G,(size_t) atoi(optarg));
				break;
            case 'a':
                mpz_set_ui(A,(size_t) atoi(optarg));
				break;
            case 'b':
                mpz_set_ui(B,(size_t) atoi(optarg));
				break;
            case 'h':
				break;
			default:
				return 0;
		}
	}
	CHECK_ARGS();
    return 0;
}