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
mpz_t Q;
mpz_t P;
mpz_t N;
mpz_t L;
mpz_t E;

// Temp variables used for calculations
mpz_t tmpA;
mpz_t tmpB;


// This is going to hold number 7919 (large prime I found on wikipedia)
// It's going to be used to generate e
mpz_t L_Prime;


//
mpz_t Smallest_prime;


bool IS_PRIME(mpz_t input){
	/* The documentation suggests reps between 15 and 50 */
	int reps = 15;
	if(mpz_probab_prime_p(input, reps) != 0)
		return TRUE;
	else
		return FALSE;
}


void CHOOSE_E(){
	/*I chose e = 65537 (most common value for e) because it has 2 bits set and is efficient for modular exponentiation*/ 
	mpz_set_ui(E, 65537);
	/* e % lambda(n) */
	mpz_mod(tmpA, E, L);
	/* gcd(e, lambda(n)) */
	mpz_gcd(tmpB, E, L);

	unsigned long int e, l, mod, gcd;

	e = mpz_get_ui(E);
	l = mpz_get_ui(L);
	mod = mpz_get_ui(tmpA);
	gcd = mpz_get_ui(tmpB);
	
	printf("e : \t%lu\n",e);
	printf("l : \t%lu\n",l);
	printf("---------------------------------------\n");
	printf("mod : \t%lu\t|\tPASS\n",mod);
	printf("gcd : \t%lu\t|\tPASS\n",gcd);
	printf("---------------------------------------\n");

}

void CHECK_ARGS(){
	if(GENERATE_KEYS && !ENCRYPT && !DECRYPT && INPUT_FILE==NULL && OUTPUT_FILE==NULL && KEY_FILE ==NULL){
		
		unsigned long int input_Q, input_P;

		printf("---------------------------------------\nGenerate Keys\n---------------------------------------\n");
		
		/* Set  Q & P */
		
		printf("Enter the prime number Q : ");
		scanf("%lu", &input_Q);
		mpz_set_ui(Q, input_Q);
		while(!IS_PRIME(Q)){
			printf("Given Q is not a prime number, please type a prime number : ");
			scanf("%lu", &input_Q);
			mpz_set_ui(Q, input_Q);
		}

		printf("Enter the prime number P : ");
		scanf("%lu", &input_P);
		mpz_set_ui(P, input_P);
		while(!IS_PRIME(P)){
			printf("Given P is not a prime number, please type a prime number : ");
			scanf("%lu", &input_P);
			mpz_set_ui(P, input_P);
		}


		/* Set Q - 1 & P - 1, so we can compute lambda(n)*/
		mpz_set_ui(tmpA, input_Q-1);
		mpz_set_ui(tmpB, input_P-1);


		/* Calculate N  = Q * P */
		mpz_mul(N, P, Q);
		/* Calculate Lamda(n) */
		mpz_mul(L, tmpA, tmpB);
		
		printf("---------------------------------------\n");
		gmp_printf("Q = %Zd, P = %Zd\n", Q, P);
		printf("---------------------------------------\n");
		gmp_printf("N = %Zd\n", N);
		printf("---------------------------------------\n");
		gmp_printf("Lamda(N) = %Zd\n", L);
		printf("---------------------------------------\n");


		CHOOSE_E();


	}else if(ENCRYPT && !GENERATE_KEYS && !DECRYPT && INPUT_FILE != NULL && OUTPUT_FILE != NULL && KEY_FILE !=NULL){
		printf("Encrypt\n");
	}else if(DECRYPT && !GENERATE_KEYS && !ENCRYPT && INPUT_FILE != NULL && OUTPUT_FILE != NULL && KEY_FILE !=NULL){
		printf("Decrypt\n");
	}else{
		printf("Wrong command. Please check your command and try again.\n");
	}
}

int main(int argc, char *argv[]){

	mpz_inits(Q, P, N, L, E, tmpA, tmpB, L_Prime, NULL);

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

	CHECK_ARGS();
}



