gcc --version Output:
_________________________________________________________________________________________________________
gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0

What did I implement?
_________________________________________________________________________________________________________
Everything.

This folder contains 2 subdirectories:
_________________________________________________________________________________________________________
Diffie Hellman tool is contained inside the DH folder along with the appropriate makefile.
RSA tool is contained inside the RSA folder along with the appropriate makefile.

Implementation overview
_________________________________________________________________________________________________________
Both tools contain detailed comments (almost every line) about the logic used to build them in the appropriate files RSA.c and DH.c
but below is an overview.
_________________________________________________________________________________________________________
RSA Key Production -> RSA.c (void PRODUCE_KEYS() function) : 

I get the user input P,Q, then check if they are primes, 
If they are then I calculate N = P*Q and lambda(N)=(P-1)*(Q-1),
Based on the value of lambda using the function "void FIND_E()" I loop through all the numbers between [2, lambda - 1] (because 1 < e < lambda),
and check if that number is prime and meets the 'e' variable criteria (e%lambda!=0 and gcd(e,lambda)=1). 
The first number that meets the criteria is set to 'e'.
Having e and lambda, I calculate d = (the inverse of e modulo lambda) using the gmp_invert() function.
Lastly having (n,d) (n,e) I save these pairs in the appropriate files public.key, private.key.
_________________________________________________________________________________________________________
RSA Encryption -> RSA.c (void RSA_ENCRYPT() function): 

I load the key file then read the pair of variables in the key (n,d) or (n,e).
I load the file plain text then for each character using a for loop I compute the modular exponentation (base = plaintext character, modulo = n, exponent = d or e) to create the cypher character.
Each cypher character is of size_t (8 bytes) and gets saved into an array.
The cypher character array then gets saved to the output file which is the encrypted file.
The key used to encrypt can be public/private but the key used to decrypt has to be the opposite of the one chosen to encrypt.
_________________________________________________________________________________________________________
RSA Decryption -> RSA.c (void RSA_DECRYPT() function): 

I load the key file then I do the same thing as the encryption method,
but this time I'm doing modular exponentation (base = cypher character, modulo =n, exponent = d or e (opposite of the one used in ecryption)) on each cypher character,
I save each plain text character produced by decryption of the cypher character to a string,
then I save the string in the decrypted plain text file.
_________________________________________________________________________________________________________
DH Secret creation:

I get the variables P,G,A,B and I check if P is prime and if G is defintely not a primitive root of P,
also that A < P and B < P.
I then create the public key of A using the private number A and the public key of B using the private number B,
using modular exponentation Example. mpz_powm(public_key_a, G, secret_a, P).
I compute the secret of B using the public of A and secret of B.
I compute the secret of A using the public of B and secret of A.
The secret is computed using modular exponentation.
If these secrets match the algorithm works and I save <PUBLIC_KEY_OF_A><PUBLIC_KEY_OF_B><SHARED_SECRET> in the output file.
_________________________________________________________________________________________________________
Important : (All calculations,checks,loops etc. are done using the GMP Library) 
_________________________________________________________________________________________________________
Makefile commands:
_________________________________________________________________________________________________________
RSA makefile : 
_________________________________________________________________________________________________________
-> make :           Compiles the RSA.c file written for the tool

-> make keys :      Asks for user input of P, Q then produces the public.key and private.key files

-> make encrypt :   Encrypts the input plaintext.txt file using the private.key
                    The produced file is going to be called encrypted.txt (contains the cypher)

-> make decrypt :   Decrypts the input encrypted.txt file produced from make encrypt using the public.key
                    Produces the decrypted.txt file which should contain the original text from 
                    plaintext.txt

-> make clean   :   Deletes all the generated files
_________________________________________________________________________________________________________
Example of command order : 
    1) make
    2) make keys
    3) make encrypt
    4) make decrypt
    5) make clean
_________________________________________________________________________________________________________
You can also use the tool manually:
    After make you can run :
        Key generation :
            ./rsa_assign_1 -g
        Encryption : 
            ./rsa_assign_1 -i {YOUR_INPUT_FILE} -o {YOUR_OUTPUT_FILE} -k {PUBLIC/PRIVATE_KEY_FILE} -e
        Decryption : 
            ./rsa_assign_1 -i {YOUR_INPUT_FILE} -o {YOUR_OUTPUT_FILE} -k {PUBLIC/PRIVATE_KEY_FILE} -d
_________________________________________________________________________________________________________
Important -> If you want for example to decrypt an encrypted file you have to use the opposite key.
             Let's say you use public.key for encryption you have to use private.key for decryption or
             vise versa.
_________________________________________________________________________________________________________
DH makefile :
_________________________________________________________________________________________________________
-> make :           Compiles the DH.c file written for the tool

-> make secret :    Computes public key of A, public key of B, the secret on each side.
                    If the secret is the same (shared) then creates the output.txt file which contains
                    <PUBLIC_KEY_OF_A><PUBLIC_KEY_OF_B><SHARED_SECRET> in this order

-> make clean :     Deletes all the generated files
_________________________________________________________________________________________________________
Example of command order : 
    1) make
    2) make secret
    3) make clean
_________________________________________________________________________________________________
You can also use the tool manually:
    After make you can run :
    ./dh_assign_1 -o {YOUR_OUTPUT_FILE} -p {PRIME_P} -g {NUMBER_G} -a {PRIVATE_KEY_A} -b {PRIVATE_KEY_B}
    This creates the output file taken as -o option which contains the computed
    <PUBLIC_KEY_OF_A><PUBLIC_KEY_OF_B><SHARED_SECRET> in this order.
_________________________________________________________________________________________________________

