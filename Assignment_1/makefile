define NEWLINE

endef

all:
	gcc rsa.c -o rsa_assign_1 -lgmp
keys:
	./rsa_assign_1 -g
encrypt:
	./rsa_assign_1 -i plaintext.txt -o ciphertext.txt -k public.key -e
decrypt:
	./rsa_assign_1 -i ciphertext2.txt -o plaintext2.txt -k public.key -d
readkeys:
	./rsa_assign_1 -r
