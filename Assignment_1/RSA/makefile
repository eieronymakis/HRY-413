define NEWLINE

endef

all:
	gcc RSA.c -o rsa_assign_1 -lgmp
keys:
	./rsa_assign_1 -g
encrypt:
	./rsa_assign_1 -i plaintext.txt -o encrypted.txt -k private.key -e
decrypt:
	./rsa_assign_1 -i encrypted.txt -o decrypted.txt -k public.key -d
clean:
	rm rsa_assign_1
	rm *.key
	rm encrypted.txt
	rm decrypted.txt

