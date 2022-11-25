all: logger acmonitor test_aclog rsa

rsa: rsa.c
	gcc rsa.c -o rsa -lgmp

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog 

decrypt:
	./rsa -i encrypted_logging.log -o decrypted_logging.log -d -k public.key

clean:
	rm -rf logger.so
	rm -rf rsa
	rm -rf test_aclog
	rm -rf acmonitor
	rm -rf file_*
	rm -rf encrypted_logging.log
	rm -rf decrypted_logging.log