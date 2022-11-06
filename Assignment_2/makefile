define NEWLINE

endef

all:
	gcc -Wall -o client client.c -L/user/lib -lssl -lcrypto
	gcc -Wall -o server server.c -L/usr/lib -lssl -lcrypto
clean:
	rm client
	rm server
