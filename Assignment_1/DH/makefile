define NEWLINE

endef

all:
	gcc DH.c -o dh_assign_1 -lgmp
key:
	./dh_assign_1 -o output.txt -p 23 -g 9 -a 15 -b 5
clean:
	rm output.txt