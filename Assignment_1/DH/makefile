define NEWLINE

endef

all:
	gcc DH.c -o dh_assign_1 -lgmp
secret:
	./dh_assign_1 -o output.txt -p 23 -g 9 -a 15 -b 5
clean:
	rm dh_assign_1
	rm output.txt
	