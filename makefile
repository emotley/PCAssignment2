#build an executable named myprog from myprog.c
all: BruteForceIf.c 
	gcc -g -Wall -o BruteSerial BruteForceIf.c -lcrypto

clean: 
	$(RM) BruteSerial