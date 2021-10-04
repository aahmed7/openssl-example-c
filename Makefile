CC=gcc
LIBS=-lcrypto

example1:
	$(CC) encrypt_example.c -o $@ $(LIBS)

example2:
	$(CC) encrypt_example2.c -o $@ $(LIBS)

clean:
	rm example1 example2 encrypt.txt dec22.txt

