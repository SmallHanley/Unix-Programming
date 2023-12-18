.PHONY: all test format clean
CC=gcc
CFLAGS=-g -Wall -shared -fPIC

all: sandbox.so

sandbox.so: sandbox.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	./launcher ./sandbox.so config.txt cat /etc/passwd || true
	echo "-----------------------------------------------"
	./launcher ./sandbox.so config.txt cat /etc/hosts || true
	echo "-----------------------------------------------"
	./launcher ./sandbox.so config.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem || true
	echo "-----------------------------------------------"
	./launcher ./sandbox.so config.txt wget http://google.com -t 1 || true
	echo "-----------------------------------------------"
	./launcher ./sandbox.so config.txt wget https://www.nycu.edu.tw -t 1 || true
	echo "-----------------------------------------------"
	./launcher ./sandbox.so config.txt wget http://www.google.com -q -t 1 || true
	$(MAKE) clean

format:
	clang-format -i sandbox.c

clean:
	$(RM) *.so tmp *.log index*
