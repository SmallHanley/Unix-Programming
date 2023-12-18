#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <assert.h>

int main(int argc, char *argv[])
{
	pid_t child;
	child = fork();
	if (child == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execvp(argv[1], argv + 1);
	} else {
		int status;
		int counter = 0;
		long magic_addr;
		long restart_addr;
		int magic = 0;
		waitpid(child, &status, 0);
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
		while (WIFSTOPPED(status)) {
			counter++;
			struct user_regs_struct regs;
			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			if (counter == 6) {
				// printf("%ld\n", regs.rax);
				if (regs.rax != 0) {
					counter -= 2;
					regs.rip = restart_addr;
				}
				ptrace(PTRACE_SETREGS, child, NULL, &regs);
				for (int i = 0; i <= 8; i++) {
					long original_data = ptrace(PTRACE_PEEKDATA, child, magic_addr + i, NULL);
					// printf("%c", (char)original_data);
					char data = magic & (1 << i) ? '1' : '0';
					long new_data = (original_data & 0xffffffffffffff00L) | data;
					ptrace(PTRACE_POKEDATA, child, magic_addr + i, new_data);
				}
				// puts("");
				magic++;
			}
			else if (counter == 3) {
				magic_addr = regs.rax;
				printf("Current RIP: 0x%lx\n", magic_addr);
			}
			else if (counter == 4) {
				restart_addr = regs.rip;
			}
			ptrace(PTRACE_CONT, child, 0, 0);
			waitpid(child, &status, 0);
		}
		perror("done");
	}
	return 0;
}
