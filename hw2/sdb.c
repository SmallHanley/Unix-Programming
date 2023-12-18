#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <assert.h>
#include <capstone/capstone.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>

struct breakpoint {
	long target;
	long code;
	struct breakpoint *next;
};

struct maps {
	long min;
	long max;
	long *data;
	struct maps *next;
};

int main(int argc, char *argv[])
{
	pid_t child;
	child = fork();
	if (child == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execvp(argv[1], argv + 1);
	} else {
		int fd = open(argv[1], O_RDONLY);
		if (fd == -1) {
			perror("Failed to open ELF file");
			exit(1);
		}

		off_t file_size = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);

		void *file_buffer = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (file_buffer == MAP_FAILED) {
			perror("Failed to mmap ELF file");
			close(fd);
			exit(1);
		}

		csh handle;
		cs_insn *insn;
		int count, instr = 0;

		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
			printf("Failed to initialize Capstone\n");
			munmap(file_buffer, file_size);
			close(fd);
			exit(1);
		}

		Elf64_Ehdr *elf_header = (Elf64_Ehdr *)file_buffer;
		Elf64_Addr entry_addr = elf_header->e_entry;

		Elf64_Off ph_offset = elf_header->e_phoff;

		Elf64_Phdr *program_header = (Elf64_Phdr *)(file_buffer + ph_offset);
		int i;
		for (i = 0; i < elf_header->e_phnum; ++i) {
			if (program_header[i].p_type == PT_LOAD && entry_addr >= program_header[i].p_vaddr &&
					entry_addr < (program_header[i].p_vaddr + program_header[i].p_memsz)) {
				break;
			}
		}

		long start_offset = entry_addr - program_header[i].p_vaddr;

		count = cs_disasm(handle, file_buffer + program_header[i].p_offset, program_header[i].p_filesz, entry_addr - start_offset, 0, &insn);
		int status;
		waitpid(child, &status, 0);
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

		struct breakpoint *bp_head = NULL;
		struct user_regs_struct anchor_regs;
		struct maps *maps_head = NULL;
		int anchor_instr;

		int fd2, sz;
		char buf[16384], *s = buf, *line, *saveptr;
		char name[64];
		sprintf(name, "/proc/%d/maps", child);
		fd2 = open(name, O_RDONLY);	
		sz = read(fd2, buf, sizeof(buf) - 1);
		buf[sz] = 0;
		close(fd2);

		while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
			if(strstr(line, " rw") != NULL) {
				long min, max;
				if(sscanf(line, "%lx-%lx ", &min, &max) != 2)
					perror("get_base/main");
				struct maps *m = malloc(sizeof(struct maps));
				m->min = min;
				m->max = max;
				m->data = malloc((max - min) * sizeof(char));
				m->next = maps_head;
				maps_head = m;
			}
		}

		while (insn[instr].address < entry_addr) {
			instr++;
		}

		printf("** program '%s' loaded. entry point 0x%lx\n", argv[1], entry_addr);

		for (int j = instr; j < instr + 5; j++) {
			if (j >= count) {
				puts("** the address is out of the range of the text section.");
				break;
			}
			printf("\t%"PRIx64": ", insn[j].address);
			for (int k = 0; k < 10; k++) {
				if (k < insn[j].size)
					printf("%02x ", insn[j].bytes[k]);
				else
					printf("   ");
			}
			printf("%s\t  %s\n", insn[j].mnemonic, insn[j].op_str);
		}

		while (1) {
			char cmd[64];
			printf("(sdb) ");
			fgets(cmd, 64, stdin);
			char *word = strtok(cmd, " ");
			if (!strcmp(word, "si\n")) {
				struct user_regs_struct regs;
				ptrace(PTRACE_GETREGS, child, NULL, &regs);

				for (struct breakpoint *t = bp_head; t != NULL; t = t->next) {
					if (t->target == regs.rip) {
						long code = ptrace(PTRACE_PEEKTEXT, child, t->target, 0);
						ptrace(PTRACE_POKETEXT, child, t->target, (code & 0xffffffffffffff00) | (t->code & 0xff));
						break;
					}
				}

				ptrace(PTRACE_SINGLESTEP, child, 0, 0);
				instr++;
				waitpid(child, &status, 0);

				ptrace(PTRACE_GETREGS, child, NULL, &regs);

				for (struct breakpoint *t = bp_head; t != NULL; t = t->next) {
					if (t->target == regs.rip) {
						long code = ptrace(PTRACE_PEEKTEXT, child, t->target, 0);
						ptrace(PTRACE_POKETEXT, child, t->target, (code & 0xffffffffffffff00) | (t->code & 0xff));
						printf("** hit a breakpoint at 0x%lx\n", t->target);
						break;
					}
				}

				if (WIFEXITED(status)) {
					break;
				}

				instr = 0;
				while (insn[instr].address < regs.rip) {
					instr++;
				}

				for (int j = instr; j < instr + 5; j++) {
					if (j >= count) {
						puts("** the address is out of the range of the text section.");
						break;
					}
					printf("\t%"PRIx64": ", insn[j].address);
					for (int k = 0; k < 10; k++) {
						if (k < insn[j].size)
							printf("%02x ", insn[j].bytes[k]);
						else
							printf("   ");
					}
					printf("%s\t  %s\n", insn[j].mnemonic, insn[j].op_str);
				}
			} else if (!strcmp(word, "cont\n")) {
				struct user_regs_struct regs;
				ptrace(PTRACE_GETREGS, child, NULL, &regs);

				for (struct breakpoint *t = bp_head; t != NULL; t = t->next) {
					if (t->target == regs.rip) {
						long code = ptrace(PTRACE_PEEKTEXT, child, t->target, 0);
						ptrace(PTRACE_POKETEXT, child, t->target, (code & 0xffffffffffffff00) | (t->code & 0xff));
						ptrace(PTRACE_SINGLESTEP, child, 0, 0);
						waitpid(child, &status, 0);
						ptrace(PTRACE_POKETEXT, child, t->target, (code & 0xffffffffffffff00) | 0xcc);
						break;
					}
				}

				ptrace(PTRACE_GETREGS, child, NULL, &regs);

				int check = 0;
				for (struct breakpoint *t = bp_head; t != NULL; t = t->next) {
                                        if (t->target == regs.rip) {
						check = 1;
                                                break;
                                        }
                                }

				if (check) {
					printf("** hit a breakpoint at 0x%llx\n", regs.rip);
					instr = 0;
					while (insn[instr].address < regs.rip) {
						instr++;
					}

					for (int j = instr; j < instr + 5; j++) {
						if (j >= count) {
							puts("** the address is out of the range of the text section.");
							break;
						}
						printf("\t%"PRIx64": ", insn[j].address);
						for (int k = 0; k < 10; k++) {
							if (k < insn[j].size)
								printf("%02x ", insn[j].bytes[k]);
							else
								printf("   ");
						}
						printf("%s\t  %s\n", insn[j].mnemonic, insn[j].op_str);
					}
					continue;
				}

				ptrace(PTRACE_CONT, child, 0, 0);
				waitpid(child, &status, 0);

				ptrace(PTRACE_GETREGS, child, NULL, &regs);

				for (struct breakpoint *t = bp_head; t != NULL; t = t->next) {
					if (t->target == regs.rip - 1) {
						long code = ptrace(PTRACE_PEEKTEXT, child, t->target, 0);
						ptrace(PTRACE_POKETEXT, child, t->target, (code & 0xffffffffffffff00) | (t->code & 0xff));
						regs.rip = regs.rip - 1;
						ptrace(PTRACE_SETREGS, child, 0, &regs);
						printf("** hit a breakpoint at 0x%lx\n", t->target);
						break;
					}
				}

				if (WIFEXITED(status)) {
					break;
				}

				instr = 0;
				while (insn[instr].address < regs.rip) {
					instr++;
				}

				for (int j = instr; j < instr + 5; j++) {
					if (j >= count) {
						puts("** the address is out of the range of the text section.");
						break;
					}
					printf("\t%"PRIx64": ", insn[j].address);
					for (int k = 0; k < 10; k++) {
						if (k < insn[j].size)
							printf("%02x ", insn[j].bytes[k]);
						else
							printf("   ");
					}
					printf("%s\t  %s\n", insn[j].mnemonic, insn[j].op_str);
				}
			} else if (!strcmp(word, "break")) {
				word = strtok(NULL, " ");
				long target;
				sscanf(word, "0x%lx", &target);
				printf("** set a breakpoint at 0x%lx.\n", target);
				long code = ptrace(PTRACE_PEEKTEXT, child, target, 0);
				struct breakpoint *bp = malloc(sizeof(struct breakpoint));
				bp->target = target;
				bp->code = code;
				bp->next = bp_head;
				bp_head = bp;
				ptrace(PTRACE_POKETEXT, child, target, (code & 0xffffffffffffff00) | 0xcc);
			} else if (!strcmp(word, "anchor\n")) {
				puts("** dropped an anchor");
				ptrace(PTRACE_GETREGS, child, NULL, &anchor_regs);
				anchor_instr = instr;
				for (struct maps *t = maps_head; t != NULL; t = t->next) {
					for (long j = t->min, k = 0; j < t->max; j += 8, k++) {
						t->data[k] = ptrace(PTRACE_PEEKDATA, child, j, NULL);
					}
				}
			} else if (!strcmp(word, "timetravel\n")) {
				puts("** go back to the anchor point");
				ptrace(PTRACE_SETREGS, child, 0, &anchor_regs);
				instr = anchor_instr;
				for (struct maps *t = maps_head; t != NULL; t = t->next) {
					for (long j = t->min, k = 0; j < t->max; j += 8, k++) {
						ptrace(PTRACE_POKEDATA, child, j, t->data[k]);
					}
				}

				for (int j = instr; j < instr + 5; j++) {
					if (j >= count) {
						puts("** the address is out of the range of the text section.");
						break;
					}
					printf("\t%"PRIx64": ", insn[j].address);
					for (int k = 0; k < 10; k++) {
						if (k < insn[j].size)
							printf("%02x ", insn[j].bytes[k]);
						else
							printf("   ");
					}
					printf("%s\t  %s\n", insn[j].mnemonic, insn[j].op_str);
				}
			}

			for (struct breakpoint *t = bp_head; t != NULL; t = t->next) {
				long code = ptrace(PTRACE_PEEKTEXT, child, t->target, 0);
				ptrace(PTRACE_POKETEXT, child, t->target, (code & 0xffffffffffffff00) | 0xcc);
			}
		}

		puts("** the target program terminated.");
		cs_free(insn, count);
		cs_close(&handle);
		munmap(file_buffer, file_size);
		close(fd);
	}
	return 0;
}
