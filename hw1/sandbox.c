#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <elf.h>

#define errquit(m) \
    {              \
        perror(m); \
        _exit(-1); \
    }

static long got_min = 0, got_max = 0, base;
static char *config_path;
static int logger_fd;
static char file_log[64][1638400];
static char content[16384000];

int (*old_fptr)(int *(main) (int, char **, char **),
                int argc,
                char **ubp_av,
                void (*init)(void),
                void (*fini)(void),
                void (*rtld_fini)(void),
                void(*stack_end));

void get_base_addr();
void got_hijack();

int __libc_start_main(int *(main) (int, char **, char **),
                      int argc,
                      char **ubp_av,
                      void (*init)(void),
                      void (*fini)(void),
                      void (*rtld_fini)(void),
                      void(*stack_end))
{
    int ret;
    config_path = getenv("SANDBOX_CONFIG");
    logger_fd = atoi(getenv("LOGGER_FD"));
    get_base_addr();
    got_hijack();
    if (old_fptr == NULL) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if (handle != NULL)
            old_fptr = dlsym(handle, "__libc_start_main");
    }
    if (old_fptr != NULL)
        ret = old_fptr(main, argc, ubp_av, init, fini, rtld_fini, stack_end); 
    return ret;
}

void get_base_addr()
{
    int fd, sz;
    long left, right;
    char buf[16384], *s = buf, *line, *saveptr;
    if ((fd = open("/proc/self/maps", O_RDONLY)) < 0)
        errquit("get_base/open");
    if ((sz = read(fd, buf, sizeof(buf) - 1)) < 0)
        errquit("get_base/read");
    buf[sz] = 0;
    close(fd);

    char exe[256];
    memset(exe, 0, sizeof(exe));
    if (readlink("/proc/self/exe", exe, sizeof(exe)) == -1) {
        errquit("readlink");
    }

    int cnt = 0;
    while ((line = strtok_r(s, "\n\r", &saveptr)) != NULL) {
        s = NULL;
        if(strstr(line, exe) != NULL) {
            if (sscanf(line, "%lx-%lx ", &left, &right) != 2)
                errquit("get_base/main");
            if (cnt == 0) {
                base = left;
            } else if (cnt == 2) {
                got_min = left;
                mprotect((void *) left, right - left,
                        PROT_READ | PROT_WRITE | PROT_EXEC);
            } else if (cnt == 3) {
                got_max = right;
                mprotect((void *) left, right - left,
                        PROT_READ | PROT_WRITE | PROT_EXEC);
                return;
            }
            cnt++;
        }
    }
    _exit(-fprintf(stderr, "** get_base failed.\n"));
}

void got_hijack()
{
    void *handle = dlopen("sandbox.so", RTLD_LAZY);
    char exe[256];
    memset(exe, 0, sizeof(exe));
    if (readlink("/proc/self/exe", exe, sizeof(exe)) == -1) {
        errquit("readlink");
    }
    int fd = open(exe, O_RDONLY|O_SYNC);
    Elf32_Ehdr eh32;
    struct stat st;
    void *file;
    char *strtab;
    char *dyntab;

    if (fd < 0) {
        errquit("open");
    }

    if (fstat(fd, &st) < 0) {
        errquit("fstat");
    }

    read(fd, &eh32, sizeof(Elf32_Ehdr));
    if (eh32.e_ident[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Rela *rela;
        Elf64_Sym *dynsym;

        file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (file == MAP_FAILED) {
            errquit("mmap");
        }
        ehdr = (Elf64_Ehdr *)file;
        shdr = (Elf64_Shdr *)(file + ehdr->e_shoff);

        strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

        for (int i = 0; i < ehdr->e_shnum; i++) {
            if (!strcmp(strtab + shdr[i].sh_name, ".rela.plt")) {
                rela = file + shdr[i].sh_offset;
                for (int j = 0; j < shdr[i].sh_size / sizeof(Elf64_Rela); j++) {
                    Elf64_Sym *sym = &dynsym[ELF64_R_SYM(rela[j].r_info)];
                    if (!strcmp(dyntab + sym->st_name, "open")) {
                        long offset = (long)rela[j].r_offset;
                        long *entry = (long *) (base + offset);
                        *entry = (long) dlsym(handle, "my_open");
                    } else if (!strcmp(dyntab + sym->st_name, "read")) {
                        long offset = (long)rela[j].r_offset;
                        long *entry = (long *) (base + offset);
                        *entry = (long) dlsym(handle, "my_read");
                    } else if (!strcmp(dyntab + sym->st_name, "write")) {
                        long offset = (long)rela[j].r_offset;
                        long *entry = (long *) (base + offset);
                        *entry = (long) dlsym(handle, "my_write");
                    } else if (!strcmp(dyntab + sym->st_name, "connect")) {
                        long offset = (long)rela[j].r_offset;
                        long *entry = (long *) (base + offset);
                        *entry = (long) dlsym(handle, "my_connect");
                    } else if (!strcmp(dyntab + sym->st_name, "getaddrinfo")) {
                        long offset = (long)rela[j].r_offset;
                        long *entry = (long *) (base + offset);
                        *entry = (long) dlsym(handle, "my_getaddrinfo");
                    } else if (!strcmp(dyntab + sym->st_name, "system")) {
                        long offset = (long)rela[j].r_offset;
                        long *entry = (long *) (base + offset);
                        *entry = (long) dlsym(handle, "my_system");
                    }
                }
            }
            else if (!strcmp(strtab + shdr[i].sh_name, ".dynsym")) {
                dynsym = file + shdr[i].sh_offset;
            }
            else if (!strcmp(strtab + shdr[i].sh_name, ".dynstr")) {
                dyntab = (char *)(file + shdr[i].sh_offset);
            }
        }

        munmap(file, st.st_size);
    }
    else {
        puts("0");
    }
    close(fd);
}

int my_open(const char *path, int oflag, ...)
{
    char real_path[256];
    memset(real_path, 0, sizeof(real_path));
    if (!realpath(path, real_path)) {
        strcpy(real_path, path);
    }

    int fd, sz;
    char buf[16384], *s = buf, *line, *saveptr;
    if ((fd = open(config_path, O_RDONLY)) < 0)
        errquit("got_hijack/open");
    if ((sz = read(fd, buf, sizeof(buf) - 1)) < 0)
        errquit("got_hijack/read");
    buf[sz] = 0;
    close(fd);

    va_list args;
    va_start(args, oflag);
    mode_t mode;
    if (oflag & O_CREAT)
        mode = va_arg(args, mode_t);
    else
        mode = 0;
    va_end(args);

    bool begin = false;
    while ((line = strtok_r(s, "\n\r", &saveptr)) != NULL) {
        s = NULL;
        if (strstr(line, "BEGIN open-blacklist")) {
            begin = true;
        } else if (strstr(line, "END open-blacklist")) {
            begin = false;
        } else if (begin) {
            char blacklist_real_path[256];
            memset(blacklist_real_path, 0, sizeof(blacklist_real_path));
            if (!realpath(line, blacklist_real_path)) {
                strcpy(blacklist_real_path, line);
            }
            if (!strcmp(real_path, blacklist_real_path)) {
                dprintf(logger_fd, "[logger] open(\"%s\", %d, %d) = %d\n",
                        real_path, oflag, mode, -1);
                errno = EACCES;
                return -1;
            }
        }
    }

    int ret = open(real_path, oflag, mode);
    dprintf(logger_fd, "[logger] open(\"%s\", %d, %d) = %d\n", real_path, oflag,
            mode, ret);
    return ret;
}

ssize_t my_read(int fildes, void *buf, size_t nbyte)
{
    ssize_t ret = read(fildes, buf, nbyte);

    if (ret != -1) {
        memcpy(content, buf, ret);
        content[ret] = '\0';
        strcat(file_log[fildes], content);

        int fd, sz;
        char buffer[16384], *s = buffer, *line, *saveptr;
        if ((fd = open(config_path, O_RDONLY)) < 0)
            errquit("got_hijack/open");
        if ((sz = read(fd, buffer, sizeof(buffer) - 1)) < 0)
            errquit("got_hijack/read");
        buffer[sz] = 0;
        close(fd);

        bool begin = false;
        while ((line = strtok_r(s, "\n\r", &saveptr)) != NULL) {
            s = NULL;
            if (strstr(line, "BEGIN read-blacklist")) {
                begin = true;
            } else if (strstr(line, "END read-blacklist")) {
                begin = false;
            } else if (begin) {
                if (strstr(file_log[fildes], line)) {
                    close(fildes);
                    dprintf(logger_fd, "[logger] read(%d, %p, %ld) = %d\n",
                            fildes, buf, nbyte, -1);
                    errno = EIO;
                    return -1;
                }
            }
        }

        pid_t pid = getpid();
        char log_name[256];
        sprintf(log_name, "%d-%d-read.log", pid, fildes);
        FILE *fp = fopen(log_name, "a");
        fwrite(buf, 1, ret, fp);
        fclose(fp);
    }

    dprintf(logger_fd, "[logger] read(%d, %p, %ld) = %ld\n", fildes, buf, nbyte,
            ret);
    return ret;
}

ssize_t my_write(int fildes, const void *buf, size_t nbyte)
{
    ssize_t ret = write(fildes, buf, nbyte);

    if (ret != -1) {
        memcpy(content, buf, ret);
        content[ret] = '\0';
        pid_t pid = getpid();
        char log_name[256];
        sprintf(log_name, "%d-%d-write.log", pid, fildes);
        FILE *fp = fopen(log_name, "a");
        fprintf(fp, "%s", content);
        fclose(fp);
    }
    dprintf(logger_fd, "[logger] write(%d, %p, %ld) = %ld\n", fildes, buf,
            nbyte, ret);
    return ret;
}

int my_connect(int socket,
               const struct sockaddr *address,
               socklen_t address_len)
{
    struct sockaddr_in *addrin = (struct sockaddr_in *) address;
    char ip[256];
    int connect_port = ntohs(addrin->sin_port);
    strcpy(ip, inet_ntoa(addrin->sin_addr));
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_ALL;
    hints.ai_protocol = 0;
    hints.ai_socktype = SOCK_STREAM;

    int fd, sz;
    char buf[16384], *s = buf, *line, *saveptr;
    if ((fd = open(config_path, O_RDONLY)) < 0)
        errquit("got_hijack/open");
    if ((sz = read(fd, buf, sizeof(buf) - 1)) < 0)
        errquit("got_hijack/read");
    buf[sz] = 0;
    close(fd);

    bool begin = false;
    while ((line = strtok_r(s, "\n\r", &saveptr)) != NULL) {
        s = NULL;
        if (strstr(line, "BEGIN connect-blacklist")) {
            begin = true;
        } else if (strstr(line, "END connect-blacklist")) {
            begin = false;
        } else if (begin) {
            char hostname[256];
            char tok[8][256];
            int port;
            char *token;
            token = strtok(line, ":");
            int i = 0;
            while (token != NULL) {
                strcpy(tok[i++], token);
                token = strtok(NULL, ":");
            }
            strcpy(hostname, tok[0]);
            port = atoi(tok[1]);
            if (getaddrinfo(hostname, NULL, &hints, &result) == -1) {
                errquit("getaddrinfo");
            }
            for (rp = result; rp != NULL; rp = rp->ai_next) {
                struct sockaddr_in *addrin = (struct sockaddr_in *) rp->ai_addr;
                if (!strcmp(inet_ntoa(addrin->sin_addr), ip) &&
                    port == connect_port) {
                    dprintf(logger_fd, "[logger] connect(%d, %s, %d) = %d\n",
                            socket, ip, address_len, -1);
                    errno = ECONNREFUSED;
                    return -1;
                }
            }
            freeaddrinfo(result);
        }
    }

    int ret = connect(socket, address, address_len);

    dprintf(logger_fd, "[logger] connect(%d, %s, %d) = %d\n", socket, ip,
            address_len, ret);
    return ret;
}


int my_getaddrinfo(const char *node,
                   const char *service,
                   const struct addrinfo *hints,
                   struct addrinfo **res)
{
    int fd, sz;
    char buf[16384], *s = buf, *line, *saveptr;
    if ((fd = open(config_path, O_RDONLY)) < 0)
        errquit("got_hijack/open");
    if ((sz = read(fd, buf, sizeof(buf) - 1)) < 0)
        errquit("got_hijack/read");
    buf[sz] = 0;
    close(fd);

    bool begin = false;
    while ((line = strtok_r(s, "\n\r", &saveptr)) != NULL) {
        s = NULL;
        if (strstr(line, "BEGIN getaddrinfo-blacklist")) {
            begin = true;
        } else if (strstr(line, "END getaddrinfo-blacklist")) {
            begin = false;
        } else if (begin) {
            if (!strcmp(node, line)) {
                dprintf(logger_fd,
                        "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n",
                        node, service, hints, res, EAI_NONAME);
                return EAI_NONAME;
            }
        }
    }

    int ret = getaddrinfo(node, service, hints, res);
    dprintf(logger_fd, "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n",
            node, service, hints, res, ret);
    return ret;
}

int my_system(const char *command)
{
    dprintf(logger_fd, "[logger] system(\"%s\")\n", command);
    int ret = system(command);

    return ret;
}
