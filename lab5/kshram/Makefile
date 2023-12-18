
obj-m     += kshram.o
ccflags-y += -DEXPORT_SYMTAB -Wno-declaration-after-statement

all: check_msg check_resize check_fork
	make -C ../dist/modulebuild M=$(PWD) modules

check_msg: check_msg.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

check_resize: check_resize.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

check_fork: check_fork.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f check_msg check_resize check_fork
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp check_msg check_resize check_fork kshram.ko ../rootfs/modules
