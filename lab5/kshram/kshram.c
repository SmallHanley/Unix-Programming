/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <asm/io.h>

#include "kshram.h"

#define DEVICE_NAME "kshram"
#define DEVICE_COUNT 8
#define DEVICE_SIZE 4096

struct kshram_device {
    char* mem;
    int idx;
    size_t size;
    struct cdev cdev;
};

static dev_t devnum;
static struct kshram_device devices[DEVICE_COUNT];
static struct class *clazz;

static int kshram_open(struct inode *i, struct file *f) {
	struct kshram_device* dev = container_of(i->i_cdev, struct kshram_device, cdev);
	f->private_data = dev;
	// printk(KERN_INFO "kshram: device opened.\n");
	return 0;
}

static int kshram_close(struct inode *i, struct file *f) {
	// printk(KERN_INFO "kshram: device closed.\n");
	return 0;
}

static ssize_t kshram_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	printk(KERN_INFO "kshram: read %zu bytes @ %llu.\n", len, *off);
	return len;
}

static ssize_t kshram_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	printk(KERN_INFO "kshram: write %zu bytes @ %llu.\n", len, *off);
	return len;
}

static long kshram_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	struct kshram_device* dev = f->private_data;
	switch (cmd) {
	case KSHRAM_GETSLOTS:
		return DEVICE_COUNT;
	case KSHRAM_GETSIZE:
		return dev->size;
	case KSHRAM_SETSIZE:
		dev->size = arg;
		char *mem = krealloc(dev->mem, arg, GFP_KERNEL);
		if (!mem)
			return -1;
		dev->mem = mem;
		return 0;
	default:
		printk(KERN_INFO "kshram: ioctl invaild cmd\n");
		return -1;
	}
	printk(KERN_INFO "kshram: ioctl cmd=%u arg=%lu.\n", cmd, arg);
	return 0;
}

static int kshram_mmap(struct file *f, struct vm_area_struct *vma) {
	struct kshram_device* dev = f->private_data;
	unsigned long pfn = virt_to_phys((void *)dev->mem)>>PAGE_SHIFT;
	unsigned long len = vma->vm_end - vma->vm_start;
	int ret;

	for(int i = 0; i < dev->size; i += PAGE_SIZE)
		SetPageReserved(virt_to_page(((unsigned long)dev->mem) + i));

	ret = remap_pfn_range(vma, vma->vm_start, pfn, len, vma->vm_page_prot);
	if (ret < 0) {
	    pr_err("could not map the address area\n");
	    return -EIO;
	}
	printk(KERN_INFO "kshram/mmap: idx %d size %ld\n", dev->idx, dev->size);
	return ret;
}

static const struct file_operations kshram_fops = {
	.owner = THIS_MODULE,
	.open = kshram_open,
	.read = kshram_read,
	.write = kshram_write,
	.unlocked_ioctl = kshram_ioctl,
	.release = kshram_close,
	.mmap = kshram_mmap
};

static int kshram_proc_read(struct seq_file *m, void *v) {
	for (int i = 0; i < DEVICE_COUNT; i++) {
		char buf[256];
		sprintf(buf, "%02d: %ld\n", i, devices[i].size);
		seq_printf(m, buf);
	}
	return 0;
}

static int kshram_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, kshram_proc_read, NULL);
}

static const struct proc_ops kshram_proc_fops = {
	.proc_open = kshram_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *kshram_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init kshram_init(void)
{
	if((clazz = class_create(THIS_MODULE, "upclass")) == NULL)
		return -1;
	clazz->devnode = kshram_devnode;

	if (alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
		goto fail_chrdev;

	int i;
	for (i = 0; i < DEVICE_COUNT; i++) {
		devices[i].mem = kzalloc(DEVICE_SIZE, GFP_KERNEL);
		if (devices[i].mem == NULL) {
            		goto fail_mem;
        	}
		printk(KERN_INFO "kshram%d: %d bytes allocated @ %px\n", i, DEVICE_SIZE, devices[i].mem);
		devices[i].idx = i;
        	devices[i].size = DEVICE_SIZE;
		if (device_create(clazz, NULL, MKDEV(MAJOR(devnum), i), NULL, "%s%d", DEVICE_NAME, i) == NULL)
			goto fail_create;
		cdev_init(&devices[i].cdev, &kshram_fops);
		if (cdev_add(&devices[i].cdev, MKDEV(MAJOR(devnum), i), 1) == -1)
			goto fail_cdev_add;
	}

	// create proc
	proc_create("kshram", 0, NULL, &kshram_proc_fops);

	printk(KERN_INFO "kshram: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

fail_cdev_add:
	device_destroy(clazz, MKDEV(MAJOR(devnum), i));
fail_create:
	kfree(devices[i].mem);
fail_mem:
	for (--i; i >= 0; i--) {
		cdev_del(&devices[i].cdev);
		device_destroy(clazz, MKDEV(MAJOR(devnum), i));
		kfree(devices[i].mem);
	}
	unregister_chrdev_region(devnum, 1);
fail_chrdev:
	class_destroy(clazz);

	printk(KERN_INFO "kshram: error.\n");

	return -1;
}

static void __exit kshram_cleanup(void)
{
	remove_proc_entry("kshram", NULL);

	for (int i = 0; i < DEVICE_COUNT; i++) {
		cdev_del(&devices[i].cdev);
		device_destroy(clazz, MKDEV(MAJOR(devnum), i));
		for(int j = 0; j < devices[i].size; j += PAGE_SIZE)
			ClearPageReserved(virt_to_page(((unsigned long)devices[i].mem) + j));
		kfree(devices[i].mem);
	}

	unregister_chrdev_region(devnum, 1);
	class_destroy(clazz);

	printk(KERN_INFO "kshram: cleaned up.\n");
}

module_init(kshram_init);
module_exit(kshram_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tklin");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
