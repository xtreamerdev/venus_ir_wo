/*
 * venus_ir_wo - Realtek Venus IR Write-Only device
 *
 * Copyright (c) 2011, Pete B. <xtreamerdev@gmail.com>
 *
 * Based on venus_ir_new.c (c) 2010 Gouzhuang:
 *  http://www.cnitblog.com/gouzhuang/archive/2010/05/14/remote_control.html
 * Based on venus_ir_new2.c (c) 2010 Sekator500:
 *  http://www.moservices.org/forum/viewtopic.php?f=12&t=179&start=10#p6580
 * Based on venus_ir.c (c) 2009-2010 Realtek
 *  http://forum.xtreamer.net/mediawiki-1.15.1/index.php/Xtreamer_Source-code#Linux_Kernel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/errno.h>
#include <linux/seq_file.h>
#include <linux/kfifo.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/devfs_fs_kernel.h>
#include <linux/kallsyms.h>

#include <platform.h>
#include "venus_ir_wo.h"

/* uncomment to support (dummy) ioctl */
//#define VENUS_IR_WO_WITH_IOCTL

/*
* Version information
*/
#define DRIVER_VERSION "v0.4"
#define DRIVER_AUTHOR "Pete B., xtreamerdev@gmail.com, http://github.com/xtreamerdev/venus_ir_wo"
#define DRIVER_DESC "Venus IR - Write-Only Driver"

extern platform_info_t platform_info;

static int debug;
static dev_t dev_venus_ir_wo = 0;
static struct cdev *venus_ir_wo_cdev = NULL;
static struct platform_device *venus_ir_wo_devs;

/*
* What we need to hijack from the running venus_ir driver:
* The FIFO is to write the data to, and read_wait is to
* notify pending calls that new data is available
*/
struct kfifo** p_venus_ir_fifo = NULL;
void* p_venus_ir_read_wait = NULL;

/* Driver structure we register with the platform device core */
static struct device_driver venus_ir_wo_driver = {
	.name       = "venus_ir_wo",
	.bus        = &platform_bus_type,
	.suspend    = NULL,
	.resume     = NULL,
};

/*
* Module Functions
*/
static int venus_ir_wo_init(void) {
	unsigned long* vop = NULL;
	int offset;

	if (!is_mars_cpu())
		return -EFAULT;

	/* find the address of 'venus_ir_fifo' from the disassembly of venus_ir_open() */
	vop = (unsigned long*)kallsyms_lookup_name("venus_ir_open");
	if (vop == NULL) {
		printk(KERN_WARNING "venus_ir_wo: failed to locate 'venus_ir_open'");
		return -EFAULT;
	}
	dbg("venus_ir_open = %p\n", vop);
	//        printk("%lx %lx %lx %lx\n", vop[0], vop[1], vop[2], vop[3]);
	offset = 2;
	/*
	* look for the following MIPS asm code:
	*      lui     $v0, 0xAAAA	; 0x3c02AAAA
	*      lw      $a0, 0xBBBB	; 0x8c44BBBB
	* where 0xAAAA is page_nr+1 (msw) and 0xBBBB is the lsw
	*/
	if ( ((vop[offset]&0xFFFF0000)!=0x3c020000) || ((vop[offset+1]&0xFFFF0000)!=0x8c440000) ) {
		printk(KERN_WARNING "venus_ir_wo: asm code does not match\n");
		return -EFAULT;
	}
	/* Friggin' -1 offset on pages!! */
	p_venus_ir_fifo = (void*)(((vop[offset]&0xFFFF)-1)<<16) + (vop[offset+1] & 0xFFFF);
	dbg("&venus_ir_fifo = %p\n", p_venus_ir_fifo);

	/* find the address of 'venus_ir_read_wait' from the disassembly of venus_ir_poll() */
	vop = (unsigned long*)kallsyms_lookup_name("venus_ir_poll");
	if (vop == NULL) {
		printk(KERN_WARNING "venus_ir_wo: failed to locate 'venus_ir_poll'");
		return -EFAULT;
	}
	dbg("venus_ir_poll = %p\n", vop);
	//        printk("%0lx %0lx %0lx %0lx %0lx %0lx\n", vop[0], vop[1], vop[2], vop[3], vop[4], vop[5]);
	offset = 3;
	/*
	* look for the following MIPS asm code:
	*      lui     $v0, 0xAAAA	; 0x3c02AAAA
	*      <conditional branch>
	*      addiu   $a1, $v0, 0xBBBB; 0x2445BBBB
	* where 0xAAAA is page_nr+1 (msw) and 0xBBBB is the lsw
	*/
	if ( ((vop[offset]&0xFFFF0000)!=0x3c020000) || ((vop[offset+2]&0xFFFF0000)!=0x24450000) ) {
		printk(KERN_WARNING "venus_ir_wo: asm code does not match!\n");
		return -EFAULT;
	}
	p_venus_ir_read_wait = (void*)(((vop[offset]&0xFFFF)-1)<<16) + (vop[offset+2] & 0xFFFF);
	dbg("&venus_ir_read_wait = %p\n", p_venus_ir_read_wait);

	return 0;	/* success */
}

int venus_ir_wo_open(struct inode *inode, struct file *filp) {
	return 0;
}

ssize_t venus_ir_wo_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
	uint32_t uintBuf;
	int writeCount;

	if ((p_venus_ir_fifo == NULL) || (p_venus_ir_read_wait == NULL)) {
		return -EFAULT;
	}

	if (count < sizeof(uint32_t)) {
		return 0;
	}

	for (writeCount=0; writeCount<count; writeCount+=sizeof(uint32_t)) {
		if (copy_from_user(&uintBuf, buf, sizeof(uint32_t))) {
			return -EFAULT;
		}
		__kfifo_put(*p_venus_ir_fifo, (unsigned char*)&uintBuf, sizeof(uint32_t));
		dbg("wrote 0x%08x to IR fifo\n", uintBuf);
	}
	/* Wake up all pending processes on FIFO data */
	if (writeCount > 0) {
		wake_up_interruptible(p_venus_ir_read_wait);
	}

	return writeCount;
}

#ifdef VENUS_IR_WO_WITH_IOCTL
int venus_ir_wo_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg) {
	int err = 0;
	int retval = 0;

	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		err =  !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));

	if (err)
		return -EFAULT;

	if (!capable (CAP_SYS_ADMIN))
		return -EPERM;

	switch(cmd) {
	case VENUS_IR_WO_IOC_TEST:
		printk(KERN_INFO "venus_ir_wo: test ioctl called\n");
		break;
	default:
		retval = -ENOIOCTLCMD;
	}
	return retval;
}
#endif

struct file_operations venus_ir_wo_fops = {
	.owner =    THIS_MODULE,
	.open  =    venus_ir_wo_open,
	.write =    venus_ir_wo_write,
#ifdef VENUS_IR_WO_WITH_IOCTL
	.ioctl =    venus_ir_wo_ioctl,
#endif
};

/*
* Create a 'fakekey' sysfs parameter - this allows to issue:
*   echo 'fa05ff00' > /sys/devices/platform/VenusIR_W/fakekey
* to add a new IR key to the VenusIR FIFO
*/
static ssize_t store_fakekey(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	char *endp;
	uint32_t key = simple_strtoul(buf, &endp, 16);
	if (endp != buf && (*endp == '\0' || *endp == '\n')) {
		__kfifo_put(*p_venus_ir_fifo, (unsigned char *)&key, sizeof(uint32_t));
		dbg("wrote 0x%08x to IR fifo\n", key);
		wake_up_interruptible(p_venus_ir_read_wait);
	}
	return count;
}

static DEVICE_ATTR(fakekey, S_IWUSR, NULL, store_fakekey);


/*
* Module init/exit
*/
static int __init venus_ir_wo_init_module(void) {
	int result;

	/* MKDEV */
	dev_venus_ir_wo = MKDEV(VENUS_IR_WO_MAJOR, VENUS_IR_WO_MINOR_RP);

	/* Request Device Number */
	result = register_chrdev_region(dev_venus_ir_wo, VENUS_IR_WO_DEVICE_NUM, "venus_ir_wo");
	if (result < 0) {
		printk(KERN_WARNING "venus_ir_wo: can't register device number.\n");
		goto fail_alloc_dev;
	}

	venus_ir_wo_devs = platform_device_register_simple("VenusIR_W", -1, NULL, 0);
	if (driver_register(&venus_ir_wo_driver) != 0)
		goto fail_device_register;

	/* create sysfs files */
	device_create_file(&venus_ir_wo_devs->dev, &dev_attr_fakekey);

	/* Char Device Registration */
	venus_ir_wo_cdev = cdev_alloc();
	if (venus_ir_wo_cdev == NULL) {
		printk(KERN_ERR "venus_ir_wo: can't allocate cdev\n");
		result = -ENOMEM;
		goto fail_cdev_alloc;
	}
	venus_ir_wo_cdev->ops = &venus_ir_wo_fops;
	if (cdev_add(venus_ir_wo_cdev, MKDEV(VENUS_IR_WO_MAJOR, VENUS_IR_WO_MINOR_RP), 1)) {
		printk(KERN_ERR "venus_ir_wo: can't add character device\n");
		result = -ENOMEM;
		goto fail_cdev_add;
	}

	/* use devfs to create device file */
	devfs_mk_cdev(MKDEV(VENUS_IR_WO_MAJOR, VENUS_IR_WO_MINOR_RP), S_IFCHR|S_IRUSR|S_IWUSR, VENUS_IR_WO_DEVICE_FILE);

	/* rest of the init */
	result = venus_ir_wo_init();
	if (result)
		goto fail_init;

	printk(KERN_INFO "venus_ir_wo: driver loaded\n");
	return 0;	/* success */

fail_init:
	devfs_remove(VENUS_IR_WO_DEVICE_FILE);
fail_cdev_add:
	cdev_del(venus_ir_wo_cdev);
fail_cdev_alloc:
	driver_unregister(&venus_ir_wo_driver);
	device_remove_file(&venus_ir_wo_devs->dev, &dev_attr_fakekey);
fail_device_register:
	if (!IS_ERR(venus_ir_wo_devs))
		platform_device_unregister(venus_ir_wo_devs);
	unregister_chrdev_region(dev_venus_ir_wo, VENUS_IR_WO_DEVICE_NUM);
fail_alloc_dev:
	return result;
}

static void __exit venus_ir_wo_cleanup_module(void)
{
	/* remove device file by devfs */
	devfs_remove(VENUS_IR_WO_DEVICE_FILE);

	/* remove sysfs files */
	device_remove_file(&venus_ir_wo_devs->dev, &dev_attr_fakekey);

	/* Release Character Device Driver */
	cdev_del(venus_ir_wo_cdev);

	/* device driver removal */
	if (!IS_ERR(venus_ir_wo_devs))
		platform_device_unregister(venus_ir_wo_devs);
	driver_unregister(&venus_ir_wo_driver);

	/* Return Device Numbers */
	unregister_chrdev_region(dev_venus_ir_wo, VENUS_IR_WO_DEVICE_NUM);

	printk(KERN_INFO "venus_ir_wo: driver unloaded\n");
}

/* Register Macros */
module_init(venus_ir_wo_init_module);
module_exit(venus_ir_wo_cleanup_module);

/* Register module parameters */
module_param(debug, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "enable debug info");

/* Module information */
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");
