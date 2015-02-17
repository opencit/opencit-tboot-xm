/*
 * rpmmio_main: a tpm driver that enables access to locality other than 0.
 *
 * Copyright (c) 2006-2010, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/fs.h> /*this is the file structure, file open read close */
#include<linux/cdev.h> /* this is for character device, makes cdev avilable*/
#include<linux/semaphore.h> /* this is for the semaphore*/
#include<linux/uaccess.h> /*this is for copy_user vice vers*/

#include "tpm.h"


int chardev_init(void);


void chardev_exit(void);
static int device_open(struct inode *, struct file *);
static int device_close(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);
static loff_t device_lseek(struct file *file, loff_t offset, int orig);

/*new code*/
#define BUFFER_SIZE 1024
static char device_buffer[BUFFER_SIZE];
struct semaphore sem;
struct cdev *mcdev; /*this is the name of my char driver that i will be registering*/
int major_number; /* will store the major number extracted by dev_t*/
int ret; /*used to return values*/
dev_t dev_num; /*will hold the major number that the kernel gives*/

#define DEVICENAME "rpmmio"


#define TPMMAXBUF   4096

static int g_locality=0;
static int g_pcr = 21;
void *g_tpm_base;

/*inode reffers to the actual file on disk*/
static int device_open(struct inode *inode, struct file *filp) {
    if(down_interruptible(&sem) != 0) {
        printk(KERN_ALERT "rpmmio : the device has been opened by some other device, unable to open lock\n");
        return -1;
    }
    //buff_rptr = buff_wptr = device_buffer;
    printk(KERN_INFO "rpmmio : device opened succesfully\n");
    return 0;
}

static ssize_t device_read(struct file *fp, char *buff, size_t size, loff_t *ppos) {

  char _kbuff[TPMMAXBUF];
  size_t i= 0; 

  if(buff == NULL || size > TPMMAXBUF){
    printk(KERN_ERR "rpmmio: read error, buff null or size %d > %d\n", size, TPMMAXBUF);
    return -1;
  }
  printk(KERN_INFO "rpmmio: read\n");

  //testing
  // for(i= 0; i<size; i++){
  //   _kbuff[i]= 'a';
  //}

/*
   //real code for TPM read
  ulong addrbase = (((ulong)tpm_base | (g_locality << 12))|g_pcr)+i;
  printk(KERN_ALERT "rpmmio: to read access %#010x\n", addrbase);
  
  for(i= 0; i<size; i++){
	  //ulong addr = (((ulong)tpm_base | (g_locality << 12))|g_pcr)+i;
    //_kbuff[i]= readb((TPM_LOCALITY_BASE_N(g_locality)|g_pcr)+i);
    //_kbuff[i]= readb(addr);
    _kbuff[i]= ioread8(addrbase+i);
  }

  copy_to_user(buff, _kbuff, size);
  */
  tpm_pcr_value_t out= {{0,}};
  tpm_pcr_read(g_locality, g_pcr, &out);
  copy_to_user(buff, out.digest, size);
  printk(KERN_ALERT "rpmmio: read, size %d\n", size);
  return size;

}

static ssize_t device_write(struct file *fp, const char *buff, size_t size, loff_t *ppos) {

  //char _kbuff[TPMMAXBUF];
  size_t i= 0;
  tpm_digest_t in;
  tpm_pcr_value_t out= {{0,}};

  //if(buff == NULL || size > TPMMAXBUF){
  if(buff == NULL || size>TPM_DIGEST_SIZE){	
	  printk(KERN_ERR "rpmmio: write error, buff null or size %d > %d\n", size, TPMMAXBUF);
    return -1;
  }

  copy_from_user(in.digest, buff, size);

   tpm_pcr_extend(g_locality, g_pcr, &in, &out);

/*
ulong addrbase = ((ulong)tpm_base | (g_locality << 12))|g_pcr;
printk(KERN_ALERT "rpmmio: to write access %#010x\n", addrbase);
  for(i= 0; i<size; i++){
        //writeb((TPM_LOCALITY_BASE_N(g_locality)|g_pcr)+i, _kbuff[i]);
        ulong addr = addrbase+i;
        //writeb(addr);
        iowrite8(_kbuff[i], (void*)addr);
	}

	*/

	
 	

  printk(KERN_ALERT "rpmmio: write, size %d\n", size);
  return size;
}

static loff_t device_lseek(struct file *file, loff_t offset, int orig) {
  g_locality =(int) offset &0XFFFF;
  g_pcr = (offset >> 16) &0XFFFF;
 
  printk(KERN_INFO "locality: %d, pcr: %d\n", g_locality, g_pcr);
  return 0;
}

static int device_close(struct inode *inode, struct file *filp) {
    up(&sem);
    printk(KERN_ALERT "rpmmio : device has been closed\n");
    return ret;
}

struct file_operations fops = { /* these are the file operations provided by our driver */
    .owner = THIS_MODULE, /*prevents unloading when operations are in use*/
    .open = device_open,  /*to open the device*/
    .write = device_write, /*to write to the device*/
    .read = device_read, /*to read the device*/
    .release = device_close, /*to close the device*/
    .llseek = device_lseek
};


int chardev_init(void) 
{
    /* we will get the major number dynamically this is recommended please read ldd3*/
    ret = alloc_chrdev_region(&dev_num,0,1,DEVICENAME);
    if(ret < 0) {
        printk(KERN_ALERT " rpmmio : failed to allocate major number\n");
        return ret;
    }
    else
        printk(KERN_INFO " rpmmio : mjor number allocated succesful\n");
    major_number = MAJOR(dev_num);
    printk(KERN_INFO "rpmmio : major number of our device is %d\n",major_number);
    printk(KERN_INFO "rpmmio : to use mknod /dev/%s c %d 0\n",DEVICENAME,major_number);

    mcdev = cdev_alloc(); /*create, allocate and initialize our cdev structure*/
    mcdev->ops = &fops;   /*fops stand for our file operations*/
    mcdev->owner = THIS_MODULE;

    /*we have created and initialized our cdev structure now we need to add it to the kernel*/
    ret = cdev_add(mcdev,dev_num,1);
    if(ret < 0) {
        printk(KERN_ALERT "rpmmio : device adding to the kerknel failed\n");
        return ret;
    }
    else
        printk(KERN_INFO "rpmmio : device additin to the kernel succesful\n");
    sema_init(&sem,1);  /* initial value to one*/

	g_tpm_base = ioremap_cache(TPM_LOCALITY_BASE, 0x5000);
	
	printk(KERN_ALERT "rpmmio: iomap base %lx\n", (ulong)g_tpm_base);
    return 0;
}

void chardev_exit(void)
{
	iounmap(g_tpm_base);
	
    cdev_del(mcdev); /*removing the structure that we added previously*/
    printk(KERN_INFO " rpmmio : removed the mcdev from kernel\n");

    unregister_chrdev_region(dev_num,1);
    printk(KERN_INFO "rpmmio : unregistered the device numbers\n");
    printk(KERN_ALERT " rpmmio : character driver is exiting\n");
}

MODULE_LICENSE("GPL");    

module_init(chardev_init);
module_exit(chardev_exit);
