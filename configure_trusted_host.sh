#!/bin/bash
# This script takes the boot device name and lvm name as input and copies the pre-created manifest.xml, rootfs to boot directory
# It also generates initrd containing tpmextend binary and required tpm kernel modules and copies to boot directory

KERNEL_VERSION=3.11.0-24-generic
KERNEL_NAME=vmlinuz-$KERNEL_VERSION
INITRD_NAME=initrd.img-$KERNEL_VERSION-measurement
ROOTFS_TAR=rootfs.tar.gz
MANIFEST_FILE=tcb-manifest.xml
SINIT_BIN=3rd_gen_i5_i7_SINIT_67.BIN
BOOT_DIR="/boot/"
CONF_DIR=""
GRUB_CFG="/boot/grub/grub.cfg"
GRUB_ENTRY_NAME=TCB-protection
BOOT_DIR_PREFIX=""
XEN_NAME=xen-4.2-amd64.gz

echo "Configure the host for which hypervisor? (KVM/XEN)"
read input

if [ $input != "XEN" ] && [ $input != "KVM" ] ; then
    echo "Please type 'XEN' or 'KVM'"
    exit 1
fi

if [ $input == "KVM" ]; then
    PREGENERATED_FILES=kvm_pre_generated_files
fi
if [ $input == "XEN" ]; then
    PREGENERATED_FILES=xen_pre_generated_files
fi


echo "Enter boot device name (e.g. /dev/sda1)"
read boot_device

if [ -z $boot_device ]; then
    echo "This value can not be blank"
    exit 1
fi

# The manifest xml, key and rootfs tar could be on the boot parition or on any other partition
echo "should 'manifest xml', 'storage volume encryption key' and 'rootfs tar' be copied to boot device $boot_device for booting? (y/n)"
while : ; do
    read conf_location_resp
    if [ "$conf_location_resp" == "n" ]; then
        echo "Enter the device name that contains 'manifest xml', 'storage volume encryption key' and 'rootfs tar' (e.g. /dev/sda2)"
        read conf_device
        if [ -z $conf_device ]; then
            echo "This value can not be blank"
            exit 1
        fi
        # From the device, find the mount point that contains manifest xml, key and rootfs tar
        CONF_DIR=`df  |grep "$conf_device" | awk '{print $NF}'`
        if [ -z "$CONF_DIR" ]; then
            echo "The device $conf_device doesn't have a mount point on the system"
            exit 1
        fi
        break    
    elif [ "$conf_location_resp" == "y" ]; then
        conf_device=$boot_device
        CONF_DIR=$BOOT_DIR
        break
    else
        echo "Please type 'y' or 'n'"
    fi
done


# Check if boot directory is a separate partition or a part of partition mounted at /
df -h |grep "$boot_device" | awk '{ print $NF }'| grep "/boot"
if [ $? -eq 0 ]; then
    BOOT_DIR_PREFIX=""
else
    BOOT_DIR_PREFIX="/boot"
fi

# Check if boot partition is same as conf partition
if [ "$boot_device" == "$conf_device" ]; then
    CONF_DIR_PREFIX=$BOOT_DIR_PREFIX
else
    CONF_DIR_PREFIX=""
fi

echo "Enter LVM device name to be used as root filesystem (e.g. /dev/mapper/vg1-host_vol)"
read host_lvm_device

if [ -z $host_lvm_device ]; then
    echo "This value can not be blank"
    exit 1
fi

fdisk -l 2>/dev/null | grep $host_lvm_device &> /dev/null
if [ $? -ne 0 ]; then
    echo "The device $host_lvm_device is not present in the system. Please check the output of fdisk -l"
    exit 1
fi

if [ $input != "XEN" ] ; then
    echo "Enter encrypted LVM device name to be used for guest storage (e.g. /dev/mapper/vg1-storage_vol)"
else
    echo "Enter encrypted LVM device name to be used for persistent storage (e.g. /dev/mapper/vg1-storage_vol)"
fi
read storage_lvm_device

if [ -z $storage_lvm_device ]; then
    echo "This value can not be blank"
    exit 1
fi

fdisk -l 2>/dev/null | grep $storage_lvm_device &> /dev/null 
if [ $? -ne 0 ]; then
    echo "The device $storage_lvm_device is not present in the system. Please check the output of fdisk -l"
    exit 1
fi

echo "Enter encrypted LVM device name to be used for swap (e.g. /dev/mapper/vg1-swap_vol)"
read swap_lvm_device

if [ -z $swap_lvm_device ]; then
    echo "This value can not be blank"
    exit 1
fi

fdisk -l 2>/dev/null | grep $swap_lvm_device &> /dev/null 
if [ $? -ne 0 ]; then
    echo "The device $swap_lvm_device is not present in the system. Please check the output of fdisk -l"
    exit 1
fi

if [ $input == "XEN" ];then
    echo "Enter encrypted SR device name to be used for Storage Repository of Xen (e.g. /dev/mapper/vg1-sr_vol)"
    read sr_lvm_device

    if [ -z $sr_lvm_device ]; then
        echo "This value can not be blank"
        exit 1
    fi

    fdisk -l 2>/dev/null | grep $sr_lvm_device &> /dev/null
    if [ $? -ne 0 ]; then
        echo "The device $sr_lvm_device is not present in the system. Please check the output of fdisk -l"
        exit 1
    fi
fi

echo "Enter the name of key file that was used to encrypt the storage and swap. (e.g. /boot/tcb_lvm.key)"
echo "(The key was generated on disk by the script setup_encrypted_lvm.sh)"
read lvm_enc_key_path

if [ ! -f $lvm_enc_key_path ]; then
    echo "$lvm_enc_key_path was not found"
    exit 1
fi

lvm_enc_key=`echo $lvm_enc_key_path | awk -F/ '{print $NF}'`

echo "Enter TPM major version (e.g. 1 or 2)"
read tpm_major_version


echo "copying pre-generated rootfs tarball to plain boot partition"
cp $PREGENERATED_FILES/$ROOTFS_TAR $CONF_DIR

echo "copying pre-generated tcb manifest xml to plain boot partition"
cp $PREGENERATED_FILES/$MANIFEST_FILE $CONF_DIR

echo "Copying key to $CONF_DIR"
cp $lvm_enc_key_path $CONF_DIR

echo "copying SINIT binary to plain boot partition"
cp $PREGENERATED_FILES/$SINIT_BIN $BOOT_DIR

echo "copying kernel and initrd to plain boot partition"
cp $PREGENERATED_FILES/$KERNEL_NAME $BOOT_DIR
cp $PREGENERATED_FILES/$INITRD_NAME $BOOT_DIR

boot_device_uuid=`blkid $boot_device | sed -n 's/.*UUID=\"\([^\"]*\)\".*/\1/p'`
echo "UUID of boot device is $boot_device_uuid"

prev_grub_entry_count=`cat $GRUB_CFG | grep $GRUB_ENTRY_NAME | wc -l`
serial_no=$((prev_grub_entry_count+1))
grub_entry_current=$GRUB_ENTRY_NAME-$serial_no


if [ $input == "KVM" ];then
read -d '' grub_entry <<EOF
menuentry '$grub_entry_current' --class ubuntu --class gnu-linux --class gnu --class os --class tboot {
    insmod part_msdos
    insmod ext2
    set         root='(hd0,msdos1)'
    search      --no-floppy --fs-uuid --set=root $boot_device_uuid
    echo        'Loading tboot ...'
    multiboot   $BOOT_DIR_PREFIX/tboot.gz $BOOT_DIR_PREFIX/tboot.gz logging=serial,vga,memory
    echo        'Loading Linux "$KERNEL_VERSION" ...'
    module      $BOOT_DIR_PREFIX/$KERNEL_NAME $BOOT_DIR_PREFIX/$KERNEL_NAME root=$boot_device ro intel_iommu=on host_lvm_device=$host_lvm_device storage_lvm_device=$storage_lvm_device swap_lvm_device=$swap_lvm_device boot_partition=$boot_device conf_partition=$conf_device rootfs_path=$CONF_DIR_PREFIX/$ROOTFS_TAR manifest_path=$CONF_DIR_PREFIX/$MANIFEST_FILE lvm_enc_key=$CONF_DIR_PREFIX/$lvm_enc_key tpm_major_version=$tpm_major_version
    echo        'Loading initial ramdisk ...'
    module      $BOOT_DIR_PREFIX/$INITRD_NAME $BOOT_DIR_PREFIX/$INITRD_NAME
    echo        'Loading sinit $SINIT_BIN ...'
    module      $BOOT_DIR_PREFIX/$SINIT_BIN $BOOT_DIR_PREFIX/$SINIT_BIN
}
EOF
fi

if [ $input == "XEN" ];then
echo "copying pre-generated $XEN_NAME to plain boot partition" 
cp $PREGENERATED_FILES/$XEN_NAME $BOOT_DIR

read -d '' grub_entry <<EOF
menuentry '$grub_entry_current' --class ubuntu --class gnu-linux --class gnu --class os --class tboot {
    insmod part_msdos
    insmod ext2
    set         root='(hd0,msdos1)'
    search      --no-floppy --fs-uuid --set=root $boot_device_uuid
    echo        'Loading tboot ...'
    multiboot   $BOOT_DIR_PREFIX/tboot.gz $BOOT_DIR_PREFIX/tboot.gz logging=serial,vga,memory
    echo        'Loading Xen 4.2-amd64 ...'
    module      $BOOT_DIR_PREFIX/$XEN_NAME  $BOOT_DIR_PREFIX/$XEN_NAME placeholder iommu=force
    echo        'Loading Linux "$KERNEL_VERSION" ...'
    module      $BOOT_DIR_PREFIX/$KERNEL_NAME $BOOT_DIR_PREFIX/$KERNEL_NAME root=$boot_device ro intel_iommu=on biosdevname=0 host_lvm_device=$host_lvm_device storage_lvm_device=$storage_lvm_device swap_lvm_device=$swap_lvm_device sr_lvm_device=$sr_lvm_device boot_partition=$boot_device conf_partition=$conf_device rootfs_path=$CONF_DIR_PREFIX/$ROOTFS_TAR manifest_path=$CONF_DIR_PREFIX/$MANIFEST_FILE lvm_enc_key=$CONF_DIR_PREFIX/$lvm_enc_key tpm_major_version=$tpm_major_version
    echo        'Loading initial ramdisk ...'
    module      $BOOT_DIR_PREFIX/$INITRD_NAME $BOOT_DIR_PREFIX/$INITRD_NAME
    echo        'Loading sinit $SINIT_BIN ...'
    module      $BOOT_DIR_PREFIX/$SINIT_BIN $BOOT_DIR_PREFIX/$SINIT_BIN
}
EOF

fi
cp -f $GRUB_CFG $GRUB_CFG.bak
echo "$grub_entry" >> $GRUB_CFG

echo "Your system is now ready to get booted, please select \"$grub_entry_current\" in grub menu"

