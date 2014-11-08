#!/bin/bash

volume_group_name=vg1
storage_lvm_name=storage_vol
host_lvm_name=host_vol
swap_lvm_name=swap_vol
sr_lvm_name=sr_vol
encrypted_dev_name=enc_storage_dev
encrypted_swapdev_name=enc_swap_dev
encrypted_srdev_name=enc_sr_dev

function valid_device() {
    local storage_device=$1
    if [ -b $storage_device  ] ; then  
       return 0
    fi        
    return 1
}

function valid_size() {
    local storage_lvm_size=$1
    local size=$2
    if [ 0  -eq `echo "$storage_lvm_size > $size" | bc` ] ; then 
        return 0
    fi
    return 1
}

function set_keyvaluepair(){
    TARGET_KEY=$1
    REPLACEMENT_VALUE=$2
    CONFIG_FILE=$3
    sed -i "s/$TARGET_KEY=.*/$TARGET_KEY=$REPLACEMENT_VALUE/g" $CONFIG_FILE
}

echo "Creating LVM for KVM/XEN?"
read input

if [ $input != "XEN" ] && [ $input != "KVM" ] ; then
    echo "Please Enter valid choice KVM/XEN"
    exit 1
fi

while : ; do
    echo "Please enter device for encrypted LVM creation (e.g. /dev/sda4)"
    read storage_device
    if valid_device $storage_device; then 
        break
    else 
        echo "Incorrect device : Please try again" 
    fi
done


pvcreate -ff $storage_device
vgcreate $volume_group_name $storage_device

bytes=`/sbin/blockdev --getsize64 $storage_device`
size=$(echo "scale=3;${bytes%/*}/1024/1024/1024"|bc)

echo "Please enter the file path where encryption key for this LVM will be stored (e.g. /boot/tcb_lvm.key )"
read key_path

while : ; do
    echo "Please enter the size (in GB) for encrypted / filesystem (e.g. 100)"
    read host_lvm_size
    if valid_size $host_lvm_size $size; then break; else echo "Incorrect size : Please Enter Again"; fi
done

while : ; do
    echo "Please enter the size (in GB) for encrypted swap filesystem (e.g. 2)"
    read swap_lvm_size
    if valid_size $swap_lvm_size $size; then break; else echo "Incorrect size : Please Enter Again"; fi
done

if [ $input == "KVM" ]; then
    while : ; do
        echo "Please enter the size (in GB) for encrypted LVM storage (e.g. 100)"
        read storage_lvm_size
        if valid_size $storage_lvm_size $size; then break; else echo "Incorrect size : Please Enter Again"; fi
    done

fi

if [ $input == "XEN" ]; then
    while : ; do
        echo "Please enter the size (in GB) for encrypted LVM storage to store persistent network information, Hostname etc (e.g. 1) <Note: 1 GB is sufficient>"
        read storage_lvm_size
        if valid_size $storage_lvm_size $size; then break; else echo "Incorrect size : Please Enter Again"; fi
    done

    while : ; do
        echo "Please enter the size (in GB) for encrypted SR filesystem (e.g. 100)"
        read sr_lvm_size
        if valid_size $sr_lvm_size $size; then break; else echo "Incorrect size : Please Enter Again"; fi
    done
fi


gb_suffix=G
storage_size=$storage_lvm_size$gb_suffix
host_size=$host_lvm_size$gb_suffix
swap_size=$swap_lvm_size$gb_suffix

lvcreate --size $storage_size   -n $storage_lvm_name   $volume_group_name
lvcreate --size $host_size -n $host_lvm_name $volume_group_name
lvcreate --size $swap_size -n $swap_lvm_name $volume_group_name

modprobe dm-crypt
modprobe dm-mod

dd if=/dev/urandom of=$key_path bs=1k count=2
echo "Generated encryption key at $key_path. Please save this for future use" 

dev1_storage="/dev/mapper/$volume_group_name-$storage_lvm_name"
dev2_storage="/dev/mapper/$encrypted_dev_name"

echo YES | cryptsetup -c aes-xts-plain64 luksFormat --key-file=$key_path $dev1_storage
cryptsetup -c aes-xts-plain64 luksOpen --key-file=$key_path $dev1_storage $encrypted_dev_name
echo "Formatting drive"
mkfs.ext4 $dev2_storage

dev1_swap="/dev/mapper/$volume_group_name-$swap_lvm_name"
dev2_swap="/dev/mapper/$encrypted_swapdev_name"

echo YES | cryptsetup -c aes-xts-plain64 luksFormat --key-file=$key_path $dev1_swap
cryptsetup -c aes-xts-plain64 luksOpen --key-file=$key_path $dev1_swap $encrypted_swapdev_name
echo "Formatting drive"
mkswap $dev2_swap


sleep 5
cryptsetup -c aes-xts-plain64 luksClose $encrypted_dev_name
cryptsetup -c aes-xts-plain64 luksClose $encrypted_swapdev_name
cryptsetup -c aes-xts-plain64 luksClose $encrypted_srdev_name

if [ $input == "XEN" ]; then
    sr_size=$sr_lvm_size$gb_suffix
    lvcreate --size $sr_size -n $sr_lvm_name $volume_group_name
    echo "Created logical volume for SR: $sr_lvm_name"

    dev1_sr="/dev/mapper/$volume_group_name-$sr_lvm_name"
    dev2_sr="/dev/mapper/$encrypted_srdev_name"

    echo YES | cryptsetup -c aes-xts-plain64 luksFormat --key-file=$key_path $dev1_sr
    cryptsetup -c aes-xts-plain64 luksOpen --key-file=$key_path $dev1_sr $encrypted_srdev_name
    echo "Formatting drive"
    mkfs.ext4 $dev2_sr
    sleep 5
    cryptsetup -c aes-xts-plain64 luksClose $encrypted_srdev_name
fi

echo "Setting up LVM for host and encrypted storage is complete"
echo "Key Path : $key_path"
echo "Created logical volume for guest storage: /dev/mapper/$volume_group_name-$storage_lvm_name     size:$storage_lvm_size G"
echo "Created logical volume for / filesystem: /dev/mapper/$volume_group_name-$host_lvm_name         size:$host_lvm_size G"
echo "Created logical volume for swap: /dev/mapper/$volume_group_name-$swap_lvm_name                 size:$swap_lvm_size G"
if [ $input == "XEN" ]; then
    echo "Created logical volume for SR: /dev/mapper/$volume_group_name-$sr_lvm_name                 size:$sr_lvm_size G"
fi



