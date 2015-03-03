#!/bin/bash +x

MKINITRAMFS=`which mkinitramfs`
INITRAMFS_DIR=/usr/share/initramfs-tools/
INITRAMFS_SCRIPTS_DIR=$INITRAMFS_DIR/scripts/
INITRAMFS_HOOKS_DIR=$INITRAMFS_DIR/hooks/
KERNEL_VERSION=`uname -r`
INITRD_NAME=initrd.img-$KERNEL_VERSION-measurement
OUTPUT_LOG="/tmp/tcb-initrd-generation.log"
LIBXML_SO_PATH="/usr/lib/x86_64-linux-gnu/libxml2.so.2"
WORKING_DIR=`pwd`

export WORKING_DIR

backup_config() {
    cp -f /etc/initramfs-tools/initramfs.conf /tmp/initramfs.conf.bak
    cp -f /etc/initramfs-tools/modules /tmp/modules.bak
}

update_config() {
    echo "***Updating config files***"
    sed -i 's/MODULES=.*/MODULES=most/g' /etc/initramfs-tools/initramfs.conf
}


change_permissions() {
	echo "***Changing file permissions***"
    	chmod 755 $INITRAMFS_HOOKS_DIR/tcb
    	chmod 755 $INITRAMFS_SCRIPTS_DIR/local-premount/measure_host
	chmod 755 $WORKING_DIR/bin/verifier
	chmod 755 $WORKING_DIR/bin/tpmextend
	chmod 755 $WORKING_DIR/bin/rpmmio.ko
}

restore_config() {
    cp -f /tmp/initramfs.conf.bak /etc/initramfs-tools/initramfs.conf 
    cp -f /tmp/modules.bak /etc/initramfs-tools/modules

    rm -f $INITRAMFS_SCRIPTS_DIR/local-premount/measure_host
    rm -f $INITRAMFS_HOOKS_DIR/tcb

}

prerequisites() {
    if [ -z "$MKINITRAMFS" ]; then
        echo "Please install initramfs-tools first using apt-get"
        exit 1
    fi

    if [ ! -f "$LIBXML_SO_PATH" ]; then
        echo "$LIBXML_SO_PATH not found. Please install libxml2 first"
        exit 1
    fi
}


prerequisites

echo "---------------> Generating initrd for KVM <--------------------------"




#Create Output Directory if it does not exist
PREGENERATED_FILES=generated_files
mkdir -p $WORKING_DIR/$PREGENERATED_FILES


#Using the files while reverting the system back to its original state
backup_config

#Bringing out our desired changes to the existing files
update_config

#Copy the binaries - Check for their existence at the same time
#Check for TPMExtend
if [ ! -e "$WORKING_DIR/bin/tpmextend" ]; then
	echo "TPMExtend File Not Found"
	restore_config
	exit 1
fi


#Check for RPMMIO Driver
if [ ! -e "$WORKING_DIR/bin/rpmmio.ko" ]; then
        echo "RPMMIO.ko File Not Found"
        restore_config
        exit 1
fi



#Check for Verifier
if [ ! -e "$WORKING_DIR/bin/verifier" ]; then
        echo "Verifier File Not Found"
        restore_config
        exit 1
fi


#Check for Measure_Host script
if [ -e "$WORKING_DIR/local-premount/measure_host" ]; then
	cp -f $WORKING_DIR/local-premount/measure_host $INITRAMFS_SCRIPTS_DIR/local-premount/
else
        echo "Measure_Host File Not Found"
        restore_config
        exit 1
fi

#Check for TCB Script	 
if [ -e "$WORKING_DIR/initrd_hooks/tcb" ]; then
	cp -f $WORKING_DIR/initrd_hooks/tcb $INITRAMFS_HOOKS_DIR
else
        echo "TCB file does not exist in initrd_hooks directory"
        restore_config
        exit 1
fi

change_permissions

echo "Generating New Initrd, this might take few seconds ..."

# Remove any initrd.img files that exist in the kvm_pre_generated_files folder
rm -r $WORKING_DIR/$PREGENERATED_FILES/initrd.img-* | awk 'BEGIN{FS="-"} {print $2"-"$3}'

#Run the GENERATE_INITRD Command
$MKINITRAMFS -o $WORKING_DIR/$PREGENERATED_FILES/$INITRD_NAME $KERNEL_VERSION &> $OUTPUT_LOG
if [ $? -ne 0 ];then
    echo "INITRD Generation failed. Please check logs at $OUTPUT_LOG"
    restore_config
    exit 1
fi

echo "********> Generated initrd at $WORKING_DIR/$PREGENERATED_FILES/$INITRD_NAME <**********"
restore_config
