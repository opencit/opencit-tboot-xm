#!/bin/bash +x

MKINITRAMFS=`which mkinitramfs`
GUNZIP=`which gunzip`
INITRAMFS_DIR=/usr/share/initramfs-tools/
INITRAMFS_SCRIPTS_DIR=$INITRAMFS_DIR/scripts/
INITRAMFS_HOOKS_DIR=$INITRAMFS_DIR/hooks/
KERNEL_VERSION=`uname -r`
INITRD_NAME=initrd.img-$KERNEL_VERSION-measurement
OUTPUT_DIR=initrd_output
OUTPUT_LOG="/tmp/tcb-initrd-generation.log"
LIBXML_SO_PATH="/usr/lib/x86_64-linux-gnu/libxml2.so.2"
WORKING_DIR=`pwd`

backup_config() {
    cp -f $INITRAMFS_SCRIPTS_DIR/local /tmp/local.bak
    cp -f /etc/initramfs-tools/initramfs.conf /tmp/initramfs.conf.bak
    cp -f /etc/initramfs-tools/modules /tmp/modules.bak
}

update_config() {
    echo "Updating config files"
    sed -e "s/KERNELVERSION/$KERNEL_VERSION/g" scripts/local > $INITRAMFS_SCRIPTS_DIR/local
    sed -e "s/KERNELVERSION/$KERNEL_VERSION/g" scripts/tcbcrypt > $INITRAMFS_SCRIPTS_DIR/local-top/tcbcrypt
    sed -i 's/MODULES=.*/MODULES=most/g' /etc/initramfs-tools/initramfs.conf
}

build_binaries() {
    echo "Building rpcore components"
    cd $RPROOT/src/rptpm/rpmmio/
    make
    cd $RPROOT/src/rptest/tpmtest/
    mkdir -p ../../../build/debug/rptrustobjects/
    make -f tpmextend-g.mak
    cd $RPROOT/src/imvm/
    make -f verifier-g.mak
    cd $WORKING_DIR
}

change_permissions() {
    echo "Changing file permissions"
    chmod 755 $INITRAMFS_SCRIPTS_DIR/local
    chmod 755 $INITRAMFS_SCRIPTS_DIR/local-top/tcbcrypt
    chmod 755 $INITRAMFS_HOOKS_DIR/tcb
}

restore_config() {
    cp -f /tmp/local.bak $INITRAMFS_SCRIPTS_DIR/local
    cp -f /tmp/initramfs.conf.bak /etc/initramfs-tools/initramfs.conf 
    cp -f /tmp/modules.bak /etc/initramfs-tools/modules
    rm -f $INITRAMFS_HOOKS_DIR/tcb
    rm -f $INITRAMFS_SCRIPTS_DIR/local-top/tcbcrypt
}

prerequisites() {

    if [ -z "$RPROOT" ]; then
        echo "Please set RPROOT environment variable to RPcore root folder"
        exit 1
    fi 

    if [ -z "$MT_PUBKEY" ]; then
        echo "Please set MT_PUBKEY environment variable to Mt Wilson public key path (e.g. /root/pubkey.pem)"
        exit 1
    fi 

    if [ ! -d "$RPROOT" ]; then
        echo "The directory $RPROOT doesn't exist on the system"
        exit 1
    fi 

    if [ -z "$MKINITRAMFS" ]; then
        echo "Please install initramfs-tools first using apt-get"
        exit 1
    fi

    if [ -z "$GUNZIP" ]; then
        echo "Please install gunzip first"
        exit 1
    fi

    if [ ! -f "$LIBXML_SO_PATH" ]; then
        echo "$LIBXML_SO_PATH not found. Please install libxml2 first"
        exit 1
    fi
}

xen_restore_local_script(){
     mv scripts/local.old scripts/local
     mv scripts/tcbcrypt.old scripts/tcbcrypt
}

mkdir -p $OUTPUT_DIR
prerequisites

echo "Generating initrd for KVM/XEN ?"
read input

if [ $input != "XEN" ] && [ $input != "KVM" ] ; then
    echo "Please Enter valid choince KVM/XEN"
    exit 1
fi
if [ $input == "XEN" ]; then
    cp scripts/local scripts/local.old
    cp scripts/tcbcrypt scripts/tcbcrypt.old
    sed -i '/##XEN_SPECIFIC_CODE/r scripts/xen-specific-code-local' scripts/local        
    sed -i '/##XEN_SPECIFIC_CODE/r scripts/xen-specific-code-tcbcrypt' scripts/tcbcrypt
    trap xen_restore_local_script SIGHUP SIGINT SIGTERM
    PREGENERATED_FILES=xen_pre_generated_files
else
    PREGENERATED_FILES=kvm_pre_generated_files
fi

backup_config
update_config
build_binaries

cp -f initrd_hooks/tcb $INITRAMFS_HOOKS_DIR

change_permissions

echo "Generating new initrd, this might take few seconds ..."

#Remove any initrd.img files that exist in the kvm_pre_generated_files folder
rm $WORKING_DIR/$PREGENERATED_FILES/initrd.img-* | awk 'BEGIN{FS="-"} {print $2"-"$3}'
#$MKINITRAMFS -o $OUTPUT_DIR/$INITRD_NAME $KERNEL_VERSION &> $OUTPUT_LOG
$MKINITRAMFS -o $WORKING_DIR/$PREGENERATED_FILES/$INITRD_NAME $KERNEL_VERSION &> $OUTPUT_LOG


#Remove any vmlinuz file that may exist in kvm_pre_generated_files folder
rm $WORKING_DIR/$PREGENERATED_FILES/vmlinuz-* | awk 'BEGIN{FS="-"} {print $2"-"$3}'

#Copy the vmlinuz of the current machine to kvm_pre_generated_files folder
fname="/boot/vmlinuz-`uname -r`"
cp $fname $WORKING_DIR/$PREGENERATED_FILES

if [ $? -ne 0 ];then
    echo "initrd generation failed. Please check logs at $OUTPUT_LOG"
    restore_config
    exit 1
fi

if [ $input == "XEN" ]; then
    xen_restore_local_script
fi

echo "Generated initrd at $WORKING_DIR/$PREGENERATED_FILES/$INITRD_NAME"

restore_config


