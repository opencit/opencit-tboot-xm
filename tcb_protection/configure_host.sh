#!/bin/bash

BASE_DIR="$(dirname "$0")"
GENERATED_FILE_LOCATION="$BASE_DIR/generated_files"
KERNEL_VERSION=`uname -r`
INITRD_NAME=initrd.img-$KERNEL_VERSION-measurement
MENUENTRY_FILE="$BASE_DIR/sample_menuentry"
MENUENTRY_PREFIX="TCB-Protection"
CREATE_MENU_ENTRY_SCRIPT="$BASE_DIR/create_menuentry.pl"


function help_instruction()
{
        echo 'Usage ./configure_host.sh [Options] '
        echo ""
	echo "This script needs to run on the TXT enabled host machine on which TCB-protection needs tobe enabled."
	echo ""
	echo "This script does following functions"
        echo "1. Asks for manifest file location"
        echo "2. Gether partition information"
        echo "3. Generate kernel argument for TCB-protection enabled initrd"
        echo "4. Create a grub menuentry for TCB-Protection"
        echo "5. Add grub menuentry in /etc/grub.d/40_custom and update grub"
	echo ""
        echo "Options available : "
        echo "--help"
	exit
}

function validate_n_copy_initrd()
{
	echo "Current kernel version is $KERNEL_VERSION"
	echo "Checking for initrd available for $KERNEL_VERSION"
	# Check whether initrd exists for current kernel or not
	if [ ! -e "$GENERATED_FILE_LOCATION/$INITRD_NAME" ]; then
		echo "ERROR: $GENERATED_FILE_LOCATION/$INITRD_NAME does not exist"
		echo "Need to generate initrd for kernel version $KERNEL_VERSION"
		exit 1
	fi
	echo "Copying TCB-protection enabled initrd in /boot"
	cp -f $GENERATED_FILE_LOCATION/$INITRD_NAME /boot
}


function get_manifest_file_location()
{
	#Read the Manifest File Path
	while :;
	do
		echo "Enter the manifest file path :"
		read -e MANIFEST_PATH
		if [ -f $MANIFEST_PATH ] ; then
			echo "Found manifest file"
			break
		else
			echo "ERROR: Invalid manifest path"
			echo -e "\nPlease enter a valid path"
		fi
	done
}

function get_partition_info()
{
	# Get partition information for current OS
	PARTITION_INFO="" 
	for val in `df -t ext4 -t ext3 -t ext2 | grep -i -v Filesystem | awk '{ print $1 ":" $6}'`
	do 
		PARTITION_INFO=$PARTITION_INFO","$val; 
	done 
	PARTITION_INFO=`echo $PARTITION_INFO | cut -c2-`
	PARTITION_INFO="{"$PARTITION_INFO"}"
	echo "Partitions available and its mount points: $PARTITION_INFO"
}

function generate_kernel_args()
{
	echo "Following kernel argument will be used in grub menuentry for TCB Protection: "
	KERNEL_ARGS="MANIFEST_PATH=\"`readlink -e $MANIFEST_PATH`\" PARTITION_INFO=\"$PARTITION_INFO\""
	echo $KERNEL_ARGS
	echo ""
}

function generate_grub_entry()
{
	echo "Generate grub entry for TCB-protection"
	echo > $MENUENTRY_FILE

	perl $CREATE_MENU_ENTRY_SCRIPT $MENUENTRY_FILE $(uname -r) "$INITRD_NAME" "$KERNEL_ARGS" "$MENUENTRY_PREFIX"
	if [ $? -ne 0 ]; then
		echo "ERROR: Not able to get appropriate grub entry from /boot/grub/grub.cfg file for kernel version $KERNEL_VERSION with tboot."
		echo "Make sure that tboot is available on the host and for current kernel tboot entry is populated in /boot/grub/grub.cfg file."
		exit 1
	fi
	echo "Generated grub entry in $MENUENTRY_FILE file"
}

function update_grub()
{
	echo "Check for existing menuentry in /etc/grub.d/40_custom file"

	grep -c "menuentry '$MENUENTRY_PREFIX" /etc/grub.d/40_custom > /dev/null
	if [ $? -eq 0 ]; then
		echo "WARNING: Aborting update grub operation as /etc/grub.d/40_custom already contains grub entry for TCB-Protection"
		echo "		Follow below mentioned steps to update grub manually:"
		echo "		- Update menuenry in /etc/grub.d/40_custom file manually using grub entry available in $MENUENTRY_FILE file"
		echo "		- After updating /etc/grub.d/40_custom execute 'update-grub' command"
		echo ""
		exit
	fi
	cat $MENUENTRY_FILE >> /etc/grub.d/40_custom
	echo "Menuentry has been appended in /etc/grub.d/40_custom"
	
	update-grub
	echo "Grub entry updated... New grub option will be available in /boot/grub/grub.cfg file"
	echo "Reboot host and select appropriate grub option to boot host with TCB protection"
}

if [ $# -gt 1 ]
then
        echo "ERROR: Extra arguments"
        help_instruction
elif [ $# -eq 1 ] && [ $1 == "--help" ]
then
        help_instruction
elif [ $# -eq 0 ]
then
	echo "Configuring Host"
	validate_n_copy_initrd
	get_manifest_file_location
	get_partition_info
	generate_kernel_args
	generate_grub_entry
	update_grub
else
        help_instruction
fi
