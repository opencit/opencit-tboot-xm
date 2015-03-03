#!/bin/bash

TPM_VER=`tpm_version -v | awk 'BEGIN{FS=":"}{print $2}' | cut -c2-2`

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

PARTITION_INFO="" 
for val in `df -t ext4 -t ext3 -t ext2 | grep -i -v Filesystem | awk '{ print $1 ":" $6}'`
 do 
	PARTITION_INFO=$PARTITION_INFO","$val; 
done 
PARTITION_INFO=`echo $PARTITION_INFO | cut -c2-`
PARTITION_INFO="{"$PARTITION_INFO"}"

echo "Append the following line as kernel argument in grub menuentry for TCB Protection: "
echo ""
echo "MANIFEST_PATH=\"`readlink -e $MANIFEST_PATH`\" TPM_MAJOR_VERSION=\"$TPM_VER\" PARTITION_INFO=\"$PARTITION_INFO\""
echo ""

