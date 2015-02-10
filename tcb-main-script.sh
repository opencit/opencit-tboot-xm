#!/bin/bash

WORK_DIR=`pwd`


while true
do
echo "Please select the type of Hypervisor KVM/XEN"
	read hyp

	if [ $hyp != "XEN" ] && [ $hyp != "KVM" ];
	then
		echo "INVALID Choice"
		exit 1
	fi
	
	export HYP_NAME=$hyp

	if [ $hyp == "XEN" ]; then
	PREGENERATED_FILES=xen_pre_generated_files
	
	else
	PREGENERATED_FILES=kvm_pre_generated_files
	fi


	#Logic for checking the number of SINIT files in the respective Hypervisor_Generated Directory
	cd $WORK_DIR/$PREGENERATED_FILES
	count=`find . -iname "*SINIT*.bin" | wc -l`

	if [ $count -ne 1 ];
	then
	
		echo "ERROR: $PREGENERATED_FILES directory contains NONE or MORE THAN 1 SINIT file.Please make the necessary changes." 
		echo "Download SINIT file from https://software.intel.com/en-us/articles/intel-trusted-execution-technology & place .bin file in $PREGENERATED_FILES directory and then run this script again."
		exit 1
	
	
	else

		echo "Do you wish to proceed with Creation of New LVM's(y/n)"
 		read inp

	cd ..

	if [ "$inp" == "y" ]; 
	then
		chmod +x setup_encrypted_lvm.sh && ./setup_encrypted_lvm.sh
		chmod +x configure_trusted_host.sh && ./configure_trusted_host.sh
		echo "Installation Successful."
	exit 1

	elif [ "$inp" == "n" ]; 
	then
		chmod +x configure_trusted_host.sh && ./configure_trusted_host.sh
		echo "Installation Successful."
		exit 1
	
	else
		echo "Please type "y" or "n""
	fi


fi



done



