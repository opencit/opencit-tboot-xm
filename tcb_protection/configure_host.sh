#!/bin/bash

BASE_DIR="$(dirname "$(readlink -f ${BASH_SOURCE[0]})")"
TBOOTXM_ENV="${TBOOTXM_ENV:-/opt/tbootxm/env}"
TBOOTXM_LIB="${TBOOTXM_LIB:-/opt/tbootxm/lib}"
TBOOTXM_LAYOUT_FILE="$TBOOTXM_ENV/tbootxm-layout"
TBOOTXM_REPOSITORY="/var/tbootxm"  #"${TBOOTXM_REPOSITORY:-/var/tbootxm}"
GENERATED_FILE_LOCATION="$TBOOTXM_REPOSITORY"  #"$BASE_DIR/generated_files"
KERNEL_VERSION=`uname -r`
INITRD_NAME=initrd.img-$KERNEL_VERSION-measurement
MENUENTRY_FILE="$TBOOTXM_REPOSITORY/sample_menuentry"  #"$BASE_DIR/sample_menuentry"
MENUENTRY_PREFIX="TCB-Protection"
CREATE_MENU_ENTRY_SCRIPT="$TBOOTXM_LIB/create_menuentry.pl"  #"$BASE_DIR/create_menuentry.pl"
UPDATE_MENU_ENTRY_SCRIPT="$TBOOTXM_LIB/update_menuentry.pl"  #"$BASE_DIR/update_menuentry.pl"
#MANIFEST_PATH=${MANIFEST_PATH:-""}
MANIFEST_PATH="/boot/trust/manifest.xml"
GRUB_FILE=${GRUB_FILE:-""}
#CONFIG_FILE_NAME="$TBOOTXM_REPOSITORY/measure_host.cfg"
CONFIG_FILE_NAME="/tbootxm.conf"

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
  if [ ! -f "$MANIFEST_PATH" ] ; then
    while :;
    do
      if [ -z "$MANIFEST_PATH" ]; then
		echo "Manifest path not exported in env file"
  	        echo "Enter the manifest file path :"
	        read -e MANIFEST_PATH
      else
	 	echo "Using MANIFEST FILE : $MANIFEST_PATH"
      fi
      if [ -f "$MANIFEST_PATH" ] ; then
        echo "Found manifest file"
        break
      else
        echo "ERROR: Invalid manifest path"
        echo -e "\nPlease enter a valid path"
	unset MANIFEST_PATH
      fi
    done
  fi
  mkdir -p /boot/trust
  cp $MANIFEST_PATH /boot/trust/manifest.xml
  export MANIFEST_PATH=/boot/trust/manifest.xml
}

function get_grub_file_location()
{
  if [ ! -f "$GRUB_FILE" ]; then
    #Read the GRUB File Path
    while :;
    do
      echo "Enter the GRUB config/menu.lst file path(e.g /boot/grub/grub.cfg ) :"
      read -e GRUB_FILE
      if [ -f "$GRUB_FILE" ] ; then
        echo "Found grub config file"
        break
      else
        echo "ERROR: Invalid grub config file path"
        echo -e "\nPlease enter a valid path"
      fi
    done
  fi
	if [ -e "$GRUB_FILE" ] && [ -f "$GRUB_FILE" ] && [ -e "$TBOOTXM_LAYOUT_FILE" ]
	then
		echo "export GRUB_FILE=$GRUB_FILE" >> $TBOOTXM_LAYOUT_FILE
	else
		echo "tbootxm layout file not found"
	fi
}

function get_partition_info()
{
	# Get partition information for current OS
	PARTITION_INFO="" 
	#take all the filesystem types supported and find partition for those
	for fs_type in `cat /proc/filesystems | grep -v "nodev" | awk '{print $1}'`
	do
		for val in `df -P -t $fs_type 2> /dev/null | grep -i -v Filesystem | awk '{ print $1 ":" $6}'`
		do 
			PARTITION_INFO="${PARTITION_INFO},${val}" 
		done 
	done
	PARTITION_INFO=`echo $PARTITION_INFO | cut -c2-`
	PARTITION_INFO="{"$PARTITION_INFO"}"
	echo "Partitions available and its mount points: $PARTITION_INFO"
}

function generate_kernel_args()
{
	echo "Following kernel argument will be used in grub menuentry for TCB Protection: "
	KERNEL_ARGS="MANIFEST_PATH=\"$MANIFEST_PATH\"\nPARTITION_INFO=\"$PARTITION_INFO\""
	echo $KERNEL_ARGS
	chattr -i $CONFIG_FILE_NAME > /dev/null 2>&1
	rm -rf $CONFIG_FILE_NAME
	echo -e $KERNEL_ARGS > $CONFIG_FILE_NAME
	chattr +i $CONFIG_FILE_NAME
	echo ""
}

function which_grub() {
	
	os_version=`which_flavour`
	GRUB_VERSION=""
	
	if [ $os_version == "fedora" ] ; then
		grub2-install --version | grep " 2."
		GRUB_VERSION=2
		return
	elif [ $os_version == "suse" ] ; then
		zypper info grub | grep -i version | grep " 0."
		if [ $? -eq 0 ] ; then
	                GRUB_VERSION=0
	                return
        	fi
	elif [ $os_version == "rhel" ] && [ -n "`which grub2-install 2>/dev/null`" ] ; then
		grub2-install --version | grep " 2."
                GRUB_VERSION=2
                return		
	fi

	grub-install --version | grep " 2." 
	if [ $? -eq 0 ]
	then
		GRUB_VERSION=2
		return
	fi
	grub-install --version | grep " 0."
	if [ $? -eq 0 ]
        then
                GRUB_VERSION=0
                return
        fi
	grub-install --version | grep " 1."
	if [ $? -eq 0 ]
        then
                GRUB_VERSION=1
                return
        fi
}

function generate_grub_entry()
{
	echo "Generate grub entry for TCB-protection"
	echo > $MENUENTRY_FILE
	which_grub
	get_grub_file_location
	perl $CREATE_MENU_ENTRY_SCRIPT $MENUENTRY_FILE $(uname -r) "$INITRD_NAME" "CONFIG_FILE_PATH=\"$CONFIG_FILE_NAME\"" "$MENUENTRY_PREFIX" "$GRUB_FILE" $GRUB_VERSION 
	if [ $? -ne 0 ]; then
		echo "ERROR: Not able to get appropriate grub entry from $GRUB_FILE file for kernel version $KERNEL_VERSION ."
		echo "For Ubuntu OS make sure that tboot is available on the host and for current kernel tboot entry is populated in $GRUB_FILE file."
		exit 1
	fi
	echo "Generated grub entry in $MENUENTRY_FILE file"
}

function update_grub()
{
	if [ "$GRUB_VERSION" == "0" ]; then
		echo "Updating the $GRUB_FILE with newly generated entry"
		perl $UPDATE_MENU_ENTRY_SCRIPT $MENUENTRY_FILE $GRUB_FILE $GRUB_VERSION $MENUENTRY_PREFIX
		if [ $? -ne 0 ]
		then
			echo "Couldn't update the grub entry"
			echo "Exiting ..."
			exit
		fi
                #echo "WARNING: Not updating grub file"
                #echo "          Follow below mentioned steps to update grub manually:"
                #echo "          - Verify grub entry available in $MENUENTRY_FILE file and append it in $GRUB_FILE file manually."
                #echo ""
		exit
	fi

	echo "Check for existing menuentry in /etc/grub.d/40_custom file"

	grep -c "menuentry '$MENUENTRY_PREFIX" /etc/grub.d/40_custom > /dev/null
	if [ $? -eq 0 ]; then
		# update the existing grub entry
		echo "/etc/grub.d/40_custom already contains an entry for TCB-Protection"
		echo "updating the /etc/grub.d/40_custom with new entry"
		perl $UPDATE_MENU_ENTRY_SCRIPT $MENUENTRY_FILE /etc/grub.d/40_custom $GRUB_VERSION $MENUENTRY_PREFIX
		if [ $? -ne 0 ]
		then
			echo "Couldn't update the entry in /etc/grub.d/40_custom"
			echo "Exiting ..."
			exit
		fi
		#echo "WARNING: Aborting update grub operation as /etc/grub.d/40_custom already contains grub entry for TCB-Protection"
		#echo "		Follow below mentioned steps to update grub manually:"
		#echo "		- Update menuenry in /etc/grub.d/40_custom file manually using grub entry available in $MENUENTRY_FILE file"
		#echo "		- After updating /etc/grub.d/40_custom execute 'update-grub' or 'grub2-mkconfig -o $GRUB_FILE' command."
		#echo ""
		#exit
	else
		cat $MENUENTRY_FILE >> /etc/grub.d/40_custom
		echo "Menuentry has been appended in /etc/grub.d/40_custom"
	fi
	if [ $os_version == "fedora" ] || [ $os_version == "rhel" ]; then
		grub2-mkconfig -o $GRUB_FILE
		
	else
		update-grub
	fi

	echo "Grub entry updated... New grub option will be available in $GRUB_FILE file"
	echo "Reboot host and select appropriate grub option to boot host with TCB protection"
}

# check the flavour of OS
function which_flavour()
{
    flavour=""
    grep -c -i ubuntu /etc/*-release > /dev/null
    if [ $? -eq 0 ]; then
            flavour="ubuntu"
    fi
    grep -c -i "red hat" /etc/*-release > /dev/null
    if [ $? -eq 0 ]; then
            flavour="rhel"
    fi
    grep -c -i fedora /etc/*-release > /dev/null
    if [ $? -eq 0 ] && [ $flavour == "" ]; then
            flavour="fedora"
    fi
    grep -c -i "SuSE" /etc/*-release > /dev/null
    if [ $? -eq 0 ]; then
            flavour="suse"
    fi
    grep -c -i centos /etc/*-release > /dev/null
    if [ $? -eq 0 ]; then
            flavour="centos"
    fi
    if [ "$flavour" == "" ]; then
            echo "Unsupported linux flavor, Supported versions are ubuntu, rhel, fedora, centos and suse"
            exit 1
    else
            echo $flavour
    fi
}

function install_pkg()
{
    os_flavour=`which_flavour`
	get_grub_file_location
    echo "installing required packages $os_flavour ..."
    if [ $os_flavour == "ubuntu" ]; then
        apt-get update
        apt-get --force-yes -y install tboot
    elif [ $os_flavour == "rhel" ] || [ $os_flavour == "centos" ]; then
        yum -y install tboot
    elif [ $os_flavour == "fedora" ]; then
        yum -y install tboot
        grub2-mkconfig -o $GRUB_FILE 
    elif [ $os_flavour == "suse" ]; then
        zypper -n in tboot
        #	grub2-mkconfig -o $GRUB_FILE
    fi
}

function main()
{
    echo "Configuring Host"
    mkdir -p "/var/log/trustagent"
    validate_n_copy_initrd
    #get_manifest_file_location
    get_partition_info
    generate_kernel_args
    generate_grub_entry
    update_grub
}

if [ $# -gt 1 ]
then
        echo "ERROR: Extra arguments"
        help_instruction
elif [ $# -eq 1 ] && [ $1 == "--help" ]
then
        help_instruction
elif [ $# -eq 1 ] && [ $1 == "--installpkg" ]
then
	install_pkg
	main
elif [ $# -eq 0 ]
then
	main
else
        help_instruction
fi
