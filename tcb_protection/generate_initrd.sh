#!/bin/bash +x
LOG_FILE="outfile"

TBOOTXM_HOME="/opt/tbootxm"
TBOOTXM_BIN="/opt/tbootxm/bin"
TBOOTXM_LIB="/opt/tbootxm/lib"
TBOOTXM_REPOSITORY="/var/tbootxm"
INITRD_HOOKS_DIR="$TBOOTXM_HOME/initrd_hooks"
DRACUT_DIR="$TBOOTXM_HOME/dracut_files"
WORKING_DIR="$TBOOTXM_HOME"  #"$(dirname "$(readlink -f ${BASH_SOURCE[0]})")"
export WORKING_DIR
export TBOOTXM_BIN
export TBOOTXM_LIB
#create Output Directory if it does not exist
PREGENERATED_FILES="$TBOOTXM_REPOSITORY"  #generated_files
if [ -e $PREGENERATED_FILES ]
then
	rm -rf $PREGENERATED_FILES
fi
mkdir -p $PREGENERATED_FILES
DRACUT_MODULE_DIR=89tcbprotection
#TCB_SCRIPTS=$WORKING_DIR/tcb_protection_scripts
KERNEL_VERSION=`uname -r`
INITRD_NAME=initrd.img-$KERNEL_VERSION-measurement

function set_os()
{
	local file=$1
	local os=$2
	sed -i "s/CUR_OS/$os/" $file
}

############################################################################
#generate initrd image for ubuntu

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
	dos2unix $INITRAMFS_HOOKS_DIR/tcb

    	chmod 755 $INITRAMFS_SCRIPTS_DIR/local-premount/measure_host
    	dos2unix $INITRAMFS_SCRIPTS_DIR/local-premount/measure_host
	
	chmod 755 $TBOOTXM_BIN/verifier
	chmod 700 $TBOOTXM_BIN/tpmextend
	chmod 755 $TBOOTXM_LIB/rpmmio.ko
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

function check_prerequisites()
{
	#Copy the binaries - Check for their existence at the same time
        #Check for TPMExtend
        if [ ! -e "$TBOOTXM_BIN/tpmextend" ]; then
                echo "TPMExtend File Not Found"
		if [ $os_flavour == "ubuntu" ]
		then
                	restore_config
		fi
                exit 1
        fi


        #Check for RPMMIO Driver
        if [ ! -e "$TBOOTXM_LIB/rpmmio.ko" ]; then
                echo "RPMMIO.ko File Not Found"
               	if [ $os_flavour == "ubuntu" ]
                then
                        restore_config
                fi 
                exit 1
        fi



        #Check for Verifier
        if [ ! -e "$TBOOTXM_BIN/verifier" ]; then
                echo "Verifier File Not Found"
                if [ $os_flavour == "ubuntu" ]
                then
                        restore_config
                fi
		exit 1
        fi

	#Check for Measure_Host script
        if [ ! -e "$TBOOTXM_BIN/measure_host" ]; then
                echo "Measure_Host File Not Found"
		if  [ $os_flavour == "ubuntu" ]
                then
                        restore_config
                fi	
                exit 1
        fi

}

function generate_initrd_ubuntu()
{
	MKINITRAMFS=`which mkinitramfs`
	INITRAMFS_DIR=/usr/share/initramfs-tools/
	INITRAMFS_SCRIPTS_DIR=$INITRAMFS_DIR/scripts/
	INITRAMFS_HOOKS_DIR=$INITRAMFS_DIR/hooks/
	OUTPUT_LOG="/tmp/tcb-initrd-generation.log"
	LIBXML_SO_PATH="/usr/lib/x86_64-linux-gnu/libxml2.so.2"

	prerequisites

	echo "Creating initrd image for Ubuntu ... "


	#Using the files while reverting the system back to its original state
	backup_config

	#Bringing out our desired changes to the existing files
	update_config
	
	check_prerequisites
	
	#copy the measure_host script to INITRAMFS DIR
        cp -f $TBOOTXM_BIN/measure_host $INITRAMFS_SCRIPTS_DIR/local-premount/
	#inject the os in measure_host script
	set_os $INITRAMFS_SCRIPTS_DIR/local-premount/measure_host `which_flavour`
	#Check for TCB Script	 
	if [ -e "$INITRD_HOOKS_DIR/tcb" ]; then
		cp -f $INITRD_HOOKS_DIR/tcb $INITRAMFS_HOOKS_DIR
	else
        	echo "TCB file does not exist in initrd_hooks directory"
	        restore_config
        	exit 1
	fi

	change_permissions

	echo "this might take some time ..."

	#Run the GENERATE_INITRD Command
	$MKINITRAMFS -o $PREGENERATED_FILES/$INITRD_NAME $KERNEL_VERSION &> $OUTPUT_LOG
	if [ $? -ne 0 ];then
	    echo "INITRD Generation failed. Please check logs at $OUTPUT_LOG"
	    restore_config
	    exit 1
	fi

	echo "********> Generated initrd at $PREGENERATED_FILES/$INITRD_NAME <**********"
	restore_config

}

##################################################################################
# check the flavour of OS
function which_flavour()
{
	flavour=""
        grep -c -i ubuntu /etc/*-release > /dev/null
        if [ $? -eq 0 ] ; then
                flavour="ubuntu"
        fi
        grep -c -i "red hat" /etc/*-release > /dev/null
        if [ $? -eq 0 ] ; then
                flavour="rhel"
        fi
        grep -c -i fedora /etc/*-release > /dev/null
        if [ $? -eq 0 ] ; then
                flavour="fedora"
        fi
	grep -c -i "SuSE" /etc/*-release > /dev/null
	if [ $? -eq 0 ]
	then
		flavour="suse"
	fi
        if [ "$flavour" == "" ] ; then
                echo "Unsupported linux flavor, Supported versions are ubuntu, rhel, fedora and suse"
                exit
        else
                echo $flavour
        fi
}


###################################################################################
#function to generate intird image for redhat
function generate_initrd_redhat()
{
	echo "Creating initramfs image for Redhat..."
	echo "this might take some time..."
	redhat_mod_dir=/usr/share/dracut/modules.d/
	check_prerequisites
	mkdir -p $redhat_mod_dir/$DRACUT_MODULE_DIR
	#cp $DRACUT_DIR/* $redhat_mod_dir/$DRACUT_MODULE_DIR
	if [ -e $DRACUT_DIR/module-setup.sh ]
        then
                cp $DRACUT_DIR/module-setup.sh $redhat_mod_dir/$DRACUT_MODULE_DIR
        else
                echo "module-setup.sh is missing"
                echo "fatal error can't proceed further"
                echo "exiting..."
                #remove the inserted module
                rm -rf $redhat_mod_dir/$DRACUT_MODULE_DIR
                exit
        fi
	
	if [ -e $DRACUT_DIR/check ]
	then
		cp $DRACUT_DIR/check $redhat_mod_dir/$DRACUT_MODULE_DIR
	else
		echo "check is missing"
                echo "fatal error can't proceed further"
                echo "exiting..."
                #remove the inserted module
                rm -rf $redhat_mod_dir/$DRACUT_MODULE_DIR
                exit
	fi
	
	if [ -e $DRACUT_DIR/install ]
	then
		cp $DRACUT_DIR/install $redhat_mod_dir/$DRACUT_MODULE_DIR
	else
		echo "install is missing"
                echo "fatal error can't proceed further"
                echo "exiting..."
                #remove the inserted module
                rm -rf $redhat_mod_dir/$DRACUT_MODULE_DIR
                exit
	fi
	
	#copy the measure_host script to dracut module
	cp $TBOOTXM_BIN/measure_host $redhat_mod_dir/$DRACUT_MODULE_DIR/measure_host.sh
	#inject the os in measure_host script
	set_os $redhat_mod_dir/$DRACUT_MODULE_DIR/measure_host.sh `which_flavour`
	#copy the binaries to dracut module
	cp -r $TBOOTXM_BIN $redhat_mod_dir/$DRACUT_MODULE_DIR
	#change the premission of files in dracut module
	chmod 777 $redhat_mod_dir/$DRACUT_MODULE_DIR/check
	dos2unix $redhat_mod_dir/$DRACUT_MODULE_DIR/check
	chmod 777 $redhat_mod_dir/$DRACUT_MODULE_DIR/install
	dos2unix $redhat_mod_dir/$DRACUT_MODULE_DIR/install
	chmod 777 $redhat_mod_dir/$DRACUT_MODULE_DIR/module-setup.sh
	dos2unix $redhat_mod_dir/$DRACUT_MODULE_DIR/module-setup.sh
	chmod 777 $redhat_mod_dir/$DRACUT_MODULE_DIR/measure_host.sh
	dos2unix $redhat_mod_dir/$DRACUT_MODULE_DIR/measure_host.sh
	chmod 777 $redhat_mod_dir/$DRACUT_MODULE_DIR/bin/*

        cd $PREGENERATED_FILES
        dracut -f -v $INITRD_NAME >> $LOG_FILE 2>&1
        rm -rf $redhat_mod_dir/$DRACUT_MODULE_DIR
	echo "Finished creating initramfs image"
}


###################################################################################
#function to generate initrd image for fedora
function generate_initrd_fedora()
{
	echo "this might take some time..."
	fedora_mod_dir=/usr/lib/dracut/modules.d/
	check_prerequisites
	mkdir -p $fedora_mod_dir/$DRACUT_MODULE_DIR
	#cp $DRACUT_DIR/* $fedora_mod_dir/$DRACUT_MODULE_DIR
	if [ -e $DRACUT_DIR/module-setup.sh ]
	then    
		cp $DRACUT_DIR/module-setup.sh $fedora_mod_dir/$DRACUT_MODULE_DIR
	else
                echo "module-setup.sh is missing"
                echo "fatal error can't proceed further"
                echo "exiting..."
		#remove the inserted module
		rm -rf $fedora_mod_dir/$DRACUT_MODULE_DIR
                exit
        fi
	#copy the measure_host script to dracut module
        cp $TBOOTXM_BIN/measure_host $fedora_mod_dir/$DRACUT_MODULE_DIR/measure_host.sh
	#inject the os in measure_host script
	set_os $fedora_mod_dir/$DRACUT_MODULE_DIR/measure_host.sh `which_flavour`
        #copy the binaries to dracut module
        cp -r $TBOOTXM_BIN $fedora_mod_dir/$DRACUT_MODULE_DIR
        #change the premission of files in dracut module
	chmod 777 $fedora_mod_dir/$DRACUT_MODULE_DIR/module-setup.sh
	dos2unix $fedora_mod_dir/$DRACUT_MODULE_DIR/module-setup.sh
	chmod 777 $fedora_mod_dir/$DRACUT_MODULE_DIR/measure_host.sh
	dos2unix $fedora_mod_dir/$DRACUT_MODULE_DIR/measure_host.sh
	chmod 777 $fedora_mod_dir/$DRACUT_MODULE_DIR/bin/*

	cd $PREGENERATED_FILES
	dracut -f -v $INITRD_NAME >> $LOG_FILE 2>&1
	rm -rf $fedora_mod_dir/89tcbprotection
	echo "Finished creating the initramfs image"
}
###################################################################################

function revert_mkinitrd()
{
	rm -rf /bin/verifier /bin/tpmextend
	rm -rf /lib/mkinitrd/scripts/boot-measure_host.sh
	rm -rf /lib/mkinitrd/scripts/setup-measure_host.sh
}

function prepare_mkinitrd()
{
	cp $TBOOTXM_BIN/measure_host /lib/mkinitrd/scripts/boot-measure_host.sh
        chmod +x /lib/mkinitrd/scripts/boot-measure_host.sh
	dos2unix /lib/mkinitrd/scripts/boot-measure_host.sh
        set_os /lib/mkinitrd/scripts/boot-measure_host.sh "suse"
	cp $TBOOTXM_BIN/setup-measure_host.sh /lib/mkinitrd/scripts/setup-measure_host.sh
	chmod +x /lib/mkinitrd/scripts/setup-measure_host.sh
	dos2unix /lib/mkinitrd/scripts/setup-measure_host.sh
        # copy the binaries to location
	cp bin/verifier /bin/.
	cp bin/tpmextend /bin/.
	cp bin/rpmmio.ko /bin/.
	chmod +x /bin/verifier /bin/tpmextend /bin/rpmmio.ko
}

function generate_initrd_suse()
{
	echo "This might take some time ... "	
	MKINITRD=`which mkinitrd`
	check_prerequisites
	# update the measure host file into initrd
	prepare_mkinitrd 
	# execute the mkinitrd
	# find the exising kernel file and create initrd file name
	kernelRev=`uname -r`
	kernel=`ls /boot/ | grep -i $kernelRev | grep -e "^vmlinuz"`
	kernel=/boot/$kernel
	initrdFname=$PREGENERATED_FILES/initrd.img-$kernelRev-measurement
	echo "Using kernel $kernel and initrd $initrdFname"
	# Generate the initrd
	mkinitrd -k $kernel -i $initrdFname > /tmp/mkinitrd.log 2>&1
	if [ $? -eq 0 ]; then
		echo "Initrd created successfully"
	else
		echo "Initrd creation failed, please see mkinitrd logs for more info"
	fi
	revert_mkinitrd
}

function main_function()
{
	os_flavour=`which_flavour`
	echo "Creating initramfs image for $os_flavour..."
	if [ $os_flavour == "ubuntu" ]
	then
		generate_initrd_ubuntu
	elif [ $os_flavour == "rhel" ]
	then
		generate_initrd_redhat
	elif [ $os_flavour == "fedora" ]
	then	
		generate_initrd_fedora
        elif [ $os_flavour == "suse" ] 
        then    
                generate_initrd_suse
	else
		echo "ERROR!! : Does not support $os_flavour"
	fi
}

main_function
