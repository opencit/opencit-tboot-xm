CUR_DIR="$(dirname "$(readlink -f ${BASH_SOURCE[0]})")"
echo $CUR_DIR
LOG_FILE=$CUR_DIR/outfile
arg1=$1

##################################################################################
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
        if [ $? -eq 0 ]; then
                flavour="fedora"
        fi
        grep -c -i SuSE /etc/*-release > /dev/null
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
	echo "installing required packages $os_flavour ..."
	if [ $os_flavour == "ubuntu" ]
	then
		sudo -n apt-get update
		sudo -n apt-get install --force-yes -y make gcc g++ libxml2-dev libssl-dev "linux-headers-`uname -r`" dos2unix
	elif [ $os_flavour == "rhel" ] || [ $os_flavour == "fedora" ] || [ $os_flavour == "centos" ]
	then
		yum -y install make libgcc gcc-c++ libxml2-devel openssl-devel "kernel-devel-uname-r == $(uname -r)" dos2unix
	elif [ $os_flavour == "suse" ]
	then
		zypper -n in make gcc gcc-c++ libxml2-devel libopenssl-devel kernel-desktop-devel dos2unix
	fi
}
function help_instruction()
{
	echo 'Usage ./build_components.sh [Options] '
	echo ""
	echo "1. Builds the imvm"
	echo "2. Builds the rpmmio"
	echo "3. Builds the tpmextend"
	echo "4. Copies all the binaries and rpmmio.ko to tcb_protection/bin"
	echo ""
	echo "Options available : "
	echo '--help'
	echo '--installpkg-only'	
}
#Make the imvm
function make_imvm()
{
	cd $CUR_DIR/imvm/src
	echo "Clean verifier"
	make clean -f verifier-g.mak > $LOG_FILE 2>&1
	if [ `echo $?` -ne 0 ]
	then
		echo "ERROR: Could not clean verifier"
		exit 1
	fi 

	echo "Building verifier"
	make -f verifier-g.mak >> $LOG_FILE 2>&1
	if [ `echo $?` -ne 0 ]
	then
        	echo "ERROR: Could not build verifier"
		exit 1
	fi
}

#Make tcb_protection
function make_tpmextend()
{
	cd $CUR_DIR/tpmextend/src
	echo "Clean tpmextend"
	make clean -f tpmextend-g.mak >> $LOG_FILE 2>&1
	if [ `echo $?` -ne 0 ]
	then
	        echo "ERROR: Could not clean tpmextend"
	        exit 1
	fi
	echo "Building tpmextend"
	make -f tpmextend-g.mak >> $LOG_FILE 2>&1
	if [ `echo $?` -ne 0 ]
	then
	        echo "ERROR: Could not make tpmextend"
	        exit 1
	fi
}

# copy all the binaries and moduled to tcb_protection/bin
function cp_binaries()
{
	mkdir -p $CUR_DIR/tcb_protection/bin
	echo "Copying binaries to $CUR_DIR/tcb_protection/bin directory ..."
	cp $CUR_DIR/imvm/bin/verifier $CUR_DIR/tcb_protection/bin
	cp $CUR_DIR/rpmmio/src/rpmmio.ko $CUR_DIR/tcb_protection/bin
	cp $CUR_DIR/tpmextend/bin/debug/tpmextend $CUR_DIR/tcb_protection/bin
	echo "Build completed"
}

function main()
{
	make_imvm
	make_tpmextend
	#cp_binaries
}
if [ $# -gt 1 ]
then
	echo "extra arguments"
	help_instruction
        exit 1
elif [ $# -eq 1 ] && [ $1 == "--help" ]
then
        help_instruction
elif [ $# -eq 1 ] && [ $1 == "--installpkg-only" ]
then
        install_pkg
elif [ $# -eq 0 ]
then
	main
else
        help_instruction
        exit 1
fi
