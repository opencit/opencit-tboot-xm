CUR_DIR=$(pwd)
LOG_FILE=$CUR_DIR/outfile
arg1=$1

function install_pkg()
{
    echo 'installing required packages ...'
	apt-get update
	apt-get --force-yes -y install make gcc g++ libxml2-dev libssl-dev linux-kernel-headers
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
	echo '--installpkg'	
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

#Make the rpmmio
function make_rpmmio()
{
	cd $CUR_DIR/rpmmio/src
	echo "Clean rpmmio "
	make clean >> $LOG_FILE 2>&1
	if [ `echo $?` -ne 0 ]
	then
        	echo "ERROR: Could not clean rpmmio"
	        exit 1
	fi

	echo "Building rpmmio.ko"
	make >> $LOG_FILE 2>&1
	if [ `echo $?` -ne 0 ]
	then
	        echo "ERROR: Could not make rpmmio"
        	exit
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
	        exit
	fi
	echo "Building tpmextend"
	make -f tpmextend-g.mak >> $LOG_FILE 2>&1
	if [ `echo $?` -ne 0 ]
	then
	        echo "ERROR: Could not make tpmextend"
	        exit
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
	make_rpmmio
	make_tpmextend
	cp_binaries
}
if [ $# -gt 1 ]
then
	echo "extra arguments"
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