CUR_DIR=$(pwd)
LOG_FILE=$CUR_DIR/outfile

#Make the imvm
cd $CUR_DIR/imvm/src
echo "Clean verifier"
make clean -f verifier-g.mak > $LOG_FILE 2>&1
if [ `echo $?` -ne 0 ]
then
	echo "ERROR: Could not clean verifier"
	exit 1
fi 

echo "Build verifier"
make -f verifier-g.mak >> $LOG_FILE 2>&1
if [ `echo $?` -ne 0 ]
then
        echo "ERROR: Could not build verifier"
	exit 1
fi
#Make the rpmmio
cd $CUR_DIR/rpmmio/src
echo "Clean rpmmio"
make clean >> $LOG_FILE 2>&1
if [ `echo $?` -ne 0 ]
then
        echo "ERROR: Could not clean rpmmio"
        exit 1
fi

echo "Build rpmmio.ko"
make >> $LOG_FILE 2>&1
if [ `echo $?` -ne 0 ]
then
        echo "ERROR: Could not make rpmmio"
        exit
fi
#Make tcb_protection
cd $CUR_DIR/tpmextend/src
echo "Clean tpmextend"
make clean -f tpmextend-g.mak >> $LOG_FILE 2>&1
if [ `echo $?` -ne 0 ]
then
        echo "ERROR: Could not clean tpmextend"
        exit
fi
echo "Build tpmextend"
make -f tpmextend-g.mak >> $LOG_FILE 2>&1
if [ `echo $?` -ne 0 ]
then
        echo "ERROR: Could not make tpmextend"
        exit
fi

# copy all the binaries and moduled to tcb_protection/bin
mkdir -p $CUR_DIR/tcb_protection/bin
echo "Copying binaries to $CUR_DIR/tcb_protection/bin directory"
cp $CUR_DIR/imvm/bin/verifier $CUR_DIR/tcb_protection/bin
cp $CUR_DIR/rpmmio/src/rpmmio.ko $CUR_DIR/tcb_protection/bin
cp $CUR_DIR/tpmextend/bin/debug/tpmextend $CUR_DIR/tcb_protection/bin
echo "Build completed"
