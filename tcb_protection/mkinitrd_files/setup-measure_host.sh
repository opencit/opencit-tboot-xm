#!/bin/bash
#%stage: filesystem
#%depends: resume

 mkdir -p lib/modules/`uname -r`/kernel/drivers/char/tpm
 cp /bin/rpmmio.ko lib/modules/`uname -r`/kernel/drivers/char/tpm/. 

 #Adding additional handling for openssl library
 mkdir -p lib64
 opensslLib=`ldd /bin/verifier |  grep -i ssl | awk 'BEGIN{FS="=>"}{print $2}' | awk 'BEGIN{FS="("}{print $1}'`
 cp $opensslLib lib64/.
