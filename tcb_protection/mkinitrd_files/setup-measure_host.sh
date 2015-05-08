#!/bin/bash
#%stage: filesystem
#%depends: resume

 mkdir -p lib/modules/`uname -r`/kernel/drivers/char/tpm
 cp /bin/rpmmio.ko lib/modules/`uname -r`/kernel/drivers/char/tpm/. 
 cp /usr/bin/expr bin/.
 cp /usr/bin/wc bin/.
 #cp /usr/bin/openssl bin/.
 cp /usr/bin/cut bin/.
 cp /usr/bin/find bin/.
 cp /sbin/lvm bin/.
 #mkdir -p etc/ssl
 #cp /etc/ssl/openssl.cnf etc/ssl/openssl.cnf
 #cp /usr/local/ssl/openssl.cnf usr/local/ssl/openssl.cnf
 #Adding additional handling for openssl library
 mkdir -p lib64
 opensslLib=`ldd /bin/verifier |  grep -i ssl | awk 'BEGIN{FS="=>"}{print $2}' | awk 'BEGIN{FS="("}{print $1}'`
 cp $opensslLib lib64/.
 mkdir -p usr/bin
