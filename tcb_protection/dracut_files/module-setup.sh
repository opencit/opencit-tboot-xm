#!/bin/bash

#called by dracut
check()
{
	return 0
}

install()
{
	#copying all binaries to /bin
	inst /bin/base64 "/bin/base64"
	inst /sbin/lsof "/bin/lsof"
	inst /sbin/fuser "/bin/fuser"
	inst /bin/cut "/bin/cut"
	#inst "$moddir"/mtw_pubkey.pem /etc/mtw_pubkey.pem
	inst /bin/awk "/bin/awk"
	inst /bin/date "/bin/date"
	inst /bin/chmod "/bin/chmod"
	inst /bin/bash "/bin/bash"
	inst /bin/grep "/bin/grep"
	inst /bin/vi "/bin/vi"
	inst /usr/bin/wc "/bin/wc"
	inst /usr/bin/expr "/bin/expr"
	#inst /usr/bin/openssl "/bin/openssl"
	inst /bin/find "/bin/find"
	#inst /etc/pki/tls/openssl.cnf "/etc/pki/tls/openssl.cnf"
	inst /usr/bin/sha1sum "/bin/sha1sum"
	inst /usr/bin/sha256sum "/bin/sha256sum"
	if [ -e /usr/sbin/insmod ]
	then	
		inst /usr/sbin/insmod "/bin/insmod"
	else
		inst /sbin/insmod "/bin/insmod"
	fi
	inst "$moddir"/bin/verifier "/bin/verifier"
	inst "$moddir"/lib/rpmmio.ko "/lib/modules/`uname -r`/kernel/drivers/char/tpm/rpmmio.ko"
	inst "$moddir"/bin/tpmextend "/bin/tpmextend"

	#installing the hook
	inst_hook pre-mount 70 "$moddir"/measure_host.sh
}
