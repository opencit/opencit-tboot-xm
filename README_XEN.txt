A) Steps for Host TCB creation are same as of KVM, Please refer README.txt

The script configure_trusted_host.sh will do the following
a. copying pre-generated rootfs tarball, manifest, SINIT binary to plain boot partition
b. copy the kernel and initrd for host TCB protection to plain boot partition
c. Create a menu entry in grub to booting using the above rootfs and initrd

Before running this script, please follow the steps below

(1.1) script ./setup_encrypted_lvm.sh will create four lvm on given physical device. And it will encrypt those with dm-crypt

(1.2) script ./configure_trusted_host.sh will copy files from xen_pre_generated_files directory to /boot directory.
      And it will update /boot/grub/grub.cfg 


Manual steps To create rootfs, initrd and put them in /boot/ and update /boot/grub/grub.cfg
If you want to do it manually, then follow these steps

(2.1) Follow the steps in 1.1 from the above section

(2.2) Create rootfs tarball using a script
./create_rootfs_tarball.sh

(2.3) Generate manifest xml with this rootfs tarball using the client side tool

(2.4) Copy the rootfs tarball and manifest xml to boot directory (e.g. /boot/)

(2.5) Generated new initrd for host OS protection using a script
    (2.5.1) Export envirnoment variable
    export RPROOT="full/path/to/rpcore/in/git/repository"   (e.g. /home/intel/git-repositories/mysteryhill/rpcore)
    (2.5.2) Run the script
    ./generate_initrd

(2.6) Edit /boot/grub/grub.cfg and add a section as follows to boot using the generated initrd, and provide necessary parameters for the boot process. If your /boot parition is a seperate parition then you need to provide all relative paths (for example /tboot.gz, /rootfs.tar.gz etc.). In case your /boot parition is not a separate parition and then you need to provide all absolute paths (for example /boot/tboot.gz, /boot/rootfs.tar.gz etc.). Check the output of "df -h" command to see to confirm if /boot is a separate partition
Four major parameters to pass on as kernel parameters:
   a. boot_partition="/dev/xxx", this shall point to the disk partition that has the clear root FS stored, e.g. /dev/sda1
   b. rootfs_path="relative path to root fs on boot_partition",
   c. manifest_path="relative path to the host OS TCB manifest file on boot_partition"
   d. host_lvm_device="/dev/mapper/xxxx", this shall point to the lvm partition that was pre-created, as in step 1 above.
   e. use blkid command to find the UUID of boot partition
   Next, add the following menuentry to submenu tboot:


menuentry 'TCB-protection-3' --class ubuntu --class gnu-linux --class gnu --class os --class tboot {
    insmod part_msdos
    insmod ext2
    set         root='(hd0,msdos1)'
    search      --no-floppy --fs-uuid --set=root e26c66cf-61d6-4cbd-8d7a-4d03fa54280a
    echo        'Loading tboot ...'
    multiboot   /tboot.gz /tboot.gz logging=serial,vga,memory
    echo        'Loading Xen 4.2-amd64 ...'
    module      /xen-4.2-amd64.gz  /xen-4.2-amd64.gz placeholder iommu=force
    echo        'Loading Linux "3.11.0-24-generic" ...'
    module      /vmlinuz-3.11.0-24-generic /vmlinuz-3.11.0-24-generic root=/dev/sda1 ro intel_iommu=on host_lvm_device=/dev/mapper/vg1-host_vol storage_lvm_device=/dev/mapper/vg1-storage_vol swap_lvm_device=/dev/mapper/vg1-swap_vol sr_lvm_device=/dev/mapper/vg1-sr_vol boot_partition=/dev/sda1 rootfs_path=/rootfs.tar.gz manifest_path=/tcb-manifest.xml lvm_enc_key=/tcb_lvm.key tpm_major_version=1
    echo        'Loading initial ramdisk ...'
    module      /initrd.img-3.11.0-24-generic-measurement /initrd.img-3.11.0-24-generic-measurement
    echo        'Loading sinit 3rd_gen_i5_i7_SINIT_67.BIN ...'
    module      /3rd_gen_i5_i7_SINIT_67.BIN /3rd_gen_i5_i7_SINIT_67.BIN
}



B) Steps to perform after XEN TCB booted:
1) Setup networking by editing /etc/network/interfaces.
   /etc/init.d/networking restart
   
2) create SR
   # xe sr-create device-config:device=/dev/mapper/crypt-sr host-uuid=<> type=ext content-type=user name-label=MySR
   # xe pool-param-set uuid=<pool-uuid> default-SR=<sr-uuid created in above step>
            Get the pool-uuid from- xe pool-list
            and get sr-uuid from - xe sr-list

   
3) Setup Nova compute as VM , Import Nova Compute
   xe vm-import filename=<>

4) Follow steps given in Git: /mysteryhill/Setup-Standardization/Compute/README.txt to apply Nova compute patches and start nova services.

5) on Dom0: Update /etc/intel_rpcore_plugin.conf file with RPCORE_IPADDR, RPCORE_PORT

6) export LD_LIBRARY_PATH=/opt/RP/rpcore/lib

7) Start RPCore: cd /opt/RP/rpcore/bin/debug ; nohup ./nontpmrpcore;

8) Start xapi-access-control-proxy: cd /opt/RP/xapi-access-control-proxy ; nohup ./xapi-access-control.py

8) On Nova Compute VM: service nova-compute start ; service nova-network start; service nova-api-metadata start;

9) Now you can try launching VM from Openstack Controller.

10) If you want to shutdown or reboot the Dom0 machine then, you have to shutdown all guest VM first.
