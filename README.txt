############################################################################################
section 1
############################################################################################

The script configure_trusted_host.sh will do the following 
a. copying pre-generated rootfs tarball, manifest, SINIT binary to plain boot partition
b. copy the kernel and initrd for host TCB protection to plain boot partition
c. Create a menu entry in grub to booting using the above rootfs and initrd

Before running this script, please follow the steps below

(1.1) Prepare a lvm partition, to researve disk space for the encrypted disk partition used during the boot process. 
It's a seperate partition from the partition that holds the root FS on disk (the clear partition). You may need 
to use an USB bootable disk to repartition the disk, if your root FS partition occupies the entire disk.
Examples on how to create lvm partition: mysteryhill/docs/setup/dm-crypt block attach.doc
You also need to created an encrypted parition for storing VM images and keep the key on plain parition.
This script will do it all for you if you have disk partition already created
./setup_encrypted_lvm.sh

(1.2) Run the script
./configure_trusted_host.sh
This script needs the name of logical volumes for rootFS and VM image storage (this is encrypted to the key need to be provided
when prompted by the script)

############################################################################################
section 2
############################################################################################

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

menuentry 'Ubuntu GNU/Linux, with tboot 1.7.0 and Linux 3.11.0-19-generic' --class ubuntu --class gnu-linux --class gnu --class os --class tboot {
    insmod part_msdos
    insmod ext2
    set root='(hd0,msdos1)'
    search --no-floppy --fs-uuid --set=root 86339206-364a-4a70-a9f1-d70d73eaea01
    echo    'Loading tboot 1.7.0 ...'
    multiboot   /tboot.gz /tboot.gz logging=serial,vga,memory
    echo    'Loading Linux 3.11.0-19-generic ...'
    module  /vmlinuz-3.11.0-19-generic /vmlinuz-3.11.0-19-generic root=UUID=ac2877fc-8832-4e46-98a9-d3ccff25631f ro   intel_iommu=on host_lvm_device=/dev/mapper/VolumeGroup-mylvm boot_partition=/dev/sda1 rootfs_path=/rootfs.tar.gz manifest_path=/manifest-201406240317.xml
    echo    'Loading initial ramdisk ...'
    module  /initrd.img-3.11.0-19-generic-measurement /initrd.img-3.11.0-19-generic-measurement
    echo    'Loading sinit 3rd_gen_i5_i7_SINIT_67.BIN ...'
    module  /3rd_gen_i5_i7_SINIT_67.BIN /3rd_gen_i5_i7_SINIT_67.BIN
}




