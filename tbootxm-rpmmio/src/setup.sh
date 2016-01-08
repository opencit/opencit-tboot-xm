#!/bin/sh

echo "insmod"
insmod ./rpmmio.ko
major=$(awk '$2 == "rpmmio" {print $1}' /proc/devices)
echo "mknod /dev/rpmmio0 c $major 0"
mknod /dev/rpmmio0 c $major 0
chmod 777 /dev/rpmmio0
