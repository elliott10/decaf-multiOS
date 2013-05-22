#!/bin/bash
#please input image directory as argument, when you run
# set your img path
IMAGEPATH=$1

if [ -n "$IMAGEPATH" ] ; then
	echo "mount guest_os filesystem out"
	SER_HOME=$(eval echo ~${SUDO_USER})
	MNTPATH=/mnt/image
	echo "image path is "$IMAGEPATH
	echo "mount path is "$MNTPATH
	mkdir -p $MNTPATH

	sudo modprobe nbd max_part=16
	sudo qemu-nbd -c /dev/nbd1 $IMAGEPATH
	sudo partprobe /dev/nbd1
	sudo mount /dev/nbd1p1 $MNTPATH

	python ParseDll.py
else
	echo "NO image path specified"
	exit
fi

#umount
echo "umount image" $IMAGEPATH
sudo umount $MNTPATH
sudo qemu-nbd -d /dev/nbd1p1
sudo qemu-nbd -d /dev/nbd1
