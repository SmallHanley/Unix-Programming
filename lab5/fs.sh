bunzip2 dist/rootfs.cpio.bz2
rm -rf tmp
mkdir tmp
cp dist/rootfs.cpio tmp/rootfs.cpio
cd tmp
cpio -i -H newc < rootfs.cpio
cp -t . ../rootfs/modules/*
rm rootfs.cpio
find . | cpio -o -H newc > rootfs.cpio
cd ..
cp tmp/rootfs.cpio dist/rootfs.cpio
bzip2 dist/rootfs.cpio
