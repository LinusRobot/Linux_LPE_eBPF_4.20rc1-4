ALL:
	gcc -g -O0 -masm=intel -static -o exp exp.c 
	find . | cpio -o --format=newc > ../rootfs.cpio
