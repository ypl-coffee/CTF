exp:
	gcc exp.c -o exp -pthread -static
clean:
	rm -f core.cpio
	rm -f ../core.cpio
	rm -f exp
pack:
	find . -print0 \
	| cpio --null -ov --format=newc \
	| gzip -9 > ../core.cpio
all: clean exp pack