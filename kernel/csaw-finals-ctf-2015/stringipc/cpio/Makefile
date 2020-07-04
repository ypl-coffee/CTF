pack:
	find . -print0 \
	| cpio --null -ov --format=newc \
	| gzip -9 > ../core.cpio
clean:
	rm my
	rm -f core.cpio
	rm -f ../core.cpio
my:
	musl-gcc my.c -o my -static
all: clean my pack