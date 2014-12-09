CFLAGS += -Wall -Wextra -ansi
LDFLAGS += -lnettle

all: aesscan

aesscan: aesscan.o

clean:
	-rm -f aesscan aesscan.o

# Should show "109992: found key (decrypted data = 4 text, 0 binary)"
test: aesscan
	./aesscan -s test/keyandjunk.bin test/encrypted-txt-with-iv.bin test/encrypted-txt-with-iv-1.bin test/encrypted-txt-with-iv-2.bin test/encrypted-txt-with-iv-3.bin


.PHONY: all clean test
