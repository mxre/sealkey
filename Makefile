LIBRARIES = -lkeyutils -ljson-c -lefivar -ludev
INCLUDES = -I/usr/include/efivar

# source files
SOURCES = \
	src/sealkey.c \
	src/pcr.c \
	src/configfile.c \
	src/systemd-boot.c \
	src/efi_boot.c \
	src/measure_pe.c \
	src/measure_cmdline.c \
	src/hash.c

# set required C flags
CFLAGS += -std=c11 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE=1

# enable TCSD support
LIBRARIES += -ltspi -lcrypto
SOURCES += src/tcsp.c src/tcsp_nv.c
CFLAGS += -DUSE_TSPI=1 -DUSE_OPENSSL=1

#LIBRARIES += -lgcrypt
#CFLAGS += -DUSE_GCRYPT=1

# executable name
BINARY = sealkey

# don't print build commands
.SILENT:
.PHONY: all clean dist debug doc open-doc

OBJECTS = $(patsubst src/%.c,obj/%.o,$(SOURCES))

all: $(BINARY)

# build for release
dist: CFLAGS += -O3 -g0 -Wall -fPIC -DNDEBUG -D_FORTIFY_SOURCE=2 -fstack-protector-strong --param=ssp-buffer-size=4
dist: LDFLAGS += -pie -Wl,-s,-O1,--sort-common,-z,relro,-z,now
dist: all

# build for debug
debug: CFLAGS += -O0 -g3 -Wall -Wextra -DDEBUG
debug: LDFLAGS +=
debug: all

$(BINARY): $(OBJECTS)
	@echo -e "\x1b[33mCCLD\x1b[0m $@"
	$(CC) $(LDFLAGS) $^ $(LIBRARIES) -o $@

obj/%.d: src/%.c
	@test -d obj || mkdir obj
	@echo -e "\x1b[33mDEP\x1b[0m  $<"
	$(CC) $(CFLAGS) $(INCLUDES) $< -MM -MF $@

obj/%.o: src/%.c obj/%.d
	@test -d obj || mkdir obj
	@echo -e "\x1b[32mCC\x1b[0m   $@"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@echo -e "\x1b[31mRM\x1b[0m   $(OBJECTS) $(BINARY)"
	$(RM) $(OBJECTS) $(BINARY) $(OBJECTS:.o=.d)

doc: doc/doxygen.cfg
	@echo -e "\x1b[34mGEN\x1b[0m  doxygen"
	doxygen $<

open-doc: doc
	xdg-open doc/html/index.html

-include $(OBJECTS:.o=.d)
