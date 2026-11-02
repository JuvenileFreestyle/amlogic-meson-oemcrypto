# SPDX-License-Identifier: MIT
#
# Amlogic Meson Widevine L1 OEMCrypto Bridge Driver
#
# Copyright (c) 2026 JuvenileFreestyle <JuvenileFreestyle@users.noreply.github.com>

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -fPIC -Iinclude
LDFLAGS ?= -shared -Wl,-soname,liboemcrypto.so.1
LIBS = -lteec -lpthread

TARGET_LIB = liboemcrypto_meson.so
SONAME = liboemcrypto.so

SRCS = src/meson_oemcrypto_core.c src/meson_oemcrypto_secmem.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)
	ln -sf $(TARGET_LIB) $(SONAME)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET_LIB) $(SONAME)

install: $(TARGET_LIB)
	install -d $(DESTDIR)/usr/lib
	install -m 0755 $(TARGET_LIB) $(DESTDIR)/usr/lib/
	ln -sf $(TARGET_LIB) $(DESTDIR)/usr/lib/$(SONAME)
	install -d $(DESTDIR)/usr/include
	install -m 0644 include/OEMCrypto.h $(DESTDIR)/usr/include/

.PHONY: all clean install
