# SPDX-License-Identifier: GPL-2.0

-include netlinkconfig.mk

ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
endif

SHARED_LIBS = y

DEFINES= -DRESOLVE_HOSTNAMES -DLIBDIR=\"$(LIBDIR)\"

CC := gcc
HOSTCC ?= $(CC)
DEFINES += -D_GNU_SOURCE
# Turn on transparent support for LFS
DEFINES += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CCOPTS = -O2 -pipe
WFLAGS := -Wall -Wstrict-prototypes  -Wmissing-prototypes
WFLAGS += -Wmissing-declarations -Wold-style-definition -Wformat=2
CFLAGS := $(WFLAGS) $(CCOPTS) $(DEFINES) $(CFLAGS)
YACCFLAGS = -d -t -v

SUBDIRS=demo

all: configsmk
	@export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
	@libtool --finish /usr/local/lib
	@set -e; \
	for i in $(SUBDIRS); \
	do echo; echo $$i; $(MAKE) -C $$i; done

.PHONY: clean clobber distclean check cscope version

help:
	@echo "Make Targets:"
	@echo " all                 - build binaries"
	@echo " clean               - remove products of build"
	@echo " distclean           - remove configuration and build"
	@echo " cscope              - build cscope database"
	@echo " version             - update version"
	@echo ""
	@echo "Make Arguments:"
	@echo " V=[0|1]             - set build verbosity level"

configsmk:
	sh configure

clean:
	@for i in $(SUBDIRS); \
	do $(MAKE) -C $$i clean; done

clobber:
	touch config.mk
	$(MAKE) clean
	rm -f config.mk cscope.*

distclean: clobber

cscope:
	cscope -b -q -R -Iinclude -sip -slib -smisc -snetem -stc

.EXPORT_ALL_VARIABLES:
