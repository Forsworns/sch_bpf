# SPDX-License-Identifier: GPL-2.0

SUBDIRS=tc bpf

all:
	@set -e; \
	for i in $(SUBDIRS); \
	do echo; echo $$i; $(MAKE) -C $$i; done
	
clean:
	@for i in $(SUBDIRS); \
	do $(MAKE) -C $$i clean; done
