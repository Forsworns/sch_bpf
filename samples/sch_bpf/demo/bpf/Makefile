# SPDX-License-Identifier: GPL-2.0
include ../../config.mk

ARCH := $(shell uname -m | sed 's/x86_64/x86/')
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

APPS = sch_bpf_pfifo

all: $(APPS)

sch_bpf_pfifo: sch_bpf_pfifo.skel.h sch_bpf_pfifo.o
	$(call msg,CC,$@)
	$(QUIET_LINK)$(CC) $(CFLAGS) $(LDFLAGS) sch_bpf_pfifo.c $(LDLIBS) -o $@
	
sch_bpf_pfifo.skel.h: sch_bpf_pfifo.bpf.o 
	$(call msg,GEN-SKEL,$@)
	$(BPFTOOL) gen skeleton $< > $@

sch_bpf_pfifo.bpf.o: sch_bpf_pfifo.bpf.c $(LIBBPF_OBJ)
	$(call msg,BPF,$@)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
			 $(SCHBPF_KERNEL_INCLUDE)					\
		     -c $(filter %.c,$^) -o $@ &&		      \
	$(LLVM_STRIP) -g $@

clean:
	rm -f $(APPS) *.skel.h *.o
