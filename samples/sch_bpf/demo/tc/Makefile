# SPDX-License-Identifier: GPL-2.0
include ../../config.mk
APPS = sch_pfifo

all: $(APPS)

%: %.o 
	$(QUIET_LINK)$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@


clean:
	rm -f $(APPS)
