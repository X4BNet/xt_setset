# Edit Makefile.in and run ./configure

KVERSION = 6.11.0-1018-azure
KDIR = /lib/modules/6.11.0-1018-azure/build
KINSTDIR = $(shell dirname /lib/modules/6.11.0-1018-azure/build)
KOPTS =  -DHAVE_LLIST
IPTABLES_CFLAGS = -DXTABLES  
IPTABLES_MODULES = /usr/lib/debug/.dwz/x86_64-linux-gnu/iptables.debug
DEPMOD = /sbin/depmod -a $(KVERSION)
CARGS = 
CC = gcc

# https://www.kernel.org/doc/Documentation/kbuild/modules.txt
# https://www.kernel.org/doc/Documentation/kbuild/makefiles.txt
obj-m = xt_setset.o
ccflags-y =  -DHAVE_LLIST

all: xt_setset.ko libxt_setset.so

xt_setset.ko: xt_setset.c Makefile
	@echo Compiling for kernel $(KVERSION)
	make -C $(KDIR) M=$(CURDIR) modules CONFIG_DEBUG_INFO=y
	@touch $@
	
sparse: | xt_setset.c Makefile
	@rm -f xt_setset.ko xt_setset.o
	@echo Compiling for kernel $(KVERSION)
	make -C $(KDIR) M=$(CURDIR) modules C=1
	@touch xt_setset.ko
minstall: | xt_setset.ko
	@echo " *"
	make -C $(KDIR) M=$(CURDIR) modules_install INSTALL_MOD_PATH=$(DESTDIR)
	$(DEPMOD)
mclean:
	make -C $(KDIR) M=$(CURDIR) clean
lclean:
	-rm -f *.so *_sh.o
clean: mclean lclean
	-rm -f *.so *.o modules.order

libxt_setset_sh.o: libxt_setset.c
	gcc -O2 -Wall -Wunused $(IPTABLES_CFLAGS) -fPIC -o $@ -c libxt_setset.c

%.so: %_sh.o
	gcc -shared -lxtables -o $@ $<

linstall: | libxt_setset.so
	@echo " *"
	install -D libxt_setset.so $(DESTDIR)$(IPTABLES_MODULES)/libxt_setset.so

dinstall:
	@echo " *"
	@./install-dkms.sh --install

install: minstall linstall

uninstall:
	-rm -f $(DESTDIR)$(IPTABLES_MODULES)/libxt_setset.so
	@if [ "dinstall" = dinstall ]; then ./install-dkms.sh --uninstall; fi
	-rm -f $(DESTDIR)$(KINSTDIR)/extra/xt_setset.ko

Makefile: Makefile.in configure
	./configure --make ${CARGS}

load: all
	-insmod xt_setset.ko

unload:
	-rmmod xt_setset.ko

reload: unload load

ChangeLog:
	gitlog-to-changelog > ChangeLog
.PHONY: ChangeLog
