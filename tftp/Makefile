SRCROOT = ..
VERSION = $(shell cat ../version)

-include ../MCONFIG
include ../MRULES

LIB_OBJS = tftp_client.$(O)
LIB  = libtftp.so

all:  $(LIB) tftp$(X) tftp.1 test

$(LIB): $(LIB_OBJS)
	$(CC) -shared $(LDFLAGS) $^ $(TFTP_LIBS) -o $@

tftp$(X): main.$(O)
	$(CC) $(LDFLAGS) $^ $(LIB) $(TFTP_LIBS) -o $@

test$(X): test.$(O)
	$(CC) -g -O0 $(LDFLAGS) $^ $(LIB) $(TFTP_LIBS) -o $@ -lpthread

tftp.1: tftp.1.in ../version
	sed -e 's/@@VERSION@@/$(VERSION)/g' < $< > $@

install: all
	mkdir -p $(INSTALLROOT)$(BINDIR) $(INSTALLROOT)$(MANDIR)/man1
	$(INSTALL_PROGRAM) tftp$(X) $(INSTALLROOT)$(BINDIR)
	$(INSTALL_PROGRAM) $(LIB) $(INSTALLROOT)$(LIBDIR)
	$(INSTALL_DATA)    tftp.1   $(INSTALLROOT)$(MANDIR)/man1

clean:
	rm -f *.o *.obj *.exe tftp tftp.1 test $(LIB)

distclean: clean
	rm -f *~
