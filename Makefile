# source: Makefile.in
# Copyright Gerhard Rieger and contributors (see file CHANGES)
# Published under the GNU General Public License V.2, see file COPYING

# note: @...@ forms are filled in by configure script

SHELL = /bin/sh
AR = ar
RANLIB = ranlib

.SUFFIXES: .c .o

prefix = /usr/local
exec_prefix = ${prefix}

BINDEST = ${exec_prefix}/bin

datarootdir = ${prefix}/share
MANDEST = ${datarootdir}/man

srcdir = .


CC = gcc
CXX = g++
CCOPTS = $(CCOPT) 

SYSDEFS = 
CPPFLAGS = -I. 
#0 INCLS = -I. @V_INCL@
DEFS = -DHAVE_CONFIG_H
LIBS = -lrt -lutil -lcrypto -lssl
LDFLAGS = 

INSTALL = /usr/bin/install -c

#OBJ = $(CSRC:.c=.o) $(GENSRC:.c=.o) 

# ARCHIVE_PATH:=../../build/cargo/debug/librlbox_lucet_sandbox.a
INTEGRATION_HEADER_PATH:=../../include
RLBOX_HEADER_PATH:=../../build/_deps/rlbox-src/code/include
INCLUDE_FLAGS:=-I $(RLBOX_HEADER_PATH) -I $(INTEGRATION_HEADER_PATH) #-Wl,--whole-archive $(ARCHIVE_PATH)
MISC_FLAGS:= -Wl,--no-whole-archive -rdynamic #-lpthread -lrt -ldl
RLBOX_FLAGS:= $(MISC_FLAGS)  $(INCLUDE_FLAGS) 

#0 CFLAGS = -O -D_GNU_SOURCE -Wall -Wno-parentheses $(CCOPTS) $(DEFS) $(INCLS)
CFLAGS = -O0 -g -D_GNU_SOURCE -Wall -Wno-parentheses $(CCOPTS) $(DEFS) $(CPPFLAGS) 
CLIBS = $(LIBS)
#CLIBS = $(LIBS) -lm -lefence
XIOSRCS = xioinitialize.c xiohelp.c xioparam.c xiodiag.c xioopen.c xioopts.c \
	xiosignal.c xiosigchld.c xioread.c xiowrite.c \
	xiolayer.c xioshutdown.c xioclose.c xioexit.c \
	xio-process.c xio-fd.c xio-fdnum.c xio-stdio.c xio-pipe.c \
	xio-gopen.c xio-creat.c xio-file.c xio-named.c \
	xio-socket.c xio-interface.c xio-listen.c xio-unix.c \
	xio-ip.c xio-ip4.c xio-ip6.c xio-ipapp.c xio-tcp.c \
	xio-sctp.c xio-rawip.c \
	xio-socks.c xio-proxy.c xio-udp.c \
	xio-rawip.c \
	xio-progcall.c xio-exec.c xio-system.c xio-termios.c xio-readline.c \
	xio-pty.c xio-openssl.c xio-streams.c\
	xio-ascii.c xiolockfile.c xio-tcpwrap.c xio-ext2.c xio-tun.c
XIOOBJS = $(XIOSRCS:.c=.o)
UTLSRCS = error.c dalan.c procan.c procan-cdefs.c hostan.c fdname.c sysutils.c utils.c nestlex.c vsnprintf_r.c snprinterr.c filan.c sycls.c sslcls.c
UTLOBJS = $(UTLSRCS:.c=.o)
CFILES = $(XIOSRCS) $(UTLSRCS) socat.c procan_main.c filan_main.c
OFILES = $(CFILES:.c=.o)
PROGS = socat procan filan

HFILES = sycls.h sslcls.h error.h dalan.h procan.h filan.h hostan.h sysincludes.h xio.h xioopen.h sysutils.h utils.h nestlex.h vsnprintf_r.h snprinterr.h compat.h \
	xioconfig.h mytypes.h xioopts.h xiodiag.h xiohelp.h xiosysincludes.h \
	xiomodes.h xiolayer.h xio-process.h xio-fd.h xio-fdnum.h xio-stdio.h \
	xio-named.h xio-file.h xio-creat.h xio-gopen.h xio-pipe.h \
	xio-socket.h xio-interface.h xio-listen.h xio-unix.h \
	xio-ip.h xio-ip4.h xio-ip6.h xio-rawip.h \
	xio-ipapp.h xio-tcp.h xio-udp.h xio-sctp.h \
	xio-socks.h xio-proxy.h xio-progcall.h xio-exec.h \
	xio-system.h xio-termios.h xio-readline.h \
	xio-pty.h xio-openssl.h xio-streams.h \
	xio-ascii.h xiolockfile.h xio-tcpwrap.h xio-ext2.h xio-tun.h


DOCFILES = README README.FIPS CHANGES FILES EXAMPLES PORTING SECURITY DEVELOPMENT doc/socat.yo doc/socat.1 doc/socat.html doc/xio.help FAQ BUGREPORTS COPYING COPYING.OpenSSL doc/dest-unreach.css doc/socat-openssltunnel.html doc/socat-multicast.html doc/socat-tun.html doc/socat-genericsocket.html
SHFILES = daemon.sh mail.sh ftp.sh readline.sh \
	socat_buildscript_for_android.sh
TESTFILES = test.sh socks4echo.sh proxyecho.sh gatherinfo.sh readline-test.sh \
	proxy.sh socks4a-echo.sh
OSFILES = Config/Makefile.Linux-2-6-24 Config/config.Linux-2-6-24.h \
	Config/Makefile.SunOS-5-10 Config/config.SunOS-5-10.h \
	Config/Makefile.FreeBSD-6-1 Config/config.FreeBSD-6-1.h \
	Config/Makefile.NetBSD-5-1  Config/config.NetBSD-5-1.h \
	Config/Makefile.OpenBSD-4-3 Config/config.OpenBSD-4-3.h \
	Config/Makefile.AIX-5-3 Config/config.AIX-5-3.h \
	Config/Makefile.Cygwin-1-5-25 Config/config.Cygwin-1-5-25.h \
	Config/Makefile.MacOSX-10-5 Config/config.MacOSX-10-5.h \
	Config/Makefile.DragonFly-2-8-2 Config/config.DragonFly-2-8-2.h




all: progs doc

scmclean: gitclean

gitclean: distclean docclean
	rm -f Makefile.bak configure

doc: doc/socat.1 doc/socat.html

docclean:
	rm -f doc/socat.1 doc/socat.html

doc/socat.1: doc/socat.yo
	yodl2man -o $@ $+

doc/socat.html: doc/socat.yo
	cd doc; yodl2html -o socat.html socat.yo; cd ..

progs: $(PROGS)

depend: $(CFILES) $(HFILES)
	makedepend $(SYSDEFS) $(CFILES)

socat: socat.o libxio.a
	$(CXX) $(CFLAGS) $(LDFLAGS) -o $@ socat.o libxio.a $(CLIBS) -lpthread -ldl 

PROCAN_OBJS=procan_main.o procan.o procan-cdefs.o hostan.o error.o sycls.o sysutils.o utils.o vsnprintf_r.o snprinterr.o
procan: $(PROCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(PROCAN_OBJS) $(CLIBS)

FILAN_OBJS=filan_main.o filan.o fdname.o error.o sycls.o sysutils.o utils.o vsnprintf_r.o snprinterr.o
filan: $(FILAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(FILAN_OBJS) $(CLIBS)

libxio.a: $(XIOOBJS) $(UTLOBJS)
#	$(CXX) $(CFLAGS) -std=c++17 -E $(RLBOX_FLAGS) -c rlbox_openssl.cpp > rlbox_openssl_preprocessed.cpp
	$(CXX) $(CFLAGS) -std=c++17 -Wall -Wextra -Wno-int-to-pointer-cast -Wno-unused-parameter $(RLBOX_FLAGS) -c -o rlbox_openssl.o rlbox_openssl.cpp
	$(AR) r $@ $(XIOOBJS) $(UTLOBJS) rlbox_openssl.o
	$(RANLIB) $@

doc: doc/xio.help
#

strip: progs
	strip $(PROGS)

install: progs $(srcdir)/doc/socat.1
	mkdir -p $(DESTDIR)$(BINDEST)
	$(INSTALL) -m 755 socat $(DESTDIR)$(BINDEST)
	$(INSTALL) -m 755 procan $(DESTDIR)$(BINDEST)
	$(INSTALL) -m 755 filan $(DESTDIR)$(BINDEST)
	mkdir -p $(DESTDIR)$(MANDEST)/man1
	$(INSTALL) -m 644 $(srcdir)/doc/socat.1 $(DESTDIR)$(MANDEST)/man1/

uninstall:
	rm -f $(DESTDIR)$(BINDEST)/socat
	rm -f $(DESTDIR)$(BINDEST)/procan
	rm -f $(DESTDIR)$(BINDEST)/filan
	rm -f $(DESTDIR)$(MANDEST)/man1/socat.1

# make a GNU-zipped tar ball of the source files
dist: socat.tar.gz socat.tar.bz2

socat.tar.gz: socat.tar
	gzip -9 <socat.tar >socat.tar.gz

socat.tar.bz2: socat.tar
	bzip2 -9 <socat.tar >socat.tar.bz2

VERSION = `sed 's/"//g' VERSION`
TARDIR = socat-$(VERSION)
socat.tar: configure.in configure Makefile.in config.h.in install-sh VERSION $(CFILES) $(HFILES) $(DOCFILES) $(SHFILES) $(OSFILES) $(TESTFILES) socat.spec \
	configure.ac
	if [ ! -d $(TARDIR) ]; then mkdir $(TARDIR); fi
	tar cf - $+ |(cd $(TARDIR); tar xf -)
	tar cvf socat.tar $(TARDIR)
	rm -f $(TARDIR)/COPYING		# write protected
	rm -r $(TARDIR)

clean:
	rm -f *.o libxio.a socat procan filan \
	socat.tar socat.tar.Z socat.tar.gz socat.tar.bz2 \
	socat.out compile.log test.log

# remove all files that are generated from the original socat distribution
# note that Makefile is also removed, so you have to start with ./configure
# again
distclean: clean
	rm -f config.status config.cache config.log config.h Makefile
	rm -rf autom4te.cache

info: socat
	uname -a >socat.out
	./socat -V >>socat.out
	./socat -hh >>socat.out

# perform some tests on socat
test: progs
	./test.sh

cert:
	# prepare critical files with correct permissions to avoid race cond
	>cert.key
	>cert.pem
	chmod 600 cert.key cert.pem
	# generate a private key
	openssl genrsa -out cert.key 1024
	# generate a self signed cert
	openssl req -new -key cert.key -x509 -days 3653 -out cert.crt
	# ...enter fields
	# generate the pem file
	cat cert.key cert.crt >cert.pem
	#echo use cert.pem on requestors side, i.e. with option cert=cert.pem
	#echo use cert.crt on checkers side, i.e. with option cafile=cert.crt
