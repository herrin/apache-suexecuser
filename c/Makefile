# For gcc
CC= gcc
# For ANSI compilers
#CC= cc

#For Optimization
CFLAGS= -O2 -Wall -g -fno-strict-aliasing
#For debugging
# CFLAGS= -g -Wall
#LIBS= /usr/lib/libc_p.a /usr/lib/libg.a

RM= /bin/rm -f
#--- You shouldn't have to edit anything else. ---

#LIBEXECDIR=`apxs2 -q LIBEXECDIR 2>>/dev/null`

.c.o: 
	$(CC) -c $(CFLAGS) $<

PROGS=strlwr suexec-user suexec-cgiuser mod_cgisuexecuser


OBJS_STRLWR=strlwr.o lowercase.o
OBJS_SUEXEC=suexec.o
OBJS_SUEXEC_USER=suexec-user.o suexec-util.o lowercase.o
OBJS_SUEXEC_SYSTEM=suexec-system.o suexec-util.o lowercase.o
OBJS_SUEXEC_CGIUSER=suexec-cgiuser.o suexec-util.o lowercase.o
OBJS_SUEXEC_WEBMASTR=suexec-webmastr.o suexec-util.o lowercase.o

all: $(PROGS)

strlwr: $(OBJS_STRLWR)
	$(CC) $(OBJS_STRLWR) -o $@

suexec-system: $(OBJS_SUEXEC_SYSTEM)
	$(CC) $(OBJS_SUEXEC_SYSTEM) -o $@

suexec-user: $(OBJS_SUEXEC_USER)
	$(CC) $(OBJS_SUEXEC_USER) -o $@

suexec-cgiuser: $(OBJS_SUEXEC_CGIUSER)
	$(CC) $(OBJS_SUEXEC_CGIUSER) -o $@

suexec-webmastr: $(OBJS_SUEXEC_WEBMASTR)
	$(CC) $(OBJS_SUEXEC_WEBMASTR) -o $@

suexec: $(OBJS_SUEXEC)
	$(CC) $(OBJS_SUEXEC) -o $@

mod_cgisuexecuser: 
	apxs2 -i -S LIBEXECDIR=`pwd` -c mod_cgisuexecuser.c

install: all

clean:
	rm -f *.o *.lo *.slo *.so  $(PROGS)
	rm -rf .libs
