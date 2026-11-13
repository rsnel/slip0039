CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Wno-unused-parameter
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

source_c := wordlists.c $(filter-out wordlists.c,$(wildcard *.c))
objs := $(source_c:.c=.o)
dep_files := $(source_c:.c=.d)
dep_files := $(wildcard $(dep_files))

slip0039: $(objs)
	$(CC) $(LDFLAGS) -o $@ $^

ifneq ($(dep_files),)
  include $(dep_files)
endif

%.o: %.c
	$(CC) $(CFLAGS) -Wp,-MD,$(<:.c=.d) -c -o $@ $<

# utf8proc.c is included as it is
utf8proc.o: CFLAGS += -DUTF8PROC_STATIC -Wno-sign-compare -Wno-implicit-fallthrough

# the version is that of git, if this is a git checkout
slip0039.o: version.h

version.h: FORCE
	@v=`git describe --always --dirty 2>/dev/null || echo unknown`; \
	echo "#define SLIP0039_VERSION \"$$v\"" > version.h.tmp; \
	cmp -s version.h.tmp version.h || mv version.h.tmp version.h; \
	rm -f version.h.tmp

wordlists.c: wordlists/*.txt wordlists2c.sh
	sh wordlists2c.sh > wordlists.c.tmp && mv wordlists.c.tmp wordlists.c

clean:
	rm -f slip0039 wordlists.c version.h
	rm -f $(objs) $(dep_files)

test: slip0039
	sh tests/run.sh

install: slip0039
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man1
	install -m 755 slip0039 $(DESTDIR)$(BINDIR)/slip0039
	install -m 644 slip0039.1 $(DESTDIR)$(MANDIR)/man1/slip0039.1

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/slip0039 $(DESTDIR)$(MANDIR)/man1/slip0039.1

FORCE:

.PHONY: clean test install uninstall FORCE
