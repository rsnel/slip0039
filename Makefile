CFLAGS=-Wall -g

source_c := wordlists.c $(wildcard *.c)
objs := $(source_c:.c=.o)
dep_files := $(source_c:.c=.d)
dep_files := $(wildcard $(dep_files))

slip0039: $(objs)
	$(CC) -o $@ $^

ifneq ($(dep_files),)
  include $(dep_files)
endif

%.o: %.c
	$(CC) $(CFLAGS) -Wp,-MD,$(<:.c=.d) -c -o $@ $<

wordlists.c: wordlist_slip0039.txt wordlist_bip0039_english.txt \
	wordlist_diceware_german.txt wordlists2c.sh
	sh wordlists2c.sh > wordlists.c

clean:
	rm -f slip0039 wordlists.c
	rm -f $(objs) $(dep_files)

test:
	./test.sh
