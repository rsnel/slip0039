# SLIP-0039 implementation in C without dependencies

slip0039 splits a secret into SLIP-0039 shares and recovers it. Its
shares are deterministic, so they can be checked with an independent
implementation (`verify.py`), and with its codecs a wrong passphrase
recovers a secret that looks just as real as the right one (honey
encryption).

## Building and installing

    $ make
    $ make test
    $ sudo make install

`make install` installs `slip0039` and its manual page in `/usr/local`
(set `PREFIX` or `DESTDIR` to change that). `make test` needs `jq` and
Python 3, and, if it is available, Node.js to test the JavaScript port
that the website uses. `slip0039 --help` gives a summary of the usage.

## Usage

`$ slip0039 [ OPTION ]... [ recover ]`

`$ slip0039 [ OPTION ]... check`

`$ slip0039 [ OPTION ]... split <EXP> <GT> <XofY>..`

The input is read from standard input, one item per line. If standard
input is a terminal, slip0039 asks for every item; the passphrase, the
SEED and the master secret are not echoed, and for `split` they must be
typed twice (the SEED once, an empty SEED generates one).

option `-d` (debug) displays the shares, secrets and digests in the known groups
at program exit

    0 - 9, A - F are the numbers of the groups/shares
    ? means 'digest'
    S means 'secret'
    P means 'plaintext' (decrypted secret)

option `-q` (quiet) shuts up warnings and notes

option `-h` or `--help` shows a summary of the usage, `-V` or `--version`
the version

option `--random-seed` generates the SEED for `split` (64 random letters
and digits), instead of reading it from the input; it is shown on standard
error, unless `-q` is given, it is needed only to check the shares with
`verify.py`

option `-c` specifies the encoding of the master secret, optionally followed
by the wordlist (an empty `WORDLIST` selects the default wordlist of the codec)
and, for codecs that need it, an argument `ARG`; the argument is not stored
in the shares, so `split` shows the command to recover them, write it
down with your shares

* `base16`: this is the default codec, it stores 16 bytes of data or more in
  increments of 2 bytes with a default maximum of 64 bytes; upper case and
  spaces are accepted

* `bip39`: use this codec to store a valid bip39 mnemonic from 12 to 24
  words in increments of 3 words

  - `english` is the default wordlist for this codec, a word can be given
    by its first 4 letters

  - `spanish`, `french`, `italian`, `portuguese`, `czech`, `japanese`,
    `korean`, `chinese_simplified` and `chinese_traditional` are also
    supported; the input is converted to Unicode normalization form NFKD,
    the form of the wordlists, so an accented letter can be typed in any
    way; `japanese` mnemonics are printed with ideographic spaces (U+3000),
    ordinary spaces are accepted

* `diceware`: this codec stores a diceware passphrase of any number of words
  (up to 39 with the default settings); the master secret is made large
  enough for the passphrase and for `GAIN` (see `--gain`), so that every
  passphrase, the right one or a wrong one, recovers a diceware passphrase of
  the same number of words; the number of words is mandatory, as in
  `-c diceware::12` or `-c diceware:dutch:12`, use the same value for `split`
  (where it is checked against the passphrase) and for `recover` (where any
  number of words that fits in the master secret can be used, the gain that
  was used to split does not matter); write it down with your shares

* `password`: this codec stores a random password of a given length, encoded
  in the same way as `diceware` (every master secret recovers a password of
  that length), the length is mandatory, as in `-c password::20`; the
  wordlist is the alphabet of the password:

  - `alnum` (the default): `0-9`, `A-Z` and `a-z`

  - `alpha`: `A-Z` and `a-z`

  - `lower`: `a-z`

  - `ascii`: all printable ASCII characters except space

  This is only a good choice for passwords that were generated uniformly from
  the alphabet (as password managers do), not for passwords chosen by a
  person and not for passwords that were generated with rules like 'at least
  one digit'

* `numeric`: this codec stores a random number of a given number of digits
  (a PIN for example) in the same way, as in `-c numeric::6`, leading zeros
  are significant

* `totp`: this codec stores the base32 secret of a TOTP or HOTP
  authenticator (RFC 6238, RFC 4226), as shown by many sites as an
  alternative to the QR code, in the same way as `diceware`; the number of
  base32 characters (without `=` padding) is mandatory, as in `-c totp::32`;
  when splitting, spaces, `=` and lower case letters are accepted, when
  recovering, the secret is printed in upper case without spaces and padding

* `bip32`: this codec stores a BIP32 root extended private key (depth 0, no
  parent fingerprint, child number 0) in a master secret of 64 bytes: the
  private key followed by the chain code, which is exactly the output of
  HMAC-SHA512 from which BIP32 derives the root key, so `-c base16` shows it;
  the version is not stored and is mandatory, as in `-c bip32::zprv`, it is
  one of `xprv`, `yprv`, `zprv`, `Yprv`, `Zprv` or, for testnet, `tprv`,
  `uprv`, `vprv`, `Uprv`, `Vprv` (see SLIP-0132), use the same value for
  `split` (where it is checked against the key) and for `recover`; write it
  down with your shares; this codec does not take a wordlist

  Every master secret, so also the one recovered with a wrong passphrase,
  decodes to a valid extended private key (except with negligible
  probability). Extended public keys (`xpub` etc.) are not supported: a
  compressed public key is the x coordinate and the parity of y, which is one
  bit more than fits in 64 bytes together with the chain code, and a wrong
  passphrase would give an x that is not on the curve half of the time.

* `wif`: this codec stores a bitcoin private key in Wallet Import Format in a
  master secret of 32 bytes (the private key, so `-c base16` shows it); the
  type of the key is not stored and is mandatory, as in `-c wif::compressed`,
  it is one of `compressed` (the key starts with `K` or `L`), `uncompressed`
  (`5`), `testnet-compressed` (`c`) or `testnet-uncompressed` (`9`)

* `nostr`: this codec stores a nostr private key (`nsec1...`, NIP-19) in a
  master secret of 32 bytes (the private key); this codec has no argument

* `codex32`: this codec stores a codex32 secret (BIP-0093, share index `s`)
  that encodes a BIP32 master seed of 16, 20, 24, 28, 32 or 64 bytes, the
  master secret is the master seed (so `-c base16` shows it); the threshold
  and the identifier are not stored and are mandatory, as in
  `-c codex32::0test` for the secret `ms10tests...`, the secret is recovered
  in the case of this argument (so `-c codex32::0TEST` recovers
  `MS10TESTS...`, upper case is recommended for handwriting); the 1 to 4
  padding bits at the end of the payload are not stored, if they are not
  zero a warning is given and the recovered secret differs in its last
  characters, but it encodes the same master seed; codex32 shares (share
  index other than `s`) are not supported

For `bip32`, `wif`, `nostr` and `codex32` every master secret, so also the
one recovered with a wrong passphrase, decodes to a valid key or seed (except
with negligible probability).

Keep in mind that honey encryption only helps against an attacker who has no
other way to check a guess: the public keys and addresses that belong to a
wallet that has been used can be found on the blockchain, so an attacker can
recognize the right private key, extended key or master seed by deriving
them; secrets that can only be checked online with a limited number of
tries, like a PIN, a TOTP secret or the password of an account, benefit the
most.

option `--gain GAIN` bounds the advantage an attacker gets from the way
structured secrets (like a diceware passphrase) are encoded, the default is
`0.01`; it is used by the `diceware`, `password`, `numeric` and `totp`
codecs

An attacker with a list of q equally likely passphrases can decrypt with all
of them and gets q plausible secrets. If the encoding were perfect, the best
the attacker could do is pick one at random, which is right with probability
1/q. The encoding used here is very slightly uneven, which lets the attacker
do a little better: right with probability at most (1 + GAIN)/q. Each halving
of GAIN costs one extra bit in the stored secret: `0.01` needs 7 bits on top
of the size of the data and `0.001` needs 10. The default `0.01` amounts to
losing about 0.014 bits of passphrase strength, once, however many passphrases
the attacker tries, which is negligible compared to the strength of any
reasonable passphrase. Because the secret grows in steps of 16 bits, a
stricter value often does not change the length of the shares at all.

option `--pre-may-2024` selects the share format of SLIP-0039 as it was
before May 2024, when the highest bit of the 5 bit iteration exponent became
the extendable backup flag; this option is not recommended

Without this option, `split` creates extendable shares (the flag is set and
the iteration exponent is at most 15) and `recover` accepts both extendable
and non-extendable shares, so shares made before May 2024 are recovered
without it, unless their iteration exponent is 16 or more, which is very
unlikely. With this option, `split` creates non-extendable shares, which
other SLIP-0039 implementations can only recover if the iteration exponent is
at most 15.

### Mode `recover` (default when no mode is specified)

In this mode, the first line of standard input is the passphrase, and the
rest of the lines (until EOF) are mnemonics, the output is the master
secret in the format of the codec when there are no errors and is an
error message when there are.

The input may be sloppy: empty lines are skipped, upper case letters,
tabs, extra spaces, CRLF line ends and a missing newline at the end are
accepted, and a word of a mnemonic can be given by its first 4 letters (in
the SLIP-0039 wordlist, these identify the word). Errors give the number
of the line of the input.

All given shares are used: the shares beyond the threshold of a group
(and the groups beyond the group threshold) are checked against the
others, so a share of another split with the same identifier is detected
instead of ignored. If there are not enough shares, `recover` shows
which groups are complete and how many shares are missing.

### Mode `check`

In this mode, the input is only the mnemonics, without passphrase. The
output tells which groups are complete and which shares are missing, and,
if there are enough shares, whether they belong together (the digests and
the extra shares are checked, as with `recover`). The exit status is 0 if
the master secret can be recovered.

    $ slip0039 check < shares
    identifier 12466, extendable, iteration exponent 0, master secret of 128 bits
    1 of 1 groups needed, 1 complete
    group 1 (academic): 2 of 2 shares, complete (lines 1, 2)
    the shares belong together, the master secret can be recovered

### Mode `split`

in mode split, the first line of standard input is also the passphrase, the
second line of standard input should be entropy for the PRNG (the SEED,
not with `--random-seed`) and the third line should be the master secret

on the commandline the iteration `EXP`onent (at most 15, or 31 with
`--pre-may-2024`), the group threshold `GT` (at least 1) and the
specifications of groups must be given

the `ID` is the low 15 bits of the first 2 bytes of SHA256 of `SEED`

shares and the `n - 4` bytes of the digest share are computed with PBKDF2 with
the `EMS || SEED` as password and other parameters that decide the structure of
the split as salt. If `SEED` is not kept secret, then an adversary that already
knows `EMS`, can use it to guess the structure of the split i.e. how many
shares each group has. Also when a codec is used that needs some random
data, like diceware, the correctness of the passphrase can be proven if one
knows the `SEED`. Treat it as confidential as the secret and the
passphrase.

All data supplied to this program on standard input should be treated as highly confidential. `SEED` should be destroyed after a single use

The first `XofY` reflects the distribution of shares in the first group.
The second `XofY` reflects the distribution of shares in the second group.
etc

## Verifying that `split` is deterministic

The reference implementation of SLIP-0039 takes the random values that the
scheme needs (the random shares and the random part of the digests) from
the operating system. Shares made that way cannot be checked: a malicious
implementation could, for example, hide an encrypted copy of the master
secret in them, and nobody could tell. `slip0039 split` is deterministic:
every random value is taken, in a fixed order, from

    PBKDF2-HMAC-SHA256(password = EMS || SEED,
                       salt = e || GT || G || T_1 || N_1 ... T_G || N_G,
                       iterations = 1)

where EMS is the encrypted master secret (as specified by SLIP-0039, the
only place where the master secret and the passphrase are used) and the
salt describes the split, with each number as a single byte. The
identifier is the lowest 15 bits of the first two bytes of SHA256(SEED).

`verify.py` is an independent implementation of all of this in Python
that only uses the standard library. It reads the same input and takes the
same arguments as `slip0039 split`, including `-c` with every codec and
`--gain`, and prints the same shares:

    $ ./slip0039 split 1 2 2of3 3of5 < input > shares
    $ ./verify.py 1 2 2of3 3of5 < input | diff - shares

If `diff` prints nothing, the shares contain only what SLIP-0039 prescribes:
the EMS, split with randomness that is a fixed function of the EMS and the
SEED. For the honey encoded codecs (`diceware`, `password`, `numeric` and
`totp`) this also shows that the master secret is k + j*r, where k is the
secret, j the number of possible secrets and r is derived from the SEED
only. `tests/verify.sh` runs a number of such comparisons.

With 1 iteration, block i of the PBKDF2 output is
HMAC-SHA256(EMS || SEED, salt || i), a pseudorandom function keyed with
EMS || SEED. Someone who holds fewer shares than the threshold sees some of
these bytes, but computing the EMS (or anything else about the key) from
them is as hard as breaking HMAC-SHA256, unless the key can be guessed.
So this protection is computational, while that of shares made with true
randomness is information theoretic, and it depends on EMS || SEED being
hard to guess. A master secret of 128 bits or more is enough on its own,
but for a low entropy secret (a PIN with `numeric`, a short `password`) the
randomness of the honey encoding also comes from SEED, so then the SEED is
what protects the secret: use a long random SEED (`slip0039` warns if it is
shorter than 64 characters), and keep in mind that the identifier reveals
15 bits of SHA256(SEED).

## Website

`doc/index.html` is the website of slip0039. Its demo uses `doc/slip0039.js`,
a JavaScript port of `split` and `recover` (for the `base16`, `numeric`,
`password` and `totp` codecs) that gives the same shares as slip0039 and
`verify.py`; `tests/js.js` checks that. The site loads nothing from other
sites.

## Specification

`doc/slip-0039.md` is the current specification, `doc/slip-0039-deprecated.md`
is the version from before the extendable backup flag was added in May 2024.

## Features

* Attempts are made to wipe all sensitive data from memory upon
  termination, also when the program is killed by a signal or crashes
  (the signal handler only uses async-signal-safe functions).

* Data is locked in memory so that it does not get swapped out to disk. On
  Linux the whole process is locked, this needs a few MiB of locked memory
  (see `ulimit -l`); core dumps are disabled.

* The program is constructed such that the amount of data that is needlessly
  rearranged and copied around is reduced.

* The output of the program is deterministic, so that the output can be
  reproduced on multiple machines and it is easy to see that the random data in
  the shares and in the second part of the digest share contains no information.

* Sensitive data should be handled in constant time. The exception is the
  Unicode normalization of a master secret in words that is not ASCII.

## Testsuite

`make test` runs `tests/run.sh`, which runs:

* `tests/vectors.sh`: the official test vectors, the first 40 entries of
  `tests/vectors.json`; test 41 can detect certain errors in modular
  arithmetic, tests 42 to 45 use extendable shares, added to the
  specification in May 2024

* `tests/codecs.sh`: every codec, the secret is recovered and a wrong
  passphrase gives a secret of the same format

* `tests/errors.sh`: invalid input is refused with a clear message, a share
  of another split is detected

* `tests/input.sh`: sloppy input, Unicode, the terminal (with
  `tests/terminal.py`) and signals

* `tests/verify.sh`: `verify.py` reproduces the shares of every codec

* `tests/golden.sh`: the shares and recovered secrets of every codec are
  compared to `tests/golden.expected`, so that a change of an encoding,
  which would make existing shares unrecoverable, does not go unnoticed

* `tests/js.js`: `doc/slip0039.js` gives the same shares as slip0039 (if
  `node` is available)

The tests are run by GitHub Actions on Linux and macOS, with gcc and
clang, and with AddressSanitizer and UndefinedBehaviorSanitizer.

## Portability

The program is known to work on Linux and MacOS. Issues pertaining to
MacOS not having mlockall() have been fixed. The build and the tests also
work where `/bin/sh` is bash.

## Authors

The project was started by Rik Snel (https://github.com/rsnel/). MacOS compatibility and various fixes were offered by James Z.M. Gao  (https://github.com/gzm55).

The sha256 code is copyright (c) 2014 The Bitcoin Core developers under the MIT license.

The utf8 code is:

* Copyright (c) 2014-2021 Steven G. Johnson, Jiahao Chen, Peter Colberg, Tony Kelman, Scott P. Jones, and other contributors.

* Copyright (c) 2009 Public Software Group e. V., Berlin, Germany

under the MIT license.

Wordlists:

* slip0039 and BIP39 (all languages): from the SLIP-0039 and BIP-0039
  repositories, their checksums are checked by `wordlists2c.sh`

* diceware English

* diceware German, provided by Benjamin Tenne under the terms of the GNU GPL

* diceware Dutch, provided by Bart Van den Eynde under the GFDL; it has
  the words `abc`, `hij` and `ijk` twice, typing one of them gives the
  first, which is the same passphrase

## Examples

Example split `MS = 00000000000000000000000000000000`, `SEED = fdsaludskj` with debug output:

    $ slip0039 -q -d split 0 4 2of3 5of10 1of1 7of14 << EOF
    TREZOR
    fdsaludskj
    00000000000000000000000000000000
    EOF
    ladybug again adult roster bolt medical junction satoshi forward fortune tracks exhaust eyebrow year ancestor fridge dramatic lily velvet mailman
    ladybug again adult scared breathe step charity prepare lunch join coal jerky unknown scholar order blimp bumpy furl texture intend
    ladybug again adult shadow angel ceramic penalty reunion dryer cargo anatomy charity hanger lunch example holiday video decision legal inherit
    ladybug again benefit ruin acrobat cylinder believe reject false loud unknown program step hush negative friar exhaust analysis petition champion
    ladybug again benefit scholar breathe library gums device piece tracks game permit museum rumor toxic forecast alive lecture prepare desktop
    ladybug again benefit shaped craft brave famous exchange wrap exceed thank miracle closet easel umbrella firefly glen carve python class
    ladybug again benefit slap column income news true satisfy elegant move center fortune secret intend material merchant alien arena pregnant
    ladybug again benefit sniff argue drink plot cleanup length reunion predator quiet legs width cylinder flip headset pencil ranked careful
    ladybug again benefit spine chew deny husband snake marathon penalty liberty should papa timely grasp quick puny calcium sugar numerous
    ladybug again benefit stilt body general agency argue valid chest treat sidewalk home similar skunk tactics royal prune mixed sweater
    ladybug again benefit swing daisy pitch huge source describe fiction alarm animal lair ounce gesture trash pancake nuclear escape romp
    ladybug again benefit teaspoon alive edge trial video domestic repair cinema trust hush orbit breathe plot change frequent license wrist
    ladybug again benefit thunder blanket group grumpy likely season liberty dive duration leaves midst eraser syndrome election traveler move zero
    ladybug again chubby romp alpha emerald exhaust class crowd aspect amuse fiscal slush remember welcome animal bike gesture shadow arcade
    ladybug again depart rumor capture medal disease hesitate clay wavy mailman club dough prisoner veteran peanut wavy prayer memory grownup
    ladybug again depart scout avoid execute wireless premium type ecology vexed jury aunt unusual medical garlic chemical dance bishop desert
    ladybug again depart shelter bedroom numerous medical blanket spit scandal frozen body soldier tracks scatter drift blanket check glimpse system
    ladybug again depart sled column retailer revenue genius mixture disaster calcium loud fantasy civil helpful oral center lyrics legend theater
    ladybug again depart software dryer raisin rhythm fiction email miracle making divorce bolt withdraw slush unfold subject company friar race
    ladybug again depart spit cover kind gasoline bedroom curious timely hairy meaning born category vocal idle criminal junction closet omit
    ladybug again depart strategy darkness campus tadpole credit mayor birthday true prospect together orbit window aunt depend database epidemic maximum
    ladybug again depart symbolic buyer decision usher subject guest closet desert shame extra scatter beam velvet curious freshman epidemic shaft
    ladybug again depart tenant daughter romantic frequent salary response husky much lizard symbolic artist slush ceramic luck various hamster trend
    ladybug again depart tidy chubby have quick carve holiday peanut treat beaver endorse gray firefly mason walnut hanger aircraft python
    ladybug again depart trend custody shaft course numb predator emerald dive pleasure eclipse cylinder downtown scramble liquid muscle inside pink
    ladybug again depart undergo alien warn devote usual view soul judicial vegan herald satisfy hybrid ancestor blind civil glen ordinary
    ladybug again depart valuable aviation wealthy volume phantom dance dream painting relate dream aircraft eclipse easel acne quarter museum smug
    ladybug again depart violence alien closet aircraft wisdom fumes chew edge scandal modern upgrade obtain smith fiction upgrade breathe upstairs
    slip0039:debug:---START---internal slip0039 data----
    slip0039:debug:size of master secret=16 bytes
    slip0039:debug:Identifier=0x3f00
    slip0039:debug:Extendable backup flag=1
    slip0039:debug:Iteration exponent=0 (2500 iterations per round)
    slip0039:debug:/    count= 4 available= 4 threshold= 4  (ladybug again)
    slip0039:debug:/0/  count= 3 available= 3 threshold= 2  (adult)
    slip0039:debug:/0/0   5a8f1eac356d5b39f4e942fec285d0f0   (roster)
    slip0039:debug:/0/1   62d8887aca207989b793bdc52751586c   (scared)
    slip0039:debug:/0/2   2a21291bd0f71f42721da7881336dbd3   (shadow)
    slip0039:debug:/0/?   60c5b0fdd9084e5712cbaedd01338408 
    slip0039:debug:/0/S   5892262b26456ce751b151e6e4e70c94 
    slip0039:debug:/1/  count=10 available=10 threshold= 5  (benefit)
    slip0039:debug:/1/0   042e04ab8d48873bdafb62706615cd3a   (ruin)
    slip0039:debug:/1/1   62831a335e9ee7d7ea565bc1b9e5a41c   (scholar)
    slip0039:debug:/1/2   a71854a4d7f74d38c924973ffb45618d   (shaped)
    slip0039:debug:/1/3   9e73664eb30c42e5620d6cc75da8da40   (slap)
    slip0039:debug:/1/4   343d2aa24609bd2afb3e07facb8589ad   (sniff)
    slip0039:debug:/1/5   8b32dc0d0a31a460bca684e6193b3ac7   (spine)
    slip0039:debug:/1/6   59610110d3c522ba5cadb8cbb33def03   (stilt)
    slip0039:debug:/1/7   b9a8dbcd28d054c180b1f99e189e8e82   (swing)
    slip0039:debug:/1/8   1c413a7f4cebba48deb5c19d062aa886   (teaspoon)
    slip0039:debug:/1/9   546719e83f1c82ce73ea0391128de10a   (thunder)
    slip0039:debug:/1/?   35e9664af03ddac45c60e0d8a4f6059c 
    slip0039:debug:/1/S   852c8522cdcd4dd27f74f04c7f015af4 
    slip0039:debug:/2/  count= 1 available= 1 threshold= 1  (chubby)
    slip0039:debug:/2/0   1d4493a23cae0e02556b3ab97e80b04f   (romp)
    slip0039:debug:/2/S   1d4493a23cae0e02556b3ab97e80b04f 
    slip0039:debug:/3/  count=14 available=14 threshold= 7  (depart)
    slip0039:debug:/3/0   798ece26d090f9228264edae3d0a3be4   (rumor)
    slip0039:debug:/3/1   3e4e3efac7b040fd17b43befa3c60489   (scout)
    slip0039:debug:/3/2   4799e3c15356c417816747e7f123cc54   (shelter)
    slip0039:debug:/3/3   9ebcaf56164b380738714d239b19c883   (sled)
    slip0039:debug:/3/4   f7b56f954d119262b3a05afc73aee369   (software)
    slip0039:debug:/3/5   a47c98211cb5e61a48e85c203db718ab   (spit)
    slip0039:debug:/3/6   bc1d77c2a639147acb039b9d3ed0eccd   (strategy)
    slip0039:debug:/3/7   71313c3da5a025cd1c8d41c4843f2cb5   (symbolic)
    slip0039:debug:/3/8   bebfd71c26f070a5785f760db3a2121e   (tenant)
    slip0039:debug:/3/9   8c6a6ce1fdb6a3ba51151a655588d7e0   (tidy)
    slip0039:debug:/3/A   b7c88a399aaf448e7aa5022e0eec5e13   (trend)
    slip0039:debug:/3/B   1bf88d8f13d4d25e7f29b2c31c30a057   (undergo)
    slip0039:debug:/3/C   3df97dda5cbb3c680b90f1051023fc02   (valuable)
    slip0039:debug:/3/D   1b25c14fc17922d04c424df026dcfd53   (violence)
    slip0039:debug:/3/?   93f28398279b0d9db73dc34d0769a426 
    slip0039:debug:/3/S   62f5515778c6b496943a7a2e70bb3471 
    slip0039:debug:/?     2949ea8441fc18d3a27a050e2a0572f2 
    slip0039:debug:/S     9f42d0ebd9ce2afb8319c59dcc60129f 
    slip0039:debug:/P     00000000000000000000000000000000 
    slip0039:debug:---END-----internal slip0039 data----

Example Recover with debug output:

    $ slip0039 -d << EOF
    TREZOR
    ladybug again adult roster bolt medical junction satoshi forward fortune tracks exhaust eyebrow year ancestor fridge dramatic lily velvet mailman
    ladybug again adult scared breathe step charity prepare lunch join coal jerky unknown scholar order blimp bumpy furl texture intend
    ladybug again benefit ruin acrobat cylinder believe reject false loud unknown program step hush negative friar exhaust analysis petition champion
    ladybug again benefit scholar breathe library gums device piece tracks game permit museum rumor toxic forecast alive lecture prepare desktop
    ladybug again benefit shaped craft brave famous exchange wrap exceed thank miracle closet easel umbrella firefly glen carve python class
    ladybug again benefit slap column income news true satisfy elegant move center fortune secret intend material merchant alien arena pregnant
    ladybug again benefit sniff argue drink plot cleanup length reunion predator quiet legs width cylinder flip headset pencil ranked careful
    ladybug again chubby romp alpha emerald exhaust class crowd aspect amuse fiscal slush remember welcome animal bike gesture shadow arcade
    ladybug again depart rumor capture medal disease hesitate clay wavy mailman club dough prisoner veteran peanut wavy prayer memory grownup
    ladybug again depart scout avoid execute wireless premium type ecology vexed jury aunt unusual medical garlic chemical dance bishop desert
    ladybug again depart shelter bedroom numerous medical blanket spit scandal frozen body soldier tracks scatter drift blanket check glimpse system
    ladybug again depart sled column retailer revenue genius mixture disaster calcium loud fantasy civil helpful oral center lyrics legend theater
    ladybug again depart software dryer raisin rhythm fiction email miracle making divorce bolt withdraw slush unfold subject company friar race
    ladybug again depart spit cover kind gasoline bedroom curious timely hairy meaning born category vocal idle criminal junction closet omit
    ladybug again depart strategy darkness campus tadpole credit mayor birthday true prospect together orbit window aunt depend database epidemic maximum
    EOF
    00000000000000000000000000000000
    slip0039:debug:---START---internal slip0039 data----
    slip0039:debug:size of master secret=16 bytes
    slip0039:debug:Identifier=0x3f00
    slip0039:debug:Extendable backup flag=1
    slip0039:debug:Iteration exponent=0 (2500 iterations per round)
    slip0039:debug:/    count= 4 available= 4 threshold= 4  (ladybug again)
    slip0039:debug:/0/  count= ? available= 2 threshold= 2  (adult)
    slip0039:debug:/0/0   5a8f1eac356d5b39f4e942fec285d0f0   (roster)
    slip0039:debug:/0/1   62d8887aca207989b793bdc52751586c   (scared)
    slip0039:debug:/0/?   60c5b0fdd9084e5712cbaedd01338408 
    slip0039:debug:/0/S   5892262b26456ce751b151e6e4e70c94 
    slip0039:debug:/1/  count= ? available= 5 threshold= 5  (benefit)
    slip0039:debug:/1/0   042e04ab8d48873bdafb62706615cd3a   (ruin)
    slip0039:debug:/1/1   62831a335e9ee7d7ea565bc1b9e5a41c   (scholar)
    slip0039:debug:/1/2   a71854a4d7f74d38c924973ffb45618d   (shaped)
    slip0039:debug:/1/3   9e73664eb30c42e5620d6cc75da8da40   (slap)
    slip0039:debug:/1/4   343d2aa24609bd2afb3e07facb8589ad   (sniff)
    slip0039:debug:/1/?   35e9664af03ddac45c60e0d8a4f6059c 
    slip0039:debug:/1/S   852c8522cdcd4dd27f74f04c7f015af4 
    slip0039:debug:/2/  count= ? available= 1 threshold= 1  (chubby)
    slip0039:debug:/2/0   1d4493a23cae0e02556b3ab97e80b04f   (romp)
    slip0039:debug:/2/S   1d4493a23cae0e02556b3ab97e80b04f 
    slip0039:debug:/3/  count= ? available= 7 threshold= 7  (depart)
    slip0039:debug:/3/0   798ece26d090f9228264edae3d0a3be4   (rumor)
    slip0039:debug:/3/1   3e4e3efac7b040fd17b43befa3c60489   (scout)
    slip0039:debug:/3/2   4799e3c15356c417816747e7f123cc54   (shelter)
    slip0039:debug:/3/3   9ebcaf56164b380738714d239b19c883   (sled)
    slip0039:debug:/3/4   f7b56f954d119262b3a05afc73aee369   (software)
    slip0039:debug:/3/5   a47c98211cb5e61a48e85c203db718ab   (spit)
    slip0039:debug:/3/6   bc1d77c2a639147acb039b9d3ed0eccd   (strategy)
    slip0039:debug:/3/?   93f28398279b0d9db73dc34d0769a426 
    slip0039:debug:/3/S   62f5515778c6b496943a7a2e70bb3471 
    slip0039:debug:/?     2949ea8441fc18d3a27a050e2a0572f2 
    slip0039:debug:/S     9f42d0ebd9ce2afb8319c59dcc60129f 
    slip0039:debug:/P     00000000000000000000000000000000 
    slip0039:debug:---END-----internal slip0039 data----
