# SLIP-0039 implementation in C without dependencies

## Usage

`$ slip0039 [ -d ] [ -q ] [ -c CODEC[:[WORDLIST][:ARG]] ] [ --gain GAIN ] [ --pre-may-2024 ] recover`

`$ slip0039 [ -d ] [ -q ] [ -c CODEC[:[WORDLIST][:ARG]] ] [ --gain GAIN ] [ --pre-may-2024 ] split <EXP> <GT> <XofY>..`

option `-d` (debug) displays the shares, secrets and digests in the known groups
at program exit

option `-q` (quiet) shuts up warnings

    0 - 9, A - F are the numbers of the groups/shares
    ? means 'digest'
    S means 'secret'
    P means 'plaintext' (decrypted secret)

option `-c` specifies the encoding of the master secret, optionally followed
by the wordlist (an empty `WORDLIST` selects the default wordlist of the codec)
and, for codecs that need it, an argument `ARG`

* `base16`: this is the default codec, it stores 16 bytes of data or more in
  increments of 2 bytes with a default maximum of 64 bytes

* `bip39`: use this codec to store a valid bip39 wordlist from 12 to 24
  words in increments of 3 words

  - `english` is the default wordlist for this codec

  - `spanish` is also supported, but UTF-8 normalization is not yet supported

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
rest of the lines (until EOF) are mnemonics, the output is a base16 encoded
string of the secret when there are no errors and is an errormessage when there
are

### Mode `split`

in mode split, the first line of standard input is also the passphrase, the
second line of standard input should be entropy for the PRNG and the third line should be the master secret

on the commandline the iteration `EXP`onent (at most 15, or 31 with
`--pre-may-2024`) and the specifications of groups must be given

the `ID` is the low 15 bits of the first 2 bytes of SHA256 of `SEED`

shares and the `n - 4` bytes of the digest share are computed with PBKDF2 with
the `EMS || SEED` as password and other parameters that decide the structure of
the split as salt. If `SEED` is not kept secret, then an adversary that already
knows `EMS`, can use it to guess the structure of the split i.e. how many
shares each group has. Also when a codec is used that needs some random data, like diceware, the correctness of the passphrase can be proven if one knows the `SEED`. Treat it as confidential as the secret and the passphrase.

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

`verify.py` is an independent implementation of all of this in about 200
lines of Python that only uses the standard library. It reads the same
input and takes the same arguments as `slip0039 split` (with the default
codec), and prints the same shares:

    $ ./slip0039 split 1 2 2of3 3of5 < input > shares
    $ ./verify.py 1 2 2of3 3of5 < input | diff - shares

If `diff` prints nothing, the shares contain only what SLIP-0039 prescribes:
the EMS, split with randomness that is a fixed function of the EMS and the
SEED. For another codec, recover the master secret with `-c base16` and use
that as input. `test-verify.sh` runs a number of such comparisons.

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

## Specification

`doc/slip-0039.md` is the current specification, `doc/slip-0039-deprecated.md`
is the version from before the extendable backup flag was added in May 2024.

## Features

* Attempts are made to wipe all sensitive data from memory upon termination.

* Data is locked memory so that it does not get swapped out to disk.

* The program is constructed such that the amount of data that is needlessly
  rearranged and copied around is reduced.

* The output of the program is deterministic, so that the output can be
  reproduced on multiple machines and it is easy to see that the random data in
  the shares and in the second part of the digest share contains no information.

* Sensitive data should be handled in constant time.

## Testsuite

The original test-suite is included as the first 40 entries of vectors.json and can
be checked by running `./test.sh` or `make test`

Test 41 can detect certain errors in modular arithmetic.

Tests 42 to 45 use extendable shares, added to the specification in May 2024.

`./test-verify.sh` checks that `verify.py` reproduces the shares of `split`.

## Portability

The program is known to work on Linux and MacOS. Issues pertaining to MacOS not having mlockall() have been fixed.

## Authors

The project was started by Rik Snel (https://github.com/rsnel/). MacOS compatibility and various fixes were offered by James Z.M. Gao  (https://github.com/gzm55).

The sha256 code is copyright (c) 2014 The Bitcoin Core developers under the MIT license.

The utf8 code is:

* Copyright (c) 2014-2021 Steven G. Johnson, Jiahao Chen, Peter Colberg, Tony Kelman, Scott P. Jones, and other contributors.

* Copyright (c) 2009 Public Software Group e. V., Berlin, Germany

under the MIT license.

Wordlists:

diceware English

diceware German

## Examples

Example split `MS = 000000000000000000000000000000`, `SEED = fdsaludskj` with debug output:

    $ slip0039 split -d fdsaludskj 0 4 2of3 5of10 1of1 7of14 << EOF
    TREZOR
    00000000000000000000000000000000
    EOF
    ladybug academic adult roster cubic verify detailed aquatic smoking literary tadpole mineral party garlic enemy window peaceful custody warn slap
    ladybug academic adult scared capture surface station should decrease patent likely slice element olympic true reward subject geology fluff dynamic
    ladybug academic adult shadow average peaceful vexed deal finance silver grocery disaster together lift campus install boundary vexed wolf ruin
    ladybug academic benefit ruin clothes adequate damage champion nervous charity express document upstairs march midst airport merchant payroll counter tidy
    ladybug academic benefit scholar cover script income crush empty making leaf earth curious course bumpy human critical daisy rumor hunting
    ladybug academic benefit shaped club cause coal public modify junction parking snake theory salt unknown again losing fragment ancient smirk
    ladybug academic benefit slap actress wrote lobe discuss subject perfect hospital join impulse belong replace forget execute pregnant general hawk
    ladybug academic benefit sniff analysis valid remove angel tolerate welfare devote oral learn sprinkle medal detailed owner snapshot dream cargo
    ladybug academic benefit spine early hand fortune resident security imply express facility inmate failure papa national edge oven airline party
    ladybug academic benefit stilt behavior advocate mayor vintage employer crush hazard science device blind phantom perfect admit peanut modify material
    ladybug academic benefit swing apart legs mineral rumor valuable snapshot behavior phantom market together findings deploy problem merit course carve
    ladybug academic benefit teaspoon cage infant dramatic client prisoner ecology carpet plot various screw tackle carbon welfare pile arena merit
    ladybug academic benefit thunder beaver quick garden material surface premium submit evening velvet clinic strategy squeeze burning lilac increase visual
    ladybug academic chubby romp dance swimming replace shaft peaceful escape jewelry fact corner thorn music human wrap vampire fragment carbon
    ladybug academic depart rumor clogs grill answer thank rich unwrap hormone task slow lift discuss august depend usual human memory
    ladybug academic depart scout alcohol ocean cultural aluminum revenue filter writing stick location soul velvet omit testify fumes erode famous
    ladybug academic depart shelter amuse gather glad says believe extra garlic dress guilt moment hamster quantity legend machine sled pajamas
    ladybug academic depart sled depart necklace picture smart display pencil alcohol aviation remove aunt spray adult class wrote knife race
    ladybug academic depart software dance careful submit nervous beaver wisdom client stadium prize width twin lunar station laden regret juice
    ladybug academic depart spit average nail endless pumps mule robin resident dynamic plunge hairy orange depict curly tension float have
    ladybug academic depart strategy dough branch license revenue mother guilt victim jacket scout merit parking review headset percent bucket huge
    ladybug academic depart symbolic afraid much wisdom improve downtown gravity orbit petition flip shaft pants crisis testify theory herd rapids
    ladybug academic depart tenant damage item yelp taxi breathe source nail slush criminal frost literary exhaust library retreat armed junk
    ladybug academic depart tidy champion glad grownup stadium alto adjust birthday glen scandal disaster execute photo failure nuclear ceramic provide
    ladybug academic depart trend dish syndrome inside blue clinic campus making style undergo unhappy arcade slap tackle raisin grin romp
    ladybug academic depart undergo daisy rumor artwork scroll being lift zero elephant nylon ecology puny alive laser entrance task safari
    ladybug academic depart valuable desktop tenant that crystal spend very dress describe civil gross fatal decision grumpy lamp unhappy should
    ladybug academic depart violence dive mayor rumor stick express submit prospect involve legs ruler clock yield oven hearing already sister
    slip0039:debug:---START---internal slip0039 data----
    slip0039:debug:size of master secret=16 bytes
    slip0039:debug:Identifier=0x3f00
    slip0039:debug:Iteration exponent=0 (2500 iterations per round)
    slip0039:debug:/    count= 4 available= 4 threshold= 4  (ladybug academic)
    slip0039:debug:/0/  count= 3 available= 3 threshold= 2   (adult)
    slip0039:debug:/0/0   b3f38d50c7408577c91e886051bfb68d    (roster)
    slip0039:debug:/0/1   79dbf5fca4c7a260fcdd0c9c3acbdf69    (scared)
    slip0039:debug:/0/2   3ca37d130155cb59a3839b838757645e    (shadow)
    slip0039:debug:/0/?   ffb04823d369bbc2691db895f41ef4b0
    slip0039:debug:/0/S   3598308fb0ee9cd55cde3c699f6a9d54
    slip0039:debug:/1/  count=10 available=10 threshold= 5   (benefit)
    slip0039:debug:/1/0   98020ba2166221d3f3a7c18ca4405a40    (ruin)
    slip0039:debug:/1/1   a4c65cd2c5178ae013f8b528c6c6f4ad    (scholar)
    slip0039:debug:/1/2   992049bb0e4e7aa87d0b8fc2fbd0421b    (shaped)
    slip0039:debug:/1/3   06fea1938769a51ba799cb12eeb5a938    (slap)
    slip0039:debug:/1/4   26f16e70ab9cfa4d89ca02d623b3567b    (sniff)
    slip0039:debug:/1/5   fd6996cbbf1e7253f50dd65168497d04    (spine)
    slip0039:debug:/1/6   4803a39f55162c5acc54d715e97a500a    (stilt)
    slip0039:debug:/1/7   3081e47c1bc6d0c48a5e33e6d5633ebb    (swing)
    slip0039:debug:/1/8   72748f024ab840c7eaabc9c637a1ebe9    (teaspoon)
    slip0039:debug:/1/9   45b39808db6fac76a4bbcb25366d686f    (thunder)
    slip0039:debug:/1/?   0bcf1beb0aaa14a35ddbdc712795a848
    slip0039:debug:/1/S   873b207a9511a368b31889c92fdfe04f
    slip0039:debug:/2/  count= 1 available= 1 threshold= 1   (chubby)
    slip0039:debug:/2/0   bbdceebc8a8d4a9e5510a0e465c6f7f7    (romp)
    slip0039:debug:/2/S   bbdceebc8a8d4a9e5510a0e465c6f7f7
    slip0039:debug:/3/  count=14 available=14 threshold= 7   (depart)
    slip0039:debug:/3/0   966602de32faefdb9dfb39838e10e8cd    (rumor)
    slip0039:debug:/3/1   1a9b8b4082f5553f9d8e1ad27cb9c78a    (scout)
    slip0039:debug:/3/2   2560d8ac3c4a505813c9a1941a5b3206    (shelter)
    slip0039:debug:/3/3   cc9829dcece5a481a0f6e70ef570308f    (sled)
    slip0039:debug:/3/4   bb1f36a98845fc092d6ebafafaf87f5f    (software)
    slip0039:debug:/3/5   3c97919b1658bf6ef3f2ab69273338b6    (spit)
    slip0039:debug:/3/6   ed1820dbd653687d278f1690687bd9ad    (strategy)
    slip0039:debug:/3/7   0f95ff0728ee65274a5962c8a832b38a    (symbolic)
    slip0039:debug:/3/8   ba787fce0462d2a5ece8ab5da154ea0c    (tenant)
    slip0039:debug:/3/9   856299dd6c1f024516371038138a6545    (tidy)
    slip0039:debug:/3/A   e3de1d8160941d62bda3b6ee432cd37a    (trend)
    slip0039:debug:/3/B   b9c1837c684983bff4366840ec7071fd    (undergo)
    slip0039:debug:/3/C   d3e1b8d2cb50f3cf23408e66d4e3119e    (valuable)
    slip0039:debug:/3/D   e78e706d8d3fdaac077607c1495ff679    (violence)
    slip0039:debug:/3/?   87b5ac71bd9c550f90814d5c4b054fe4
    slip0039:debug:/3/S   0971836d200977a0737dcda759510dca
    slip0039:debug:/?     c282dcebcb07e251d6c4dff4871476c3
    slip0039:debug:/S     704f8961a3517062e43073980c32c40a
    slip0039:debug:/P     00000000000000000000000000000000
    slip0039:debug:---END-----internal slip0039 data----

Example Recover with debug output:

    $ slip0039 -d << EOF
    TREZOR
    ladybug academic adult roster cubic verify detailed aquatic smoking literary tadpole mineral party garlic enemy window peaceful custody warn slap
    ladybug academic adult scared capture surface station should decrease patent likely slice element olympic true reward subject geology fluff dynamic
    ladybug academic benefit ruin clothes adequate damage champion nervous charity express document upstairs march midst airport merchant payroll counter tidy
    ladybug academic benefit scholar cover script income crush empty making leaf earth curious course bumpy human critical daisy rumor hunting
    ladybug academic benefit shaped club cause coal public modify junction parking snake theory salt unknown again losing fragment ancient smirk
    ladybug academic benefit slap actress wrote lobe discuss subject perfect hospital join impulse belong replace forget execute pregnant general hawk
    ladybug academic benefit sniff analysis valid remove angel tolerate welfare devote oral learn sprinkle medal detailed owner snapshot dream cargo
    ladybug academic chubby romp dance swimming replace shaft peaceful escape jewelry fact corner thorn music human wrap vampire fragment carbon
    ladybug academic depart rumor clogs grill answer thank rich unwrap hormone task slow lift discuss august depend usual human memory
    ladybug academic depart scout alcohol ocean cultural aluminum revenue filter writing stick location soul velvet omit testify fumes erode famous
    ladybug academic depart shelter amuse gather glad says believe extra garlic dress guilt moment hamster quantity legend machine sled pajamas
    ladybug academic depart sled depart necklace picture smart display pencil alcohol aviation remove aunt spray adult class wrote knife race
    ladybug academic depart software dance careful submit nervous beaver wisdom client stadium prize width twin lunar station laden regret juice
    ladybug academic depart spit average nail endless pumps mule robin resident dynamic plunge hairy orange depict curly tension float have
    ladybug academic depart strategy dough branch license revenue mother guilt victim jacket scout merit parking review headset percent bucket huge
    EOF
    00000000000000000000000000000000
    slip0039:debug:---START---internal slip0039 data----
    slip0039:debug:size of master secret=16 bytes
    slip0039:debug:Identifier=0x3f00
    slip0039:debug:Iteration exponent=0 (2500 iterations per round)
    slip0039:debug:/    count= 4 available= 4 threshold= 4  (ladybug academic)
    slip0039:debug:/0/  count= ? available= 2 threshold= 2   (adult)
    slip0039:debug:/0/0   b3f38d50c7408577c91e886051bfb68d    (roster)
    slip0039:debug:/0/1   79dbf5fca4c7a260fcdd0c9c3acbdf69    (scared)
    slip0039:debug:/0/?   ffb04823d369bbc2691db895f41ef4b0 
    slip0039:debug:/0/S   3598308fb0ee9cd55cde3c699f6a9d54 
    slip0039:debug:/1/  count= ? available= 5 threshold= 5   (benefit)
    slip0039:debug:/1/0   98020ba2166221d3f3a7c18ca4405a40    (ruin)
    slip0039:debug:/1/1   a4c65cd2c5178ae013f8b528c6c6f4ad    (scholar)
    slip0039:debug:/1/2   992049bb0e4e7aa87d0b8fc2fbd0421b    (shaped)
    slip0039:debug:/1/3   06fea1938769a51ba799cb12eeb5a938    (slap)
    slip0039:debug:/1/4   26f16e70ab9cfa4d89ca02d623b3567b    (sniff)
    slip0039:debug:/1/?   0bcf1beb0aaa14a35ddbdc712795a848 
    slip0039:debug:/1/S   873b207a9511a368b31889c92fdfe04f 
    slip0039:debug:/2/  count= ? available= 1 threshold= 1   (chubby)
    slip0039:debug:/2/0   bbdceebc8a8d4a9e5510a0e465c6f7f7    (romp)
    slip0039:debug:/2/S   bbdceebc8a8d4a9e5510a0e465c6f7f7 
    slip0039:debug:/3/  count= ? available= 7 threshold= 7   (depart)
    slip0039:debug:/3/0   966602de32faefdb9dfb39838e10e8cd    (rumor)
    slip0039:debug:/3/1   1a9b8b4082f5553f9d8e1ad27cb9c78a    (scout)
    slip0039:debug:/3/2   2560d8ac3c4a505813c9a1941a5b3206    (shelter)
    slip0039:debug:/3/3   cc9829dcece5a481a0f6e70ef570308f    (sled)
    slip0039:debug:/3/4   bb1f36a98845fc092d6ebafafaf87f5f    (software)
    slip0039:debug:/3/5   3c97919b1658bf6ef3f2ab69273338b6    (spit)
    slip0039:debug:/3/6   ed1820dbd653687d278f1690687bd9ad    (strategy)
    slip0039:debug:/3/?   87b5ac71bd9c550f90814d5c4b054fe4 
    slip0039:debug:/3/S   0971836d200977a0737dcda759510dca 
    slip0039:debug:/?     c282dcebcb07e251d6c4dff4871476c3 
    slip0039:debug:/S     704f8961a3517062e43073980c32c40a 
    slip0039:debug:/P     00000000000000000000000000000000 
    slip0039:debug:---END-----internal slip0039 data----

