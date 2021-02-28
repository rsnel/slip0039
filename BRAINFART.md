This implementation of slip0039 stores 128 + a multiple of 16 bits. It is
currently limited to 512 bits to allow the storage (root) xpubs and xprvs.

But what if we want to store structured data? Like a BIP39 mnemonic sentence of
24 words? Or a diceware mnemomic sentence?

BIP39
~~~~~

A 24 word BIP39 mnemonic sentence contains 256 bits of entropy and a checksum
of 8 bits. To store such a mnemonic sentence, we just store the entropy and
recompute the checksum as needed.

All the other sizes of BIP39 mnemonic sentences also correspond to supported
slip0039 data sizes.

In this way, every passphrase will result in an equally likeley and valid BIP39
mnemonic seed. The result of typing the 'right' passphrase is not discernible
to typing another passphrase.

diceware
~~~~~~~~

Each word in a diceware password contains log2(6^5) = 12.92... bits of entropy.
This is not an integer, so we need a bignum-like implementation to convert it
to a binary number.

Furthermore, the lengths supported by diceware (5 to 20 inclusive as the
minimum recommended length is 5 words and 20 words provides >= 256 bits of
security) do not correspond to the lengths supported by slip0039. This means
that the length of the diceware password also must be encoded in the data.

Since the minimum amount of data encoded in slip0039 is 128 bits, we need to be
able to encode 5 different lengths of diceware passphrases in that case.

 5 to  9 words: log2((6^5)^9 \*5) = 118.64... <= 128 bits
10 to 11 words: log2((6^5)^11\*2) = 143.17... <= 144 bits
12 words:       log2((6^5)^12)    = 155.09... <= 160 bits
13 words:       log2((6^5)^13)    = 168.02... <= 176 bits
14 words:       log2((6^5)^14)    = 180.94... <= 192 bits
15 to 16 words: log2((6^5)^16\*2) = 207.79... <= 208 bits
17 words:       log2((6^5)^17)    = 219.72... <= 224 bits
18 words:       log2((6^5)^18)    = 232.64... <= 240 bits
19 words:       log2((6^5)^19)    = 245.57... <= 256 bits
20 words:       log2((6^5)^20)    = 258,49... <= 272 bits

What we want is that every passphrase yields a possible diceware passphrase,
with a 'uniform distribution'. Also, the passphrase that pops up when the
'correct' passphrase is typed should look no different than the others.

To get these properties we take several steps.

Let's begin with as simple example. Let us assume we want to store one of the
numbers 0, 1, 2, 3, 4 (we call this number x), but we are required to use 128 
bits to store it. 

First try:

Just store the numbers 0, 1, 2, 3, 4. When the correct passphrase, there is no
problem. But when a random passphrase is given, the chances of the output being
in the range 0..4 will be astronomically small. To reject such passphrases
means giving up plausible deniability.

Second try:

Suppose that x is uniform in 0 to 4 (inclusive) Now select a random y with 125
bits and compute z = y + (x<<125). Now z is uniform in 0 to 4<<125+(2^126-1)
(inclusive).  We can just store this and be done. Now the chance of a
passphrase being rejected is < .5.  This is better, but not good enough. The
user should be completely free to choose an alternate passphrase and use the
output for something else than their main secret. Every passphrase should work.

Third try:

Introduce an pseudorandom shuffle function. When a passphrase yields an output
that is too large, just apply this function until the output is in range and
then decode it.  This sounds reasonable, but in this scheme using the decoder
means that it was not the real passphrase.

Fourth try:

Decode in the same way as in the third try, but do something at the encoding
side.

Make the pseudorandom function reversible and (when the (repeated) application
of the inverse yields an out-of-range value, then apply it a couple of times).
This will be undone at decoding time.

This is still not good enough. Assume that the valid codes represent fraction p
of the total possilbe words. There is a chance p that application of the
reverse yields a valid value, so in this case we can't produce an non-valid
value using our pseudorandom function. This does not seem a to be a problem,
because there is still a probability 1-p that we can, but this means that the
real passphrase can never yield a valid value that would become invalid after
application of the reverse without skewing the probabilities.

Fifth try:

Decide (based on provided entropy) if we want to encode a valid value in
slip0039 or a value that is too high. When valid: just use the one that was
just encoded.  When invalid:
- if application of the reverse yields an invalid value: take a random invalid
  output from the list using the uniform distribution
- if application of the reverse yields an in-range value: change the input
  somewhat and retry application of the reverse


