This implementation of slip0039 stores 128 + a multiple of 16 bits. It is
currently limited to 512 bits to allow the storage xpubs and xprvs.

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

Furthermore, the lengths supported by diceware (1 to 20 inclusive) do not
correspond to the lengths supported by slip0039. This means that the length of
the diceware password also must be encoded in the data.

Since the minimum amount of data encoded in slip0039 is 128 bits, we need to be
able to encode 5 different lengths of diceware passphrases in that case (we do
not consider passphrases with 1 to 4 words, because the recommended minimum
length is 5 words). 

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

To get these properties we take several steps. Suppose we want to store a 10 word passphrase.


