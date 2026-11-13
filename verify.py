#!/usr/bin/env python3
# verify.py - independently reproduce the shares created by slip0039 split
#
# Copyright 2026 Rik Snel <rik@snel.it>
#
# This file is part of slip0039.
#
# slip0039 is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# slip0039 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with slip0039.  If not, see <https://www.gnu.org/licenses/>.
"""Reproduce the shares that `slip0039 split` creates, using only the
Python standard library, to show that slip0039 is deterministic and that
its shares contain nothing but what SLIP-0039 prescribes.

Usage (same input and arguments as slip0039 split):

    printf 'PASSPHRASE\\nSEED\\nMASTER_SECRET\\n' |
        ./verify.py [-c CODEC] [--gain GAIN] [--pre-may-2024] [-v] \\
            EXP GT XofY...

The output is identical to that of slip0039 split, so

    ./slip0039 split 1 2 2of3 3of5 < input > shares
    ./verify.py 1 2 2of3 3of5 < input | diff - shares

prints nothing if the shares are reproduced. All codecs of slip0039 are
supported, with the same -c argument; for the honey encoded codecs
(diceware, password, numeric and totp) this also shows that the master
secret is k + j*r, where k is the secret, j the number of possible
secrets and r a number that is derived from the SEED only.

The computation has two stages, which only meet in the EMS:

1. encrypt(): the master secret and the passphrase give the encrypted
   master secret (EMS), exactly as specified by SLIP-0039; this is the only
   place where the master secret and the passphrase are used

2. everything else is a function of the EMS, the SEED and the description
   of the split, nothing else: the identifier is taken from SHA256(SEED),
   and all randomness that SLIP-0039 calls for (the random part of the
   digests and the random shares) is taken, in a fixed order, from

       PBKDF2-HMAC-SHA256(password = EMS || SEED,
                          salt = e || GT || G || T_1 || N_1 ... T_G || N_G,
                          iterations = 1)

   (all numbers in the salt are single bytes); with 1 iteration, block i
   of this stream is HMAC-SHA256(EMS || SEED, salt || i), so it is a
   pseudorandom function of the secret key EMS || SEED: computing the EMS
   (or anything else about the key) from these bytes is as hard as
   breaking HMAC-SHA256, unless the key can be guessed
"""

import hashlib
import hmac
import os
import re
import sys
import unicodedata

WORDLISTS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
        "wordlists")
WORDLIST = os.path.join(WORDLISTS, "wordlist_slip0039.txt")

# GF(256) with the polynomial x^8 + x^4 + x^3 + x + 1, as in SLIP-0039

EXP = [0]*255
LOG = [0]*256
x = 1
for i in range(255):
    EXP[i] = x
    LOG[x] = i
    x ^= x << 1             # multiply by the generator 3
    if x & 0x100:
        x ^= 0x11b

def gf_mul(a, b):
    return 0 if a == 0 or b == 0 else EXP[(LOG[a] + LOG[b]) % 255]

def gf_div(a, b):
    return 0 if a == 0 else EXP[(LOG[a] - LOG[b]) % 255]

def interpolate(points, x):
    """value at x of the polynomial through points [(x_i, bytes_i)]"""
    n = len(points[0][1])
    out = bytearray(n)
    for i, (xi, yi) in enumerate(points):
        # Lagrange basis polynomial of point i, evaluated at x
        basis = 1
        for j, (xj, _) in enumerate(points):
            if j != i:
                basis = gf_mul(basis, gf_div(x ^ xj, xi ^ xj))
        for k in range(n):
            out[k] ^= gf_mul(basis, yi[k])
    return bytes(out)

# stage 1: the encryption of SLIP-0039

def encrypt(ms, passphrase, identifier, ext, e):
    """4 round Feistel network with PBKDF2-HMAC-SHA256 as round function"""
    salt = b"" if ext else b"shamir" + identifier.to_bytes(2, "big")
    half = len(ms)//2
    left, right = ms[:half], ms[half:]
    for i in range(4):
        f = hashlib.pbkdf2_hmac("sha256", bytes([i]) + passphrase,
                salt + right, 2500 << e, half)
        left, right = right, bytes(a ^ b for a, b in zip(left, f))
    return right + left

# stage 2: from the EMS to the shares

class Stream:
    """the bytes of a PBKDF2 output, consumed from the start"""
    def __init__(self, password, salt, length):
        # if all thresholds are 1, no randomness is needed
        self.data = hashlib.pbkdf2_hmac("sha256", password, salt, 1,
                length) if length else b""
        self.pos = 0
    def take(self, n):
        self.pos += n
        assert self.pos <= len(self.data)
        return self.data[self.pos - n:self.pos]

def split_secret(threshold, count, secret, rng):
    """SplitSecret of SLIP-0039, with rng as source of randomness"""
    n = len(secret)
    if threshold == 1:
        return [secret]*count
    r = rng.take(n - 4)
    digest = hmac.new(r, secret, hashlib.sha256).digest()[:4] + r
    shares = [rng.take(n) for _ in range(threshold - 2)]
    points = list(enumerate(shares)) + [(254, digest), (255, secret)]
    for i in range(threshold - 2, count):
        shares.append(interpolate(points, i))
    return shares

def random_bytes_needed(n, gt, groups):
    sets = [(gt, len(groups))] + groups
    return sum(n - 4 + (t - 2)*n for t, _ in sets if t > 1)

def split(ems, seed, e, gt, groups):
    """all shares, group by group, as [(group index, member index, share)]"""
    n = len(ems)
    salt = bytes([e, gt, len(groups)] + [v for g in groups for v in g])
    rng = Stream(ems + seed, salt, random_bytes_needed(n, gt, groups))
    group_shares = split_secret(gt, len(groups), ems, rng)
    member_shares = [split_secret(t, c, group_shares[i], rng)
            for i, (t, c) in enumerate(groups)]
    assert rng.pos == len(rng.data)
    return [(i, j, s) for i, shares in enumerate(member_shares)
            for j, s in enumerate(shares)]

# the codecs: from the master secret as it is given to the master secret
# of SLIP-0039 (bytes)

def fatal(msg):
    sys.exit("verify.py: " + msg)

def read_wordlist(family, language=""):
    name = "wordlist_" + family + ("_" + language if language else "")
    with open(os.path.join(WORDLISTS, name + ".txt"), encoding="utf-8") as f:
        # a trailing space is not part of a word (diceware dutch)
        return [w.rstrip(" ") for w in f.read().split("\n")[:-1]]

def ascii_lower(text):
    return "".join(c.lower() if "A" <= c <= "Z" else c for c in text)

def words_of(text, words):
    """split a secret of words like slip0039 does: Unicode NFKD, runs of
    spaces, tabs and CRs are one separator, lower case if the wordlist
    has no upper case letters"""
    text = unicodedata.normalize("NFKD", text)
    if not any("A" <= c <= "Z" for w in words for c in w):
        text = ascii_lower(text)
    return [w for w in re.split("[ \t\r]+", text) if w]

def lookup(words, word, prefix=0):
    """index of word (the first if it occurs more than once), a word
    may be given by its first prefix (or more) letters if prefix > 0"""
    norm = [unicodedata.normalize("NFKD", w) for w in words]
    for i, w in enumerate(norm):
        if w == word or (prefix and len(word) >= prefix and
                w.startswith(word)):
            return i
    fatal("word '%s' not found" % word)

def bit_length_extra(gain):
    """honey_extra_bits() of honey.c"""
    bits = 0
    while 2**bits < 1/gain + 1:
        bits += 1
    return bits

def modular(digits, m, seed, gain):
    """the modular DTE of honey.c: the secret k (the digits in base m,
    most significant first) is stored as x = k + j*r, with j = m^count
    and 0 <= x < 2^n; r is uniform on the possible values, which are one
    more for k < t, the randomness comes from the SEED only"""
    j = m**len(digits)
    k = 0
    for d in digits:
        k = k*m + d
    bits = max(128, j.bit_length() + bit_length_extra(gain))
    bits = (bits + 15)//16*16
    if bits > 512:
        fatal("the secret does not fit in a master secret of 512 bits")
    L = bits//8
    u = int.from_bytes(hashlib.pbkdf2_hmac("sha256", b"honey", seed, 1, L),
            "big")
    R, t = divmod(2**bits, j)
    r = u % (R + 1) if k < t else u % R
    return (k + j*r).to_bytes(L, "big")

def base16(text, arg, seed, gain, language):
    text = ascii_lower(re.sub("[ \t]", "", text))
    if not re.fullmatch("[0-9a-f]*", text) or len(text) % 4:
        fatal("master secret must be hexadecimal, a multiple of 16 bits")
    ms = bytes.fromhex(text)
    if len(ms) < 16:
        fatal("master secret must be at least 16 bytes")
    return ms

def bip39(text, arg, seed, gain, language):
    words = read_wordlist("bip39", language or "english")
    idx = [lookup(words, w, 4 if (language or "english") == "english" else 0)
            for w in words_of(text, words)]
    if len(idx) not in (12, 15, 18, 21, 24):
        fatal("a BIP39 mnemonic has 12, 15, 18, 21 or 24 words")
    v = 0
    for i in idx:
        v = v << 11 | i
    cs = len(idx)//3
    entropy = (v >> cs).to_bytes(len(idx)*4//3, "big")
    if hashlib.sha256(entropy).digest()[0] >> (8 - cs) != v & (2**cs - 1):
        fatal("invalid BIP39 mnemonic, checksum does not match")
    return entropy

def symbols(family, default, spaced):
    def codec(text, arg, seed, gain, language):
        words = read_wordlist(family, language or default)
        if spaced:
            digits = [lookup(words, w) for w in words_of(text, words)]
        else:
            digits = [lookup(words, c) for c in text]
        if len(digits) != int(arg):
            fatal("the secret has %d symbols, -c specifies %s" %
                    (len(digits), arg))
        return modular(digits, len(words), seed, gain)
    return codec

B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

def totp(text, arg, seed, gain, language):
    text = re.sub("[ =]", "", text).upper()
    if len(text) != int(arg):
        fatal("the TOTP secret has %d characters, -c specifies %s" %
                (len(text), arg))
    v = 0
    for c in text:
        v = v << 5 | B32.index(c)
    n = 5*len(text)//8
    p = 5*len(text) - 8*n
    if v & (2**p - 1):
        fatal("the unused bits of the last character are not zero")
    return modular(list((v >> p).to_bytes(n, "big")), 256, seed, gain)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

def base58check(text, length):
    v = 0
    for c in text:
        v = v*58 + B58.index(c)
    data = v.to_bytes(length, "big")
    if hashlib.sha256(hashlib.sha256(data[:-4]).digest()).digest()[:4] != \
            data[-4:]:
        fatal("invalid base58check string, checksum does not match")
    return data

def private_key(key):
    if not 0 < int.from_bytes(key, "big") < ORDER:
        fatal("the private key is not in the range [1, n-1]")
    return key

BIP32_VERSIONS = { "xprv": 0x0488ade4, "yprv": 0x049d7878,
        "zprv": 0x04b2430c, "Yprv": 0x0295b005, "Zprv": 0x02aa7a99,
        "tprv": 0x04358394, "uprv": 0x044a4e28, "vprv": 0x045f18bc,
        "Uprv": 0x024285b5, "Vprv": 0x02575048 }

def bip32(text, arg, seed, gain, language):
    key = base58check(text, 82)
    if int.from_bytes(key[:4], "big") != BIP32_VERSIONS[arg]:
        fatal("the version of the extended key is not " + arg)
    if any(key[4:13]) or key[45]:
        fatal("not a root extended private key")
    return private_key(key[46:78]) + key[13:45]

WIF_TYPES = { "compressed": (0x80, 1), "uncompressed": (0x80, 0),
        "testnet-compressed": (0xef, 1), "testnet-uncompressed": (0xef, 0) }

def wif(text, arg, seed, gain, language):
    version, compressed = WIF_TYPES[arg]
    key = base58check(text, 37 + compressed)
    if key[0] != version or (compressed and key[33] != 1):
        fatal("the WIF key is not of type " + arg)
    return private_key(key[1:33])

B32L = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    gen = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk

def nostr(text, arg, seed, gain, language):
    if text != text.lower() and text != text.upper():
        fatal("nostr private key mixes upper and lower case")
    text = text.lower()
    if not text.startswith("nsec1") or len(text) != 5 + 52 + 6:
        fatal("not a nostr private key")
    data = [B32L.index(c) for c in text[5:]]
    hrp = [ord(c) >> 5 for c in "nsec"] + [0] + [ord(c) & 31 for c in "nsec"]
    if bech32_polymod(hrp + data) != 1:
        fatal("invalid nostr private key, checksum does not match")
    v = 0
    for d in data[:52]:
        v = v << 5 | d
    if v & 15:
        fatal("the padding bits are not zero")
    return private_key((v >> 4).to_bytes(32, "big"))

# codex32 (BIP-0093), the generators and constants of the regular and the
# long checksum, the residue starts with the value of the prefix "ms"
MS32 = { 13: (65, (0x19dc500ce73fde210, 0x1bfae00def77fe529,
            0x1fbd920fffe7bee52, 0x1739640bdeee3fdad, 0x07729a039cfc75f5a),
            0x10ce0795c2fd1e62a),
        15: (75, (0x3d59d273535ea62d897, 0x7a9becb6361c6c51507,
            0x543f9b7e6c38d8a2a0e, 0x0c577eaeccf1990d13c,
            0x1887f74f8dc71b10651), 0x43381e570bf4798ab26) }

def ms32_polymod(values, variant):
    bits, gen, _ = MS32[variant]
    residue = 0x23181b3
    for v in values:
        b = residue >> (bits - 5)
        residue = (residue & (2**(bits - 5) - 1)) << 5 ^ v
        for i in range(5):
            residue ^= gen[i] if (b >> i) & 1 else 0
    return residue

def codex32(text, arg, seed, gain, language):
    if text != text.lower() and text != text.upper():
        fatal("codex32 secret mixes upper and lower case")
    text = text.lower()
    if not text.startswith("ms1"):
        fatal("codex32 secret does not start with ms1")
    data = [B32L.index(c) for c in text[3:]]
    variant = 13 if 5 + len(data) <= 93 else 15
    if (variant == 15 and not 96 <= 5 + len(data) <= 1023) or \
            ms32_polymod(data, variant) != MS32[variant][2]:
        fatal("invalid codex32 secret, the checksum does not match")
    if text[3:8] != arg.lower() or text[8] != "s":
        fatal("the header of the codex32 secret is not %ss" % arg)
    payload = data[6:-variant]
    v = 0
    for d in payload:
        v = v << 5 | d
    n = 5*len(payload)//8
    p = 5*len(payload) - 8*n
    if p > 4 or n not in (16, 20, 24, 28, 32, 64):
        fatal("the codex32 secret does not encode a master seed")
    return (v >> p).to_bytes(n, "big")

CODECS = { "base16": base16, "bip39": bip39,
        "diceware": symbols("diceware", "english", True),
        "password": symbols("password", "alnum", False),
        "numeric": symbols("numeric", "", False),
        "totp": totp, "bip32": bip32, "wif": wif, "nostr": nostr,
        "codex32": codex32 }

# the mnemonic format of SLIP-0039

def rs1024_polymod(values):
    gen = (0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009,
            0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120)
    chk = 1
    for v in values:
        b = chk >> 20
        chk = (chk & 0xfffff) << 10 ^ v
        for i in range(10):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk

def mnemonic(words, identifier, ext, e, gi, gt, g, mi, mt, share, pre_may):
    if pre_may:
        header = identifier << 5 | e
    else:
        header = identifier << 5 | ext << 4 | e
    header = header << 16 | gi << 12 | (gt - 1) << 8 | (g - 1) << 4 | mi
    header = header << 4 | (mt - 1)
    no_words = (8*len(share) + 9)//10
    value = int.from_bytes(share, "big")
    data = [header >> 10*(3 - i) & 1023 for i in range(4)]
    data += [value >> 10*(no_words - 1 - i) & 1023 for i in range(no_words)]
    cs = b"shamir_extendable" if ext else b"shamir"
    chk = rs1024_polymod(list(cs) + data + [0, 0, 0]) ^ 1
    data += [chk >> 10*(2 - i) & 1023 for i in range(3)]
    return " ".join(words[d] for d in data)

def main(argv):
    pre_may, verbose, codec, gain, args = False, False, "base16", 0.01, []
    argv = list(argv)
    while argv:
        a = argv.pop(0)
        if a == "--pre-may-2024":
            pre_may = True
        elif a == "-v":
            verbose = True
        elif a == "-q":
            pass
        elif a == "-c" and argv:
            codec = argv.pop(0)
        elif a == "--gain" and argv:
            gain = float(argv.pop(0))
        else:
            args.append(a)
    if args and args[0] == "split":
        args = args[1:]
    if len(args) < 3:
        fatal("usage: verify.py [-c CODEC] [--gain GAIN] [--pre-may-2024] "
                "[-v] [split] EXP GT XofY...")
    e, gt = int(args[0]), int(args[1])
    groups = []
    for spec in args[2:]:
        t, _, c = spec.partition("of")
        groups.append((int(t), int(c)))
    if e > (31 if pre_may else 15) or not 1 <= gt <= len(groups) <= 16:
        fatal("invalid iteration exponent or group threshold")

    name, _, rest = codec.partition(":")
    language, _, arg = rest.partition(":")
    if name not in CODECS:
        fatal("codec %s is not supported" % name)

    # the same input as slip0039 split: three lines, a CR at the end of
    # a line is not part of it
    lines = [l[:-1] if l.endswith(b"\r") else l
            for l in sys.stdin.buffer.read().split(b"\n")]
    if len(lines) < 3:
        fatal("expected passphrase, seed and master secret on stdin")
    passphrase, seed = lines[0], lines[1]
    ms = CODECS[name](lines[2].decode("utf-8"), arg, seed, gain, language)
    if len(ms) < 16 or len(ms) % 2:
        fatal("master secret must be at least 16 bytes, an even number")

    ext = 0 if pre_may else 1
    identifier = int.from_bytes(hashlib.sha256(seed).digest()[:2], "big")
    identifier &= 0x7fff

    # stage 1: the only use of the master secret and the passphrase
    ems = encrypt(ms, passphrase, identifier, ext, e)

    # stage 2: a function of EMS, SEED and the split description
    shares = split(ems, seed, e, gt, groups)

    if verbose:
        print("identifier: %d, EMS: %s" % (identifier, ems.hex()),
                file=sys.stderr)

    with open(WORDLIST) as f:
        words = f.read().split()
    for i, j, share in shares:
        print(mnemonic(words, identifier, ext, e, i, gt, len(groups), j,
                groups[i][0], share, pre_may))

if __name__ == "__main__":
    main(sys.argv[1:])
