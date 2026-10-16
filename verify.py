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

Usage (same input and arguments as slip0039 split with the default codec):

    printf 'PASSPHRASE\\nSEED\\nMASTER_SECRET_HEX\\n' |
        ./verify.py [--pre-may-2024] [-v] EXP GT XofY...

The output is identical to that of slip0039 split, so

    ./slip0039 split 1 2 2of3 3of5 < input > shares
    ./verify.py 1 2 2of3 3of5 < input | diff - shares

prints nothing if the shares are reproduced. For a codec other than base16,
recover the master secret with `slip0039 -c base16` and use that.

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
import sys

WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)),
        "wordlists", "wordlist_slip0039.txt")

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

def fatal(msg):
    sys.exit("verify.py: " + msg)

def main(argv):
    pre_may = "--pre-may-2024" in argv
    verbose = "-v" in argv
    args = [a for a in argv if a not in ("--pre-may-2024", "-v")]
    if len(args) < 3:
        fatal("usage: verify.py [--pre-may-2024] [-v] EXP GT XofY...")
    e, gt = int(args[0]), int(args[1])
    groups = []
    for spec in args[2:]:
        t, _, c = spec.partition("of")
        groups.append((int(t), int(c)))
    if e > (31 if pre_may else 15) or not 1 <= gt <= len(groups) <= 16:
        fatal("invalid iteration exponent or group threshold")

    # the same input as slip0039 split: three lines
    lines = sys.stdin.buffer.read().split(b"\n")
    if len(lines) < 3:
        fatal("expected passphrase, seed and master secret on stdin")
    passphrase, seed, ms = lines[0], lines[1], bytes.fromhex(lines[2].decode())
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
