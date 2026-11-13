// js.js - check that doc/slip0039.js, the JavaScript port that the website
// uses, gives the same shares as slip0039 split, and recovers the same
// secrets with the right and with wrong passphrases
//
// usage: node tests/js.js (in the top directory, after make)

"use strict";

const { execFileSync } = require("child_process");
const SLIP0039 = require("../doc/slip0039.js");

const SEED = "gUaRlvJDNiDFTjrJfmghruaDh47Tnm9jZCnTBnFZI5axMqxxry6j3zys1Fz67kgx";

function slip0039(args, input) {
	return execFileSync("./slip0039", ["-q"].concat(args),
		{ input: input, encoding: "utf8" }).trim();
}

/* [codec as in -c without the count, secret, count, e, gt, groups] */
const CASES = [
	["base16", "00000000000000000000000000000000", 0, 0, 1, [[1, 1]]],
	["base16", "b57d229378164c7c82e3426d0f953aa12cefcfb19b8ac9bb5a80508fa8d64c1c", 0, 1, 2, [[2, 3], [3, 5], [1, 1]]],
	["base16", "0011 2233 4455 6677 8899 AABB CCDD EEFF", 0, 0, 1, [[2, 3]]],
	["numeric", "012345", 6, 0, 1, [[2, 3]]],
	["numeric", "0".repeat(60), 60, 0, 1, [[1, 1]]],
	["password", "aB3dE5gH7jK9mN1pQ3sT", 20, 0, 2, [[1, 1], [2, 2]]],
	["password:alpha", "abcdefGHIJKL", 12, 0, 1, [[1, 1]]],
	["password:lower", "abcdefghijklmnopqrstuvwxyzabcd", 30, 0, 1, [[1, 1]]],
	["password:ascii", "a\"b\\c$d%e&f(g)h*", 16, 0, 1, [[1, 1]]],
	["totp", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", 32, 0, 1, [[2, 3]]],
	["totp", "jbsw y3dp ehpk 3pxp jbsw y3dp ee", 26, 0, 1, [[1, 1]]],
];

async function main() {
	let passed = 0, failed = 0;
	function expect(name, expected, got) {
		if (expected === got) passed++;
		else {
			failed++;
			console.log("FAILED: " + name);
			console.log("  expected: " + expected);
			console.log("  got:      " + got);
		}
	}

	for (const [codec, secret, count, e, gt, groups] of CASES) {
		const c = codec === "base16" ? "base16" :
			(codec.includes(":") ? codec + ":" : codec + "::") + count;
		const args = ["-c", c, "split", String(e), String(gt)].concat(
			groups.map(g => g[0] + "of" + g[1]));
		const name = c + " " + args.slice(2).join(" ");
		const ms = await SLIP0039.encodeSecret(codec, secret, SEED);
		const r = await SLIP0039.split({ passphrase: "TREZOR", seed: SEED,
			ms: ms, e: e, gt: gt, groups: groups });
		const js = r.shares.map(sh => sh.words).join("\n");
		const shares = slip0039(args, "TREZOR\n" + SEED + "\n" + secret + "\n");
		expect("split " + name, shares, js);

		for (const p of ["TREZOR", "wrong", ""]) {
			const rec = await SLIP0039.recover(r, r.shares, p);
			const got = SLIP0039.decodeSecret(codec, rec.ms, count);
			const want = slip0039(["-c", c], p + "\n" + shares + "\n");
			expect("recover " + name + " with \"" + p + "\"", want, got);
		}
	}

	console.log("js: passed " + passed + "/" + (passed + failed) + " tests");
	process.exit(failed ? 1 : 0);
}

main().catch(e => { console.log(e); process.exit(1); });
