/* slip0039.js - split and recover exactly like slip0039, in plain
 * JavaScript with the Web Crypto API of the browser; next to slip0039 (C)
 * and verify.py (Python) a third implementation, used by the website */
"use strict";

var SLIP0039 = (function () {

var WORDS = (
	"academic acid acne acquire acrobat activity actress adapt adequate adjust " +
	"admit adorn adult advance advocate afraid again agency agree aide " +
	"aircraft airline airport ajar alarm album alcohol alien alive alpha " +
	"already alto aluminum always amazing ambition amount amuse analysis " +
	"anatomy ancestor ancient angel angry animal answer antenna anxiety apart " +
	"aquatic arcade arena argue armed artist artwork aspect auction august " +
	"aunt average aviation avoid award away axis axle beam beard beaver become " +
	"bedroom behavior being believe belong benefit best beyond bike biology " +
	"birthday bishop black blanket blessing blimp blind blue body bolt boring " +
	"born both boundary bracelet branch brave breathe briefing broken brother " +
	"browser bucket budget building bulb bulge bumpy bundle burden burning " +
	"busy buyer cage calcium camera campus canyon capacity capital capture " +
	"carbon cards careful cargo carpet carve category cause ceiling center " +
	"ceramic champion change charity check chemical chest chew chubby cinema " +
	"civil class clay cleanup client climate clinic clock clogs closet clothes " +
	"club cluster coal coastal coding column company corner costume counter " +
	"course cover cowboy cradle craft crazy credit cricket criminal crisis " +
	"critical crowd crucial crunch crush crystal cubic cultural curious curly " +
	"custody cylinder daisy damage dance darkness database daughter deadline " +
	"deal debris debut decent decision declare decorate decrease deliver " +
	"demand density deny depart depend depict deploy describe desert desire " +
	"desktop destroy detailed detect device devote diagnose dictate diet " +
	"dilemma diminish dining diploma disaster discuss disease dish dismiss " +
	"display distance dive divorce document domain domestic dominant dough " +
	"downtown dragon dramatic dream dress drift drink drove drug dryer " +
	"duckling duke duration dwarf dynamic early earth easel easy echo eclipse " +
	"ecology edge editor educate either elbow elder election elegant element " +
	"elephant elevator elite else email emerald emission emperor emphasis " +
	"employer empty ending endless endorse enemy energy enforce engage enjoy " +
	"enlarge entrance envelope envy epidemic episode equation equip eraser " +
	"erode escape estate estimate evaluate evening evidence evil evoke exact " +
	"example exceed exchange exclude excuse execute exercise exhaust exotic " +
	"expand expect explain express extend extra eyebrow facility fact failure " +
	"faint fake false family famous fancy fangs fantasy fatal fatigue favorite " +
	"fawn fiber fiction filter finance findings finger firefly firm fiscal " +
	"fishing fitness flame flash flavor flea flexible flip float floral fluff " +
	"focus forbid force forecast forget formal fortune forward founder " +
	"fraction fragment frequent freshman friar fridge friendly frost froth " +
	"frozen fumes funding furl fused galaxy game garbage garden garlic " +
	"gasoline gather general genius genre genuine geology gesture glad glance " +
	"glasses glen glimpse goat golden graduate grant grasp gravity gray " +
	"greatest grief grill grin grocery gross group grownup grumpy guard guest " +
	"guilt guitar gums hairy hamster hand hanger harvest have havoc hawk " +
	"hazard headset health hearing heat helpful herald herd hesitate hobo " +
	"holiday holy home hormone hospital hour huge human humidity hunting " +
	"husband hush husky hybrid idea identify idle image impact imply improve " +
	"impulse include income increase index indicate industry infant inform " +
	"inherit injury inmate insect inside install intend intimate invasion " +
	"involve iris island isolate item ivory jacket jerky jewelry join judicial " +
	"juice jump junction junior junk jury justice kernel keyboard kidney kind " +
	"kitchen knife knit laden ladle ladybug lair lamp language large laser " +
	"laundry lawsuit leader leaf learn leaves lecture legal legend legs lend " +
	"length level liberty library license lift likely lilac lily lips liquid " +
	"listen literary living lizard loan lobe location losing loud loyalty luck " +
	"lunar lunch lungs luxury lying lyrics machine magazine maiden mailman " +
	"main makeup making mama manager mandate mansion manual marathon march " +
	"market marvel mason material math maximum mayor meaning medal medical " +
	"member memory mental merchant merit method metric midst mild military " +
	"mineral minister miracle mixed mixture mobile modern modify moisture " +
	"moment morning mortgage mother mountain mouse move much mule multiple " +
	"muscle museum music mustang nail national necklace negative nervous " +
	"network news nuclear numb numerous nylon oasis obesity object observe " +
	"obtain ocean often olympic omit oral orange orbit order ordinary organize " +
	"ounce oven overall owner paces pacific package paid painting pajamas " +
	"pancake pants papa paper parcel parking party patent patrol payment " +
	"payroll peaceful peanut peasant pecan penalty pencil percent perfect " +
	"permit petition phantom pharmacy photo phrase physics pickup picture " +
	"piece pile pink pipeline pistol pitch plains plan plastic platform " +
	"playoff pleasure plot plunge practice prayer preach predator pregnant " +
	"premium prepare presence prevent priest primary priority prisoner privacy " +
	"prize problem process profile program promise prospect provide prune " +
	"public pulse pumps punish puny pupal purchase purple python quantity " +
	"quarter quick quiet race racism radar railroad rainbow raisin random " +
	"ranked rapids raspy reaction realize rebound rebuild recall receiver " +
	"recover regret regular reject relate remember remind remove render repair " +
	"repeat replace require rescue research resident response result retailer " +
	"retreat reunion revenue review reward rhyme rhythm rich rival river robin " +
	"rocky romantic romp roster round royal ruin ruler rumor sack safari " +
	"salary salon salt satisfy satoshi saver says scandal scared scatter scene " +
	"scholar science scout scramble screw script scroll seafood season secret " +
	"security segment senior shadow shaft shame shaped sharp shelter sheriff " +
	"short should shrimp sidewalk silent silver similar simple single sister " +
	"skin skunk slap slavery sled slice slim slow slush smart smear smell " +
	"smirk smith smoking smug snake snapshot sniff society software soldier " +
	"solution soul source space spark speak species spelling spend spew spider " +
	"spill spine spirit spit spray sprinkle square squeeze stadium staff " +
	"standard starting station stay steady step stick stilt story strategy " +
	"strike style subject submit sugar suitable sunlight superior surface " +
	"surprise survive sweater swimming swing switch symbolic sympathy syndrome " +
	"system tackle tactics tadpole talent task taste taught taxi teacher " +
	"teammate teaspoon temple tenant tendency tension terminal testify texture " +
	"thank that theater theory therapy thorn threaten thumb thunder ticket " +
	"tidy timber timely ting tofu together tolerate total toxic tracks traffic " +
	"training transfer trash traveler treat trend trial tricycle trip triumph " +
	"trouble true trust twice twin type typical ugly ultimate umbrella uncover " +
	"undergo unfair unfold unhappy union universe unkind unknown unusual " +
	"unwrap upgrade upstairs username usher usual valid valuable vampire " +
	"vanish various vegan velvet venture verdict verify very veteran vexed " +
	"victim video view vintage violence viral visitor visual vitamins vocal " +
	"voice volume voter voting walnut warmth warn watch wavy wealthy weapon " +
	"webcam welcome welfare western width wildlife window wine wireless wisdom " +
	"withdraw wits wolf woman work worthy wrap wrist writing wrote year yelp " +
	"yield yoga zero").split(" ");

var subtle = globalThis.crypto.subtle;
var utf8 = new TextEncoder();

function concat() {
	var n = 0, i, out, pos = 0;
	for (i = 0; i < arguments.length; i++) n += arguments[i].length;
	out = new Uint8Array(n);
	for (i = 0; i < arguments.length; i++) {
		out.set(arguments[i], pos);
		pos += arguments[i].length;
	}
	return out;
}

function toBig(bytes) {
	var x = 0n;
	for (var i = 0; i < bytes.length; i++) x = x << 8n | BigInt(bytes[i]);
	return x;
}

function fromBig(x, len) {
	var out = new Uint8Array(len);
	for (var i = len - 1; i >= 0; i--) {
		out[i] = Number(x & 255n);
		x >>= 8n;
	}
	return out;
}

function hex(bytes) {
	return Array.from(bytes, function (b) {
		return (b < 16 ? "0" : "") + b.toString(16);
	}).join("");
}

function unhex(s) {
	if (!/^([0-9a-fA-F]{2})*$/.test(s)) return null;
	var out = new Uint8Array(s.length / 2);
	for (var i = 0; i < out.length; i++)
		out[i] = parseInt(s.substr(2 * i, 2), 16);
	return out;
}

async function pbkdf2(password, salt, iterations, length) {
	if (!length) return new Uint8Array(0);
	var key = await subtle.importKey("raw", password, "PBKDF2", false,
			["deriveBits"]);
	return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2",
			hash: "SHA-256", salt: salt, iterations: iterations },
			key, 8 * length));
}

async function hmac(key, data) {
	var k = await subtle.importKey("raw", key,
			{ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return new Uint8Array(await subtle.sign("HMAC", k, data));
}

async function sha256(data) {
	return new Uint8Array(await subtle.digest("SHA-256", data));
}

/* GF(256) with the polynomial x^8 + x^4 + x^3 + x + 1 */
var EXP = new Uint8Array(255), LOG = new Uint8Array(256);
(function () {
	var x = 1;
	for (var i = 0; i < 255; i++) {
		EXP[i] = x;
		LOG[x] = i;
		x ^= x << 1;
		if (x & 0x100) x ^= 0x11b;
	}
})();

function gfMul(a, b) {
	return a && b ? EXP[(LOG[a] + LOG[b]) % 255] : 0;
}

function gfDiv(a, b) {
	return a ? EXP[(LOG[a] - LOG[b] + 255) % 255] : 0;
}

/* the value at x of the polynomial through points [[x_i, bytes_i]] */
function interpolate(points, x) {
	var out = new Uint8Array(points[0][1].length);
	points.forEach(function (p, i) {
		var basis = 1;
		points.forEach(function (q, j) {
			if (i !== j) basis = gfMul(basis, gfDiv(x ^ q[0], p[0] ^ q[0]));
		});
		for (var k = 0; k < out.length; k++) out[k] ^= gfMul(basis, p[1][k]);
	});
	return out;
}

/* the 4 round Feistel network of SLIP-0039, rounds 0..3 or 3..0 */
async function feistel(input, passphrase, id, ext, e, rounds) {
	var salt = ext ? new Uint8Array(0) :
		concat(utf8.encode("shamir"), new Uint8Array([id >> 8, id & 255]));
	var half = input.length / 2;
	var l = input.slice(0, half), r = input.slice(half);
	for (var i = 0; i < 4; i++) {
		var f = await pbkdf2(concat(new Uint8Array([rounds[i]]), passphrase),
				concat(salt, r), 2500 << e, half);
		var t = r;
		r = l.map(function (b, k) { return b ^ f[k]; });
		l = t;
	}
	return concat(r, l);
}

function encrypt(ms, passphrase, id, ext, e) {
	return feistel(ms, passphrase, id, ext, e, [0, 1, 2, 3]);
}

function decrypt(ems, passphrase, id, ext, e) {
	return feistel(ems, passphrase, id, ext, e, [3, 2, 1, 0]);
}

/* the deterministic randomness: PBKDF2 output, taken from the start */
function Stream(bytes) {
	this.data = bytes;
	this.pos = 0;
}
Stream.prototype.take = function (n) {
	this.pos += n;
	if (this.pos > this.data.length) throw new Error("stream exhausted");
	return this.data.slice(this.pos - n, this.pos);
};

async function digestOf(r, secret) {
	return concat((await hmac(r, secret)).slice(0, 4), r);
}

/* SplitSecret of SLIP-0039 */
async function splitSecret(threshold, count, secret, rng) {
	var n = secret.length, shares = [], i;
	if (threshold === 1) {
		for (i = 0; i < count; i++) shares.push(secret);
		return shares;
	}
	var digest = await digestOf(rng.take(n - 4), secret);
	for (i = 0; i < threshold - 2; i++) shares.push(rng.take(n));
	var points = shares.map(function (s, i) { return [i, s]; });
	points.push([254, digest], [255, secret]);
	for (i = threshold - 2; i < count; i++) shares.push(interpolate(points, i));
	return shares;
}

/* recover the secret at 255 from [[x, share]], check the digest */
async function recoverSecret(threshold, points) {
	if (threshold === 1) return points[0][1];
	var secret = interpolate(points, 255), digest = interpolate(points, 254);
	var check = await digestOf(digest.slice(4), secret);
	if (hex(check) !== hex(digest)) throw new Error("the digest does not match");
	return secret;
}

function randomBytesNeeded(n, gt, groups) {
	var sets = [[gt, groups.length]].concat(groups), sum = 0;
	sets.forEach(function (s) { if (s[0] > 1) sum += n - 4 + (s[0] - 2) * n; });
	return sum;
}

function rs1024(values) {
	var gen = [0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009,
		0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120];
	var chk = 1;
	values.forEach(function (v) {
		var b = chk >>> 20;
		chk = (chk & 0xfffff) << 10 ^ v;
		for (var i = 0; i < 10; i++) if (b >>> i & 1) chk ^= gen[i];
	});
	return chk;
}

function mnemonic(s, gi, mi, share) {
	var header = BigInt(s.id) << 5n | BigInt(s.ext) << 4n | BigInt(s.e);
	header = header << 16n | BigInt(gi) << 12n | BigInt(s.gt - 1) << 8n |
		BigInt(s.groups.length - 1) << 4n | BigInt(mi);
	header = header << 4n | BigInt(s.groups[gi][0] - 1);
	var words = Math.floor((8 * share.length + 9) / 10), value = toBig(share);
	var data = [], i;
	for (i = 3; i >= 0; i--) data.push(Number(header >> BigInt(10 * i) & 1023n));
	for (i = words - 1; i >= 0; i--) data.push(Number(value >> BigInt(10 * i) & 1023n));
	var cs = Array.from(utf8.encode(s.ext ? "shamir_extendable" : "shamir"));
	var chk = rs1024(cs.concat(data, [0, 0, 0])) ^ 1;
	for (i = 2; i >= 0; i--) data.push(chk >>> 10 * i & 1023);
	return data.map(function (d) { return WORDS[d]; }).join(" ");
}

/* split as slip0039 split does: s has passphrase, seed (strings), ms
 * (bytes), e, gt and groups ([[T, N], ...]); returns the identifier, the
 * EMS and the shares, group by group */
async function split(s) {
	var seed = utf8.encode(s.seed), passphrase = utf8.encode(s.passphrase);
	var id = ((await sha256(seed))[0] << 8 | (await sha256(seed))[1]) & 0x7fff;
	var st = { id: id, ext: 1, e: s.e, gt: s.gt, groups: s.groups };
	var ems = await encrypt(s.ms, passphrase, id, 1, s.e);
	var salt = new Uint8Array([s.e, s.gt, s.groups.length].concat(
		s.groups.reduce(function (a, g) { return a.concat(g); }, [])));
	var need = randomBytesNeeded(ems.length, s.gt, s.groups);
	var rng = new Stream(await pbkdf2(concat(ems, seed), salt, 1, need));
	var groupShares = await splitSecret(s.gt, s.groups.length, ems, rng);
	var shares = [];
	for (var gi = 0; gi < s.groups.length; gi++) {
		var g = s.groups[gi];
		var members = await splitSecret(g[0], g[1], groupShares[gi], rng);
		members.forEach(function (m, mi) {
			shares.push({ group: gi, member: mi, value: m,
				words: mnemonic(st, gi, mi, m) });
		});
	}
	return { id: id, ems: ems, shares: shares, state: st };
}

/* recover from some of the shares of split(): returns { ms } or
 * { missing: text } if there are not enough shares */
async function recover(result, chosen, passphrase) {
	var st = result.state, groupPoints = [], missing = [];
	for (var gi = 0; gi < st.groups.length; gi++) {
		var t = st.groups[gi][0];
		var have = chosen.filter(function (sh) { return sh.group === gi; });
		if (have.length >= t) {
			var pts = have.slice(0, t).map(function (sh) { return [sh.member, sh.value]; });
			groupPoints.push([gi, await recoverSecret(t, pts)]);
		} else if (have.length) missing.push({ group: gi, need: t - have.length });
	}
	if (groupPoints.length < st.gt) return { missing: missing, groups: groupPoints.length };
	var ems = await recoverSecret(st.gt, groupPoints.slice(0, st.gt));
	return { ems: ems, ms: await decrypt(ems, utf8.encode(passphrase),
			st.id, st.ext, st.e) };
}

/* the codecs of the demo: base16, numeric and password (alnum), with the
 * modular DTE of honey.c for the last two, gain 0.01 (7 extra bits) */
var ALPHABETS = {
	numeric: "0123456789",
	password: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
};

async function encodeSecret(codec, text, seed) {
	if (codec === "base16") {
		var ms = unhex(text.trim());
		if (!ms) throw new Error("a master secret is hexadecimal, two digits per byte");
		if (ms.length < 16 || ms.length % 2)
			throw new Error("a master secret is 16 bytes or more, an even number");
		return ms;
	}
	var alpha = ALPHABETS[codec], m = BigInt(alpha.length), k = 0n;
	if (!text.length) throw new Error("type a secret first");
	for (var i = 0; i < text.length; i++) {
		var d = alpha.indexOf(text[i]);
		if (d < 0) throw new Error("'" + text[i] + "' is not in the alphabet of " + codec);
		k = k * m + BigInt(d);
	}
	var j = m ** BigInt(text.length);
	var bits = j.toString(2).length + 7;	/* floor(log2 j) + 1 + 7 */
	bits = Math.max(128, (bits + 15) & ~15);
	if (bits > 512) throw new Error("this secret is too long for one master secret");
	var L = bits / 8, n = BigInt(bits);
	var u = toBig(await pbkdf2(utf8.encode("honey"), utf8.encode(seed), 1, L));
	var R = (1n << n) / j, t = (1n << n) % j;
	var r = k < t ? u % (R + 1n) : u % R;
	return fromBig(k + j * r, L);
}

function decodeSecret(codec, ms, count) {
	if (codec === "base16") return hex(ms);
	var alpha = ALPHABETS[codec], m = BigInt(alpha.length);
	var k = toBig(ms) % m ** BigInt(count), out = "";
	for (var i = 0; i < count; i++) {
		out = alpha[Number(k % m)] + out;
		k /= m;
	}
	return out;
}

return { split: split, recover: recover, encodeSecret: encodeSecret,
	decodeSecret: decodeSecret, hex: hex, unhex: unhex, sha256: sha256 };
})();

if (typeof module !== "undefined") module.exports = SLIP0039;
