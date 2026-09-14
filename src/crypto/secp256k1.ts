/**
 * Minimal secp256k1 public-key recovery for verifying Osaurus handshake
 * signatures. Node's `crypto` can verify an ECDSA signature against a known
 * public key, but Osaurus pins an *address* (hash of the key), so the key must
 * be recovered from `(r, s, recid)` first — which `crypto` does not expose.
 *
 * Only recovery is implemented; no signing, no secret handling. Constant-time
 * behaviour is not required because every input is public. Cross-checked in
 * tests against `@noble/curves` (dev dependency only).
 */

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

interface Point {
	x: bigint;
	y: bigint;
}

function mod(a: bigint, m: bigint = P): bigint {
	const r = a % m;
	return r >= 0n ? r : r + m;
}

function modPow(base: bigint, exponent: bigint, m: bigint): bigint {
	let result = 1n;
	let b = mod(base, m);
	let e = exponent;
	while (e > 0n) {
		if (e & 1n) result = (result * b) % m;
		b = (b * b) % m;
		e >>= 1n;
	}
	return result;
}

function modInverse(a: bigint, m: bigint): bigint {
	let [oldR, r] = [mod(a, m), m];
	let [oldS, s] = [1n, 0n];
	while (r !== 0n) {
		const q = oldR / r;
		[oldR, r] = [r, oldR - q * r];
		[oldS, s] = [s, oldS - q * s];
	}
	if (oldR !== 1n) throw new Error('secp256k1: value is not invertible');
	return mod(oldS, m);
}

function pointAdd(a: Point | null, b: Point | null): Point | null {
	if (a === null) return b;
	if (b === null) return a;
	if (a.x === b.x) {
		if (mod(a.y + b.y) === 0n) return null;
		// Doubling.
		const lambda = mod(3n * a.x * a.x * modInverse(2n * a.y, P));
		const x = mod(lambda * lambda - 2n * a.x);
		return { x, y: mod(lambda * (a.x - x) - a.y) };
	}
	const lambda = mod((b.y - a.y) * modInverse(mod(b.x - a.x), P));
	const x = mod(lambda * lambda - a.x - b.x);
	return { x, y: mod(lambda * (a.x - x) - a.y) };
}

function scalarMultiply(k: bigint, point: Point): Point | null {
	let result: Point | null = null;
	let addend: Point | null = point;
	let scalar = mod(k, N);
	while (scalar > 0n) {
		if (scalar & 1n) result = pointAdd(result, addend);
		addend = pointAdd(addend, addend);
		scalar >>= 1n;
	}
	return result;
}

function isOnCurve(point: Point): boolean {
	return mod(point.y * point.y - point.x * point.x * point.x - 7n) === 0n;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
	return BigInt('0x' + Buffer.from(bytes).toString('hex').padStart(2, '0'));
}

function bigIntTo32(value: bigint): Buffer {
	return Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
}

/**
 * Recover the uncompressed public key (`0x04 || X || Y`, 65 bytes) that
 * produced `signature` over the 32-byte `messageHash`.
 *
 * @param messageHash 32-byte digest that was signed
 * @param signature 64 bytes `r || s`
 * @param recoveryId 0…3
 */
export function recoverPublicKey(
	messageHash: Uint8Array,
	signature: Uint8Array,
	recoveryId: number,
): Buffer {
	if (messageHash.length !== 32) throw new Error('secp256k1: message hash must be 32 bytes');
	if (signature.length !== 64) throw new Error('secp256k1: signature must be 64 bytes');
	if (!Number.isInteger(recoveryId) || recoveryId < 0 || recoveryId > 3) {
		throw new Error('secp256k1: recovery id must be 0…3');
	}

	const r = bytesToBigInt(signature.subarray(0, 32));
	const s = bytesToBigInt(signature.subarray(32, 64));
	if (r <= 0n || r >= N || s <= 0n || s >= N) throw new Error('secp256k1: signature out of range');

	// R.x = r (+ n when the high bit of recid is set), R.y parity from the low bit.
	const rx = r + (recoveryId >> 1 ? N : 0n);
	if (rx >= P) throw new Error('secp256k1: invalid recovery id for r');
	const ySquared = mod(rx * rx * rx + 7n);
	let ry = modPow(ySquared, (P + 1n) / 4n, P);
	if (mod(ry * ry) !== ySquared)
		throw new Error('secp256k1: r is not an x-coordinate on the curve');
	if ((ry & 1n) !== BigInt(recoveryId & 1)) ry = P - ry;
	const R: Point = { x: rx, y: ry };

	// Q = r⁻¹ · (s·R − e·G)
	const e = mod(bytesToBigInt(messageHash), N);
	const rInv = modInverse(r, N);
	const sR = scalarMultiply(s, R);
	const eG = scalarMultiply(e, { x: GX, y: GY });
	const negEG = eG === null ? null : { x: eG.x, y: mod(-eG.y) };
	const sum = pointAdd(sR, negEG);
	if (sum === null) throw new Error('secp256k1: recovered point at infinity');
	const q = scalarMultiply(rInv, sum);
	if (q === null || !isOnCurve(q)) throw new Error('secp256k1: recovered key is invalid');

	return Buffer.concat([Buffer.from([0x04]), bigIntTo32(q.x), bigIntTo32(q.y)]);
}
