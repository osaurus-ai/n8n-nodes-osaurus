/**
 * Keccak-256 (the pre-NIST padding used by Ethereum addresses and Osaurus
 * identity hashes). Node's `crypto` only ships SHA3-256, which differs in
 * the padding byte, so this is a small dependency-free implementation.
 *
 * Inputs are short (handshake transcripts, public keys), so a plain BigInt
 * lane implementation is fast enough and easy to audit. Cross-checked in
 * tests against `@noble/hashes` (dev dependency only).
 */

const ROUNDS = 24;
const LANE_MASK = (1n << 64n) - 1n;

const ROUND_CONSTANTS: bigint[] = [
	0x0000000000000001n,
	0x0000000000008082n,
	0x800000000000808an,
	0x8000000080008000n,
	0x000000000000808bn,
	0x0000000080000001n,
	0x8000000080008081n,
	0x8000000000008009n,
	0x000000000000008an,
	0x0000000000000088n,
	0x0000000080008009n,
	0x000000008000000an,
	0x000000008000808bn,
	0x800000000000008bn,
	0x8000000000008089n,
	0x8000000000008003n,
	0x8000000000008002n,
	0x8000000000000080n,
	0x000000000000800an,
	0x800000008000000an,
	0x8000000080008081n,
	0x8000000000008080n,
	0x0000000080000001n,
	0x8000000080008008n,
];

const ROTATION_OFFSETS: number[] = [
	0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

function rotl64(value: bigint, shift: number): bigint {
	if (shift === 0) return value;
	return ((value << BigInt(shift)) | (value >> BigInt(64 - shift))) & LANE_MASK;
}

function keccakF(state: bigint[]): void {
	for (let round = 0; round < ROUNDS; round += 1) {
		// θ
		const c: bigint[] = new Array<bigint>(5);
		for (let x = 0; x < 5; x += 1) {
			c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
		}
		for (let x = 0; x < 5; x += 1) {
			const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
			for (let y = 0; y < 25; y += 5) state[x + y] ^= d;
		}
		// ρ and π
		const b: bigint[] = new Array<bigint>(25);
		for (let x = 0; x < 5; x += 1) {
			for (let y = 0; y < 5; y += 1) {
				const index = x + 5 * y;
				const newX = y;
				const newY = (2 * x + 3 * y) % 5;
				b[newX + 5 * newY] = rotl64(state[index], ROTATION_OFFSETS[index]);
			}
		}
		// χ
		for (let y = 0; y < 25; y += 5) {
			for (let x = 0; x < 5; x += 1) {
				state[x + y] = b[x + y] ^ (~b[((x + 1) % 5) + y] & LANE_MASK & b[((x + 2) % 5) + y]);
			}
		}
		// ι
		state[0] ^= ROUND_CONSTANTS[round];
	}
}

/** Keccak-256 digest of `input` (rate 136 bytes, padding 0x01 … 0x80). */
export function keccak256(input: Uint8Array): Buffer {
	const rate = 136;
	const state: bigint[] = new Array<bigint>(25).fill(0n);

	// Pad: 0x01, zeros, final byte |= 0x80.
	const paddedLength = Math.ceil((input.length + 1) / rate) * rate;
	const padded = Buffer.alloc(paddedLength);
	padded.set(input);
	padded[input.length] ^= 0x01;
	padded[paddedLength - 1] ^= 0x80;

	for (let offset = 0; offset < paddedLength; offset += rate) {
		for (let lane = 0; lane < rate / 8; lane += 1) {
			state[lane] ^= padded.readBigUInt64LE(offset + lane * 8);
		}
		keccakF(state);
	}

	const out = Buffer.alloc(32);
	for (let lane = 0; lane < 4; lane += 1) {
		out.writeBigUInt64LE(state[lane], lane * 8);
	}
	return out;
}
