import { randomBytes } from 'node:crypto';

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { describe, expect, it } from 'vitest';

import { keccak256 } from '../src/crypto/keccak';
import { recoverPublicKey } from '../src/crypto/secp256k1';

/**
 * The shipped package has zero runtime dependencies, so keccak-256 and
 * secp256k1 recovery are implemented in-repo. These tests pin them against
 * published test vectors and against `@noble/*` (dev dependency only).
 */

describe('keccak256', () => {
	it('matches the canonical empty-input and "abc" digests', () => {
		expect(keccak256(Buffer.alloc(0)).toString('hex')).toBe(
			'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
		);
		expect(keccak256(Buffer.from('abc', 'utf8')).toString('hex')).toBe(
			'4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
		);
	});

	it('agrees with @noble/hashes across block boundaries', () => {
		for (const length of [0, 1, 55, 56, 135, 136, 137, 271, 272, 273, 1000]) {
			const input = randomBytes(length);
			expect(keccak256(input).toString('hex')).toBe(Buffer.from(keccak_256(input)).toString('hex'));
		}
	});
});

describe('secp256k1.recoverPublicKey', () => {
	it('recovers the signer for random keys, messages, and both parities', () => {
		for (let i = 0; i < 16; i += 1) {
			const priv = secp256k1.utils.randomSecretKey();
			const pub = Buffer.from(secp256k1.getPublicKey(priv, false));
			const hash = randomBytes(32);
			const recovered = secp256k1.sign(hash, priv, { prehash: false, format: 'recovered' });
			const recid = recovered[0];
			const rs = recovered.subarray(1, 65);
			expect(recoverPublicKey(hash, rs, recid).toString('hex')).toBe(pub.toString('hex'));
		}
	});

	it('rejects malformed input instead of returning a key', () => {
		const hash = randomBytes(32);
		expect(() => recoverPublicKey(hash, Buffer.alloc(64), 0)).toThrow(/out of range/);
		expect(() => recoverPublicKey(hash, Buffer.alloc(63), 0)).toThrow(/64 bytes/);
		expect(() => recoverPublicKey(Buffer.alloc(31), Buffer.alloc(64, 1), 0)).toThrow(/32 bytes/);
		expect(() => recoverPublicKey(hash, Buffer.alloc(64, 1), 4)).toThrow(/recovery id/);
	});

	it('yields a different key for the wrong recovery id', () => {
		const priv = secp256k1.utils.randomSecretKey();
		const pub = Buffer.from(secp256k1.getPublicKey(priv, false)).toString('hex');
		const hash = randomBytes(32);
		const recovered = secp256k1.sign(hash, priv, { prehash: false, format: 'recovered' });
		const wrongRecid = recovered[0] ^ 1;
		expect(recoverPublicKey(hash, recovered.subarray(1, 65), wrongRecid).toString('hex')).not.toBe(
			pub,
		);
	});
});
