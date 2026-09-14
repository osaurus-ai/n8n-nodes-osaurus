import { describe, expect, it } from 'vitest';

import {
	PAIRING_CODE_PREFIX,
	PairingCodeError,
	configFromPairingCode,
	decodePairingCode,
	resolveChannelConfig,
} from '../src/pairing';

function encode(payload: unknown, version = 1): string {
	return `${PAIRING_CODE_PREFIX}${version}.${Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')}`;
}

const FULL = {
	v: 1,
	urls: [
		'http://127.0.0.1:1337',
		'http://host.docker.internal:1337',
		'https://0xabc.agent.osaurus.ai/',
	],
	cid: 'n8n-local',
	secret: 'example+secret/=', // placeholder, exercises base64-ish characters
	vfy: 'shared_secret_header',
	hdr: 'X-Custom',
	addr: '0xABCDEF0123456789abcdef0123456789ABCDEF01',
	name: 'Home n8n',
};

/**
 * Wire-shape twin of the Swift `N8nPairingCodeTests`: the exact bytes the
 * sheet emits for a minimal code, so a change on either side fails here.
 */
const SWIFT_MINIMAL_CODE =
	'osrs-n8n-1.' +
	Buffer.from(
		'{"cid":"n8n-local","secret":"abc","urls":["http://127.0.0.1:1337"],"v":1,"vfy":"hmac_sha256"}',
		'utf8',
	).toString('base64url');

describe('decodePairingCode', () => {
	it('decodes every field and lowercases the agent address', () => {
		const payload = decodePairingCode(`  ${encode(FULL)}\n`);
		expect(payload.cid).toBe('n8n-local');
		expect(payload.urls).toEqual(FULL.urls);
		expect(payload.secret).toBe(FULL.secret);
		expect(payload.vfy).toBe('shared_secret_header');
		expect(payload.hdr).toBe('X-Custom');
		expect(payload.addr).toBe('0xabcdef0123456789abcdef0123456789abcdef01');
		expect(payload.name).toBe('Home n8n');
	});

	it('decodes the Swift-emitted minimal code', () => {
		const payload = decodePairingCode(SWIFT_MINIMAL_CODE);
		expect(payload).toEqual({
			v: 1,
			urls: ['http://127.0.0.1:1337'],
			cid: 'n8n-local',
			secret: 'abc',
			vfy: 'hmac_sha256',
		});
	});

	it('rejects foreign strings, wrong versions and broken payloads with actionable text', () => {
		expect(() => decodePairingCode('osk-v1.something')).toThrow(/not an Osaurus pairing code/);
		expect(() => decodePairingCode('osrs-n8n-2.eyJ2IjoyfQ')).toThrow(/version 2 is not supported/);
		expect(() => decodePairingCode('osrs-n8n-1.!!!')).toThrow(/not valid/);
		expect(() => decodePairingCode('osrs-n8n-1')).toThrow(/separator/);
		expect(() => decodePairingCode(encode({ ...FULL, v: 3 }))).toThrow(/version 3/);
		expect(() => decodePairingCode(encode({ ...FULL, urls: [] }))).toThrow(/no URLs/);
		expect(() => decodePairingCode(encode({ ...FULL, cid: '' }))).toThrow(/connection id/);
		expect(() => decodePairingCode(encode({ ...FULL, secret: '' }))).toThrow(/secret/);
		expect(() => decodePairingCode(encode([1, 2]))).toThrow(PairingCodeError);
	});
});

describe('configFromPairingCode', () => {
	it('normalises candidates and maps fields', () => {
		const config = configFromPairingCode(encode(FULL));
		expect(config.candidates).toEqual([
			'http://127.0.0.1:1337',
			'http://host.docker.internal:1337',
			'https://0xabc.agent.osaurus.ai',
		]);
		expect(config.connectionId).toBe('n8n-local');
		expect(config.verificationMethod).toBe('shared_secret_header');
		expect(config.headerName).toBe('X-Custom');
		expect(config.agentAddress).toBe('0xabcdef0123456789abcdef0123456789abcdef01');
		expect(config.source).toBe('pairing_code');
	});

	it('defaults unknown verification to hmac and header to empty', () => {
		const config = configFromPairingCode(
			encode({ ...FULL, vfy: 'weird', hdr: undefined, addr: undefined }),
		);
		expect(config.verificationMethod).toBe('hmac_sha256');
		expect(config.headerName).toBe('');
		expect(config.agentAddress).toBeUndefined();
	});
});

describe('resolveChannelConfig', () => {
	it('prefers the pairing code when Setup is Pairing Code', () => {
		const config = resolveChannelConfig({ setup: 'pairingCode', pairingCode: encode(FULL) });
		expect(config.source).toBe('pairing_code');
		expect(config.candidates).toHaveLength(3);
	});

	it('uses the manual fields when Setup is Manual', () => {
		const config = resolveChannelConfig({
			setup: 'manual',
			pairingCode: encode(FULL),
			baseUrl: 'http://127.0.0.1:1337/',
			connectionId: ' n8n-manual ',
			secret: 'manual-secret',
			verificationMethod: 'hmac_sha256',
			headerName: '',
		});
		expect(config.source).toBe('manual');
		expect(config.candidates).toEqual(['http://127.0.0.1:1337']);
		expect(config.connectionId).toBe('n8n-manual');
		expect(config.secret).toBe('manual-secret');
		expect(config.agentAddress).toBeUndefined();
	});

	it('falls back to legacy 0.1.x credentials that predate the Setup field', () => {
		const config = resolveChannelConfig({
			baseUrl: 'http://host.docker.internal:1337',
			connectionId: 'n8n-local',
			secret: 'legacy',
			verificationMethod: 'shared_secret_header',
			headerName: 'X-Legacy',
		});
		expect(config.source).toBe('manual');
		expect(config.verificationMethod).toBe('shared_secret_header');
		expect(config.headerName).toBe('X-Legacy');
	});

	it('keeps working when n8n fills setup=pairingCode into a legacy credential', () => {
		const config = resolveChannelConfig({
			setup: 'pairingCode',
			pairingCode: '',
			baseUrl: 'http://127.0.0.1:1337',
			connectionId: 'n8n-local',
			secret: 'legacy',
		});
		expect(config.source).toBe('manual');
	});

	it('explains what is missing', () => {
		expect(() => resolveChannelConfig({ setup: 'pairingCode', pairingCode: '' })).toThrow(
			/Paste the pairing code/,
		);
		expect(() => resolveChannelConfig({ setup: 'manual', baseUrl: 'http://x' })).toThrow(
			/Manual setup needs/,
		);
	});
});
