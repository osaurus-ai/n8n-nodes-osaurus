import { beforeEach, describe, expect, it } from 'vitest';

import type { ChannelConfig } from '../src/pairing';
import type { HttpFn } from '../src/secureChannel';
import {
	NoReachableCandidateError,
	PlaintextTransport,
	describeConnection,
	explainProbe,
	makeTransport,
	pingPath,
	resetSelectedBaseUrls,
	selectBaseUrl,
} from '../src/transport';

function config(overrides: Partial<ChannelConfig> = {}): ChannelConfig {
	return {
		candidates: ['http://127.0.0.1:1337', 'http://host.docker.internal:1337', 'https://relay.test'],
		connectionId: 'n8n-local',
		secret: 'secret',
		verificationMethod: 'hmac_sha256',
		headerName: '',
		source: 'pairing_code',
		...overrides,
	};
}

type Script = Record<string, { status: number; body: string } | 'network'>;

/** Scripted plaintext HTTP: keyed by origin, records every URL hit. */
function scriptedHttp(script: Script): {
	http: HttpFn;
	hits: string[];
	headers: Record<string, string>[];
} {
	const hits: string[] = [];
	const headers: Record<string, string>[] = [];
	const http: HttpFn = async (request) => {
		hits.push(request.url);
		headers.push(request.headers);
		const origin = new URL(request.url).origin;
		const answer = script[origin];
		if (answer === undefined || answer === 'network') {
			throw new Error(`ECONNREFUSED ${origin}`);
		}
		return answer;
	};
	return { http, hits, headers };
}

const OK = {
	status: 200,
	body: '{"status":"ok","verification":"hmac_sha256","transport":"loopback"}',
};

describe('selectBaseUrl', () => {
	beforeEach(() => resetSelectedBaseUrls());

	it('tries candidates in order and keeps the first 200', async () => {
		const { http, hits, headers } = scriptedHttp({
			'http://127.0.0.1:1337': 'network',
			'http://host.docker.internal:1337': OK,
			'https://relay.test': OK,
		});
		const cfg = config();
		const transport = new PlaintextTransport(http);
		const selected = await selectBaseUrl(cfg, transport);
		expect(selected.baseUrl).toBe('http://host.docker.internal:1337');
		expect(selected.ping.ok?.verification).toBe('hmac_sha256');
		expect(hits).toEqual([
			`http://127.0.0.1:1337${pingPath('n8n-local')}`,
			`http://host.docker.internal:1337${pingPath('n8n-local')}`,
		]);
		// The probe is secret-authenticated: HMAC over the empty body.
		expect(Object.keys(headers[0])).toContain('X-Osaurus-Channel-Signature');
		expect(describeConnection(selected, transport)).toBe(
			'Connected to http://host.docker.internal:1337 (hmac_sha256, plaintext).',
		);
	});

	it('caches the winner per config and skips the failed candidates next time', async () => {
		const { http, hits } = scriptedHttp({
			'http://127.0.0.1:1337': 'network',
			'http://host.docker.internal:1337': OK,
		});
		const cfg = config();
		const transport = new PlaintextTransport(http);
		await selectBaseUrl(cfg, transport);
		hits.length = 0;
		const again = await selectBaseUrl(cfg, transport);
		expect(again.baseUrl).toBe('http://host.docker.internal:1337');
		expect(hits).toEqual([`http://host.docker.internal:1337${pingPath('n8n-local')}`]);
	});

	it('re-probes from the top when the cached winner stops answering', async () => {
		const script: Script = {
			'http://127.0.0.1:1337': 'network',
			'http://host.docker.internal:1337': OK,
			'https://relay.test': OK,
		};
		const { http, hits } = scriptedHttp(script);
		const cfg = config();
		const transport = new PlaintextTransport(http);
		await selectBaseUrl(cfg, transport);
		script['http://host.docker.internal:1337'] = 'network';
		script['http://127.0.0.1:1337'] = OK;
		hits.length = 0;
		const again = await selectBaseUrl(cfg, transport);
		expect(again.baseUrl).toBe('http://127.0.0.1:1337');
		expect(hits[0]).toContain('host.docker.internal'); // cached one first
		expect(hits[1]).toContain('127.0.0.1');
	});

	it('treats an authoritative HTTP error from the cached winner as final', async () => {
		const script: Script = { 'http://127.0.0.1:1337': OK };
		const { http, hits } = scriptedHttp(script);
		const cfg = config();
		const transport = new PlaintextTransport(http);
		await selectBaseUrl(cfg, transport);
		script['http://127.0.0.1:1337'] = { status: 401, body: '{"error":{"code":"unauthorized"}}' };
		hits.length = 0;
		await expect(selectBaseUrl(cfg, transport)).rejects.toThrow(/secret rejected \(401\)/);
		expect(hits).toHaveLength(1);
	});

	it('forceProbe ignores the cache', async () => {
		const { http, hits } = scriptedHttp({ 'http://127.0.0.1:1337': OK });
		const cfg = config({ candidates: ['http://127.0.0.1:1337'] });
		const transport = new PlaintextTransport(http);
		await selectBaseUrl(cfg, transport);
		hits.length = 0;
		await selectBaseUrl(cfg, transport, { forceProbe: true });
		expect(hits).toHaveLength(1);
	});

	it('explains every failed candidate when none answers', async () => {
		const { http } = scriptedHttp({
			'http://127.0.0.1:1337': 'network',
			'http://host.docker.internal:1337': {
				status: 426,
				body: '{"error":{"code":"secure_channel_required"}}',
			},
			'https://relay.test': { status: 404, body: '{"error":{"code":"connection_not_found"}}' },
		});
		const cfg = config();
		const transport = new PlaintextTransport(http);
		let caught: unknown;
		try {
			await selectBaseUrl(cfg, transport);
		} catch (error) {
			caught = error;
		}
		expect(caught).toBeInstanceOf(NoReachableCandidateError);
		const message = (caught as Error).message;
		expect(message).toContain('ECONNREFUSED');
		expect(message).toContain('remote callers need Secure Channel (426)');
		expect(message).toContain("connection 'n8n-local' not found (404)");
		expect((caught as NoReachableCandidateError).attempts).toHaveLength(3);
	});

	it('separates configs with different secrets in the cache', async () => {
		const { http, hits } = scriptedHttp({ 'http://127.0.0.1:1337': OK });
		const transport = new PlaintextTransport(http);
		await selectBaseUrl(config({ candidates: ['http://127.0.0.1:1337'], secret: 'a' }), transport);
		await selectBaseUrl(config({ candidates: ['http://127.0.0.1:1337'], secret: 'b' }), transport);
		expect(hits).toHaveLength(2);
	});
});

describe('makeTransport', () => {
	it('uses Secure Channel iff the config carries an agent address', () => {
		const { http } = scriptedHttp({});
		expect(makeTransport(config(), http).kind).toBe('plaintext');
		expect(makeTransport(config({ agentAddress: '0xabc' }), http).kind).toBe('secure_channel');
	});
});

describe('explainProbe', () => {
	it('maps status codes to fixes', () => {
		const cfg = config();
		expect(explainProbe({ baseUrl: 'u', status: 401, body: '' }, cfg)).toMatch(/stale/);
		expect(explainProbe({ baseUrl: 'u', status: 403, body: '' }, cfg)).toMatch(/disabled/);
		expect(explainProbe({ baseUrl: 'u', status: 429, body: '' }, cfg)).toMatch(/rate limited/);
		expect(explainProbe({ baseUrl: 'u', status: 500, body: 'boom' }, cfg)).toMatch(/HTTP 500 boom/);
		expect(explainProbe({ baseUrl: 'u', status: 0, body: '', error: 'ECONNREFUSED' }, cfg)).toBe(
			'u: ECONNREFUSED',
		);
	});
});
