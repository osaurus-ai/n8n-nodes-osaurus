import { beforeEach, describe, expect, it } from 'vitest';

import type { ChannelConfig } from '../src/pairing';
import type { HttpFn } from '../src/secureChannel';
import {
	NoReachableCandidateError,
	PROBE_TIMEOUT_MS,
	PlaintextTransport,
	describeConnection,
	explainProbe,
	isPrivateOnlyUrl,
	locationHint,
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
		expect(message).toContain('callers from another machine need Secure Channel (426)');
		expect(message).toContain('Where is your n8n?');
		expect(message).toContain("connection 'n8n-local' not found (404)");
		expect((caught as NoReachableCandidateError).attempts).toHaveLength(3);
		// One candidate answered with HTTP, so this is not the "wrong location" case.
		expect(message).not.toContain('only work from the same Mac');
	});

	it('points at Where is your n8n? → Remote when only private URLs were in the code and none answered', async () => {
		const { http } = scriptedHttp({});
		const cfg = config({
			candidates: [
				'http://127.0.0.1:1337',
				'http://host.docker.internal:1337',
				'http://192.168.1.20:1337',
			],
		});
		const transport = new PlaintextTransport(http);
		let caught: unknown;
		try {
			await selectBaseUrl(cfg, transport);
		} catch (error) {
			caught = error;
		}
		expect(caught).toBeInstanceOf(NoReachableCandidateError);
		const message = (caught as Error).message;
		expect(message).toContain('only work from the same Mac or its network');
		expect(message).toContain('Where is your n8n?');
		expect(message).toContain('Remote');
	});

	it('does not blame the location when a public relay URL was among the dead candidates', async () => {
		const { http } = scriptedHttp({});
		const cfg = config({ candidates: ['http://127.0.0.1:1337', 'https://0xabc.agent.osaurus.ai'] });
		const transport = new PlaintextTransport(http);
		await expect(selectBaseUrl(cfg, transport)).rejects.toThrow(/No Osaurus URL/);
		try {
			await selectBaseUrl(cfg, transport);
		} catch (error) {
			expect((error as Error).message).not.toContain('only work from the same Mac');
		}
	});

	it('caps each plaintext probe at the probe timeout instead of the transport default', async () => {
		const timeouts: Array<number | undefined> = [];
		const http: HttpFn = async (request) => {
			timeouts.push(request.timeoutMs);
			throw new Error('ETIMEDOUT');
		};
		const cfg = config({ candidates: ['http://127.0.0.1:1337', 'http://10.0.0.5:1337'] });
		const transport = new PlaintextTransport(http, 30_000);
		await expect(selectBaseUrl(cfg, transport)).rejects.toThrow(NoReachableCandidateError);
		expect(timeouts).toEqual([PROBE_TIMEOUT_MS, PROBE_TIMEOUT_MS]);
		// Ordinary channel requests keep the transport default.
		timeouts.length = 0;
		await transport
			.request('http://127.0.0.1:1337', 'POST', '/channels/n8n/x/inbound', '{}', {})
			.catch(() => undefined);
		expect(timeouts).toEqual([30_000]);
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

	it('names the current Osaurus steps, not the old ones', () => {
		const cfg = config();
		const fix = explainProbe({ baseUrl: 'u', status: 426, body: '' }, cfg);
		expect(fix).toContain('Who answers?');
		expect(fix).toContain('Pair');
		expect(fix).toContain('Where is your n8n?');
		expect(fix).not.toMatch(/How Osaurus replies|Connect n8n|Remote callers/);
	});
});

describe('locationHint', () => {
	it('classifies private-only URLs', () => {
		for (const url of [
			'http://127.0.0.1:1337',
			'http://localhost:1337',
			'http://host.docker.internal:1337',
			'http://192.168.1.20:1337',
			'http://10.0.0.5:1337',
			'http://172.16.4.2:1337',
			'http://172.31.255.1:1337',
			'http://169.254.1.1:1337',
			'http://my-mac.local:1337',
			'http://[::1]:1337',
			'http://[fe80::1]:1337',
		]) {
			expect(isPrivateOnlyUrl(url), url).toBe(true);
		}
		for (const url of [
			'https://0xabc.agent.osaurus.ai',
			'http://172.32.0.1:1337',
			'http://8.8.8.8:1337',
			'https://n8n.example.com',
			'not a url',
		]) {
			expect(isPrivateOnlyUrl(url), url).toBe(false);
		}
	});

	it('fires only when every candidate is private and none answered at all', () => {
		const dead = (baseUrl: string) => ({ baseUrl, status: 0, body: '', error: 'ECONNREFUSED' });
		expect(locationHint([dead('http://127.0.0.1:1337'), dead('http://10.0.0.5:1337')])).toMatch(
			/Remote/,
		);
		// A public candidate means the code was already scoped for remote.
		expect(
			locationHint([dead('http://127.0.0.1:1337'), dead('https://0xabc.agent.osaurus.ai')]),
		).toBeNull();
		// An HTTP answer means the server was reached; the location is right.
		expect(
			locationHint([
				dead('http://127.0.0.1:1337'),
				{ baseUrl: 'http://10.0.0.5:1337', status: 426, body: '' },
			]),
		).toBeNull();
		expect(locationHint([])).toBeNull();
	});
});
