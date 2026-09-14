import { createPublicKey, diffieHellman, generateKeyPairSync, randomBytes } from 'crypto';

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { describe, expect, it } from 'vitest';

import type {
	CallRequest,
	ClientHello,
	Frame,
	HttpFn,
	InnerRequest,
	ServerHello,
} from '../src/secureChannel';
import {
	SecureChannelClient,
	SecureChannelError,
	addressFromPublicKey,
	base64urlDecode,
	base64urlEncode,
	deriveSessionKeys,
	domainHash,
	open,
	requestAAD,
	responseAAD,
	responseKey,
	seal,
	transcriptPayload,
	x25519PublicKeyFromRaw,
	x25519RawPublicKey,
} from '../src/secureChannel';

/**
 * A tiny in-memory Osaurus: signs handshakes with a secp256k1 agent key,
 * derives the mirror session, decrypts calls and answers with a fin frame.
 * Built from the same primitives the client uses, so the behavioural tests
 * (cache, retry, replay, truncation) run without a network.
 */
class FakeOsaurus {
	readonly agentPrivate = randomBytes(32);
	readonly agentAddress = addressFromPublicKey(secp256k1.getPublicKey(this.agentPrivate, false));
	sessions = new Map<string, { c2s: Buffer; s2c: Buffer; seen: Set<number> }>();
	handshakes = 0;
	calls: InnerRequest[] = [];
	/** Per-path responder; default echoes 200 ok. */
	respond: (inner: InnerRequest) => { status: number; body: string } = () => ({
		status: 200,
		body: '{"status":"ok"}',
	});
	/** Test knobs. */
	forgetSessions = false;
	sessionStatus = 200;
	tamperEphemeral = false;
	omitFin = false;
	frameSeq = 0;
	expiresInSeconds = 900;

	sign(payload: Buffer): string {
		const sig = secp256k1.sign(domainHash(payload), this.agentPrivate, {
			prehash: false,
			format: 'recovered',
		});
		// noble 'recovered' = recovery || r || s ; Osaurus wants r || s || (recovery + 27)
		const recovered = Buffer.from(sig);
		const out = Buffer.concat([recovered.subarray(1), Buffer.from([recovered[0] + 27])]);
		return `0x${out.toString('hex')}`;
	}

	http: HttpFn = async (request) => {
		const url = new URL(request.url);
		if (url.pathname === '/secure/session') {
			this.handshakes += 1;
			if (this.sessionStatus !== 200)
				return { status: this.sessionStatus, body: '{"error":"nope"}' };
			const hello = JSON.parse(request.body ?? '{}') as ClientHello;
			const pair = generateKeyPairSync('x25519');
			const sid = base64urlEncode(randomBytes(16));
			const expiresAt = Math.floor(Date.now() / 1000) + this.expiresInSeconds;
			const encPub = base64urlEncode(x25519RawPublicKey(pair.publicKey));
			const unsigned = { v: 1, sid, encPub, expiresAt };
			const transcript = transcriptPayload(hello, unsigned);
			const shared = diffieHellman({
				privateKey: pair.privateKey,
				publicKey: x25519PublicKeyFromRaw(base64urlDecode(hello.encPub)),
			});
			const { c2s, s2c } = deriveSessionKeys(shared, transcript);
			this.sessions.set(sid, { c2s, s2c, seen: new Set() });
			const serverHello: ServerHello = {
				...unsigned,
				encPub: this.tamperEphemeral
					? base64urlEncode(
							x25519RawPublicKey(createPublicKey(generateKeyPairSync('x25519').privateKey)),
						)
					: encPub,
				signature: this.sign(transcript),
			};
			return { status: 200, body: JSON.stringify(serverHello) };
		}
		if (url.pathname === '/secure/call') {
			const call = JSON.parse(request.body ?? '{}') as CallRequest;
			const session = this.sessions.get(call.sid);
			if (!session || this.forgetSessions) {
				return { status: 401, body: '{"error":{"code":"secure_session_unknown"}}' };
			}
			if (session.seen.has(call.seq)) {
				return { status: 409, body: '{"error":{"code":"secure_replay"}}' };
			}
			session.seen.add(call.seq);
			const inner = JSON.parse(
				open(session.c2s, call.seq, requestAAD(call.sid, call.seq), call.ct).toString('utf8'),
			) as InnerRequest;
			this.calls.push(inner);
			const response = this.respond(inner);
			const plaintext = JSON.stringify({
				status: response.status,
				contentType: 'application/json',
				body: base64urlEncode(Buffer.from(response.body, 'utf8')),
			});
			const key = responseKey(session.s2c, call.seq);
			const fin = !this.omitFin;
			const frame: Frame = {
				seq: this.frameSeq,
				ct: seal(
					key,
					this.frameSeq,
					responseAAD(call.sid, call.seq, this.frameSeq, fin),
					Buffer.from(plaintext, 'utf8'),
				),
			};
			if (fin) frame.fin = true;
			return { status: 200, body: JSON.stringify(frame) };
		}
		return { status: 404, body: 'not found' };
	};
}

const BASE = 'http://osaurus.test:1337';

describe('SecureChannelClient', () => {
	it('handshakes once and reuses the session across calls', async () => {
		const server = new FakeOsaurus();
		const client = new SecureChannelClient(server.http);
		const first = await client.request(BASE, server.agentAddress, {
			method: 'GET',
			path: '/channels/n8n/c/ping',
		});
		const second = await client.request(BASE, server.agentAddress, {
			method: 'GET',
			path: '/channels/n8n/c/ping',
		});
		expect(first.status).toBe(200);
		expect(first.body).toBe('{"status":"ok"}');
		expect(second.status).toBe(200);
		expect(server.handshakes).toBe(1);
		expect(server.calls.map((c) => c.path)).toEqual([
			'/channels/n8n/c/ping',
			'/channels/n8n/c/ping',
		]);
	});

	it('shares one in-flight handshake between concurrent callers', async () => {
		const server = new FakeOsaurus();
		const client = new SecureChannelClient(server.http);
		await Promise.all(
			Array.from({ length: 5 }, () =>
				client.request(BASE, server.agentAddress, { method: 'GET', path: '/x' }),
			),
		);
		expect(server.handshakes).toBe(1);
		expect(server.calls).toHaveLength(5);
	});

	it('carries the channel header, body and content type inside the envelope', async () => {
		const server = new FakeOsaurus();
		const client = new SecureChannelClient(server.http);
		await client.request(BASE, server.agentAddress, {
			method: 'POST',
			path: '/channels/n8n/c/inbound',
			headers: { 'X-Osaurus-Channel-Signature': 'sha256=abc', Accept: 'ignored', Host: 'ignored' },
			contentType: 'application/json',
			body: '{"v":1}',
		});
		const inner = server.calls[0];
		expect(inner.method).toBe('POST');
		expect(inner.headers).toEqual({ 'X-Osaurus-Channel-Signature': 'sha256=abc' });
		expect(inner.contentType).toBe('application/json');
		expect(inner.accept).toBe('application/json');
		expect(base64urlDecode(inner.body ?? '').toString('utf8')).toBe('{"v":1}');
	});

	it('re-handshakes once on 401 secure_session_unknown, then gives up', async () => {
		const server = new FakeOsaurus();
		const client = new SecureChannelClient(server.http);
		await client.request(BASE, server.agentAddress, { method: 'GET', path: '/a' });
		server.sessions.clear(); // the Mac restarted
		const result = await client.request(BASE, server.agentAddress, { method: 'GET', path: '/b' });
		expect(result.status).toBe(200);
		expect(server.handshakes).toBe(2);

		server.forgetSessions = true;
		await expect(
			client.request(BASE, server.agentAddress, { method: 'GET', path: '/c' }),
		).rejects.toMatchObject({
			code: 'session_unknown',
		});
		// Exactly one retry: the cached session is tried first, then one fresh
		// handshake, then the error — never a third attempt.
		expect(server.handshakes).toBe(3);
	});

	it('never retransmits on 409 secure_replay', async () => {
		const server = new FakeOsaurus();
		const client = new SecureChannelClient(server.http);
		await client.request(BASE, server.agentAddress, { method: 'GET', path: '/a' });
		// Force the server to see the next seq as already used.
		const sid = [...server.sessions.keys()][0];
		server.sessions.get(sid)!.seen.add(2);
		const before = server.calls.length;
		await expect(
			client.request(BASE, server.agentAddress, { method: 'GET', path: '/b' }),
		).rejects.toMatchObject({
			code: 'replay_rejected',
		});
		expect(server.calls.length).toBe(before);
		expect(server.handshakes).toBe(1);
	});

	it('reports a 404 on /secure/session as unsupported and never downgrades to plaintext', async () => {
		const server = new FakeOsaurus();
		server.sessionStatus = 404;
		const client = new SecureChannelClient(server.http);
		await expect(
			client.request(BASE, server.agentAddress, { method: 'GET', path: '/a' }),
		).rejects.toMatchObject({
			code: 'peer_unsupported',
		});
		expect(server.calls).toHaveLength(0);
	});

	it('rejects a server hello whose signature does not recover to the pinned address', async () => {
		const server = new FakeOsaurus();
		const client = new SecureChannelClient(server.http);
		await expect(
			client.request(BASE, '0x0000000000000000000000000000000000000001', {
				method: 'GET',
				path: '/a',
			}),
		).rejects.toMatchObject({ code: 'identity_mismatch' });
		expect(server.calls).toHaveLength(0);
	});

	it('rejects a tampered ephemeral key (transcript no longer matches the signature)', async () => {
		const server = new FakeOsaurus();
		server.tamperEphemeral = true;
		const client = new SecureChannelClient(server.http);
		await expect(
			client.request(BASE, server.agentAddress, { method: 'GET', path: '/a' }),
		).rejects.toBeInstanceOf(SecureChannelError);
	});

	it('treats a non-fin single frame as truncation', async () => {
		const server = new FakeOsaurus();
		server.omitFin = true;
		const client = new SecureChannelClient(server.http);
		await expect(
			client.request(BASE, server.agentAddress, { method: 'GET', path: '/a' }),
		).rejects.toMatchObject({
			code: 'stream_truncated',
		});
	});

	it('rejects an out-of-order first frame', async () => {
		const server = new FakeOsaurus();
		server.frameSeq = 1;
		const client = new SecureChannelClient(server.http);
		await expect(
			client.request(BASE, server.agentAddress, { method: 'GET', path: '/a' }),
		).rejects.toMatchObject({
			code: 'out_of_order_frame',
		});
	});

	it('re-handshakes when the cached session is inside the expiry margin', async () => {
		const server = new FakeOsaurus();
		server.expiresInSeconds = 30; // < 60 s margin → unusable immediately after the handshake
		const client = new SecureChannelClient(server.http);
		await client.request(BASE, server.agentAddress, { method: 'GET', path: '/a' });
		await client.request(BASE, server.agentAddress, { method: 'GET', path: '/b' });
		expect(server.handshakes).toBe(2);
	});

	it('surfaces the inner HTTP status and body untouched', async () => {
		const server = new FakeOsaurus();
		server.respond = () => ({ status: 401, body: '{"error":{"code":"unauthorized"}}' });
		const client = new SecureChannelClient(server.http);
		const result = await client.request(BASE, server.agentAddress, { method: 'GET', path: '/a' });
		expect(result.status).toBe(401);
		expect(result.body).toContain('unauthorized');
	});

	it('keys the session cache by base URL and address', async () => {
		const server = new FakeOsaurus();
		const client = new SecureChannelClient(server.http);
		await client.request('http://a.test', server.agentAddress, { method: 'GET', path: '/a' });
		await client.request('http://b.test', server.agentAddress, { method: 'GET', path: '/a' });
		await client.request('http://a.test/', server.agentAddress, { method: 'GET', path: '/a' });
		expect(server.handshakes).toBe(2);
	});
});
