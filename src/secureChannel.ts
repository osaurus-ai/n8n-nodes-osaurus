/**
 * Osaurus Secure Channel v1 — client side.
 *
 * Faithful port of `Identity/SecureChannel.swift` + `SecureChannelClient.swift`
 * from the Osaurus app, pinned byte-for-byte by
 * `test/vectors/secure-channel-v1-vectors.json` (the same file the Swift suite
 * checks).
 *
 *   handshake : POST /secure/session  { v, agentAddress, encPub, nonce }
 *             → { v, sid, encPub, expiresAt, signature }
 *   transcript: osaurus-sc1|v=1|aA=<addr>|eC=<encPub>|nC=<nonce>|sid=<sid>|eS=<encPub>|exp=<expiresAt>
 *   identity  : keccak256("\x19Osaurus Secure Channel:\n" + len + transcript) → ecrecover → address == pinned
 *   keys      : HKDF-SHA256(X25519(eC, eS), salt = SHA256(transcript), info = osaurus-sc1:c2s | :s2c)
 *   call      : POST /secure/call { v, sid, seq, ct }  ct = ChaCha20-Poly1305(c2s, nonce(seq), aad=osaurus-sc1:req:<sid>:<seq>)
 *   response  : frames { seq, ct, fin? } under respkey = HKDF(s2c, info=osaurus-sc1:respkey:<reqSeq>),
 *               aad = osaurus-sc1:resp:<sid>:<reqSeq>:<seq>:<0|1>
 */

import {
	createCipheriv,
	createDecipheriv,
	createHash,
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	generateKeyPairSync,
	hkdfSync,
	randomBytes,
} from 'crypto';

import { keccak256 } from './crypto/keccak';
import { recoverPublicKey } from './crypto/secp256k1';

export const SECURE_CHANNEL_VERSION = 1;
export const TRANSCRIPT_DOMAIN = 'osaurus-sc1';
export const SIGNING_DOMAIN_PREFIX = 'Osaurus Secure Channel';
/** Sessions are refreshed this many seconds before the server's expiry. */
export const SESSION_EXPIRY_MARGIN_SECONDS = 60;

export type ClientHello = { v: number; agentAddress: string; encPub: string; nonce: string };
export type ServerHello = {
	v: number;
	sid: string;
	encPub: string;
	expiresAt: number;
	signature: string;
};
export type CallRequest = { v: number; sid: string; seq: number; ct: string };
export type Frame = { seq: number; ct: string; fin?: boolean };
export type InnerRequest = {
	method: string;
	path: string;
	authorization?: string;
	accept?: string;
	contentType?: string;
	headers?: Record<string, string>;
	body?: string;
};
export type InnerResponse = { status: number; contentType?: string; body?: string };

/** Minimal HTTP shape so the module is testable without n8n helpers. */
export type HttpResponse = { status: number; body: string };
export type HttpFn = (request: {
	method: 'GET' | 'POST';
	url: string;
	headers: Record<string, string>;
	body?: string;
	timeoutMs?: number;
}) => Promise<HttpResponse>;

export type SecureChannelErrorCode =
	| 'peer_unsupported'
	| 'identity_mismatch'
	| 'handshake_failed'
	| 'session_unknown'
	| 'replay_rejected'
	| 'decryption_failed'
	| 'stream_truncated'
	| 'out_of_order_frame'
	| 'malformed';

export class SecureChannelError extends Error {
	constructor(
		public readonly code: SecureChannelErrorCode,
		message: string,
	) {
		super(message);
		this.name = 'SecureChannelError';
	}
}

// MARK: - Encoding helpers

export function base64urlEncode(bytes: Uint8Array): string {
	return Buffer.from(bytes)
		.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

export function base64urlDecode(value: string): Buffer {
	const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
	return Buffer.from(normalized + '='.repeat((4 - (normalized.length % 4)) % 4), 'base64');
}

function hexToBytes(hex: string): Buffer {
	const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
	if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
		throw new SecureChannelError('malformed', 'Malformed hex value.');
	}
	return Buffer.from(clean, 'hex');
}

// X25519 raw ↔ DER (Node's KeyObject API has no raw import for X25519).
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

export function x25519PublicKeyFromRaw(raw: Uint8Array): ReturnType<typeof createPublicKey> {
	if (raw.length !== 32)
		throw new SecureChannelError('malformed', 'X25519 public key must be 32 bytes.');
	return createPublicKey({
		key: Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(raw)]),
		format: 'der',
		type: 'spki',
	});
}

export function x25519PrivateKeyFromRaw(raw: Uint8Array): ReturnType<typeof createPrivateKey> {
	if (raw.length !== 32)
		throw new SecureChannelError('malformed', 'X25519 private key must be 32 bytes.');
	return createPrivateKey({
		key: Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(raw)]),
		format: 'der',
		type: 'pkcs8',
	});
}

export function x25519RawPublicKey(key: ReturnType<typeof createPublicKey>): Buffer {
	const der = key.export({ format: 'der', type: 'spki' }) as Buffer;
	return der.subarray(der.length - 32);
}

// MARK: - Transcript, identity, key schedule

export function transcriptPayload(
	hello: ClientHello,
	serverHello: Omit<ServerHello, 'signature'>,
): Buffer {
	const canonical =
		`${TRANSCRIPT_DOMAIN}|v=${SECURE_CHANNEL_VERSION}|aA=${hello.agentAddress.toLowerCase()}` +
		`|eC=${hello.encPub}|nC=${hello.nonce}` +
		`|sid=${serverHello.sid}|eS=${serverHello.encPub}|exp=${serverHello.expiresAt}`;
	return Buffer.from(canonical, 'utf8');
}

/** `keccak256("\x19<prefix>:\n<len><payload>")` — the Osaurus domain-separated hash. */
export function domainHash(payload: Uint8Array, prefix = SIGNING_DOMAIN_PREFIX): Buffer {
	const header = Buffer.from(`\x19${prefix}:\n${payload.length}`, 'utf8');
	return keccak256(Buffer.concat([header, Buffer.from(payload)]));
}

/** EIP-55 checksummed address from an uncompressed secp256k1 public key. */
export function addressFromPublicKey(uncompressed: Uint8Array): string {
	const body = uncompressed.length === 65 ? uncompressed.subarray(1) : uncompressed;
	const hash = keccak256(body).subarray(12).toString('hex');
	const checksum = keccak256(Buffer.from(hash, 'ascii')).toString('hex');
	let out = '0x';
	for (let i = 0; i < hash.length; i += 1) {
		const c = hash[i];
		out += parseInt(checksum[i], 16) >= 8 ? c.toUpperCase() : c;
	}
	return out;
}

/** Recover the signer address of a 65-byte recoverable signature (`v = recid + 27` or `recid`). */
export function recoverAddress(
	payload: Uint8Array,
	signature: Uint8Array,
	prefix = SIGNING_DOMAIN_PREFIX,
): string {
	if (signature.length !== 65) {
		throw new SecureChannelError('malformed', 'Signature must be 65 bytes.');
	}
	let recid = signature[64];
	if (recid >= 27) recid -= 27;
	if (recid > 3) throw new SecureChannelError('malformed', 'Invalid recovery id.');
	const publicKey = tryRecoverPublicKey(
		domainHash(payload, prefix),
		signature.subarray(0, 64),
		recid,
	);
	if (!publicKey) {
		throw new SecureChannelError('malformed', 'Signature does not recover to a valid public key.');
	}
	return addressFromPublicKey(publicKey);
}

function tryRecoverPublicKey(hash: Uint8Array, rs: Uint8Array, recid: number): Buffer | null {
	try {
		return recoverPublicKey(hash, rs, recid);
	} catch {
		return null;
	}
}

export function deriveSessionKeys(
	sharedSecret: Uint8Array,
	transcript: Uint8Array,
): { c2s: Buffer; s2c: Buffer } {
	const salt = createHash('sha256').update(transcript).digest();
	const c2s = Buffer.from(
		hkdfSync('sha256', sharedSecret, salt, Buffer.from(`${TRANSCRIPT_DOMAIN}:c2s`, 'utf8'), 32),
	);
	const s2c = Buffer.from(
		hkdfSync('sha256', sharedSecret, salt, Buffer.from(`${TRANSCRIPT_DOMAIN}:s2c`, 'utf8'), 32),
	);
	return { c2s, s2c };
}

export function responseKey(s2c: Uint8Array, requestSeq: number): Buffer {
	return Buffer.from(
		hkdfSync(
			'sha256',
			s2c,
			Buffer.alloc(0),
			Buffer.from(`${TRANSCRIPT_DOMAIN}:respkey:${requestSeq}`, 'utf8'),
			32,
		),
	);
}

// MARK: - AEAD

/** 12-byte nonce: 4 zero bytes || big-endian u64 sequence. */
export function nonceForSequence(seq: number): Buffer {
	const nonce = Buffer.alloc(12);
	nonce.writeBigUInt64BE(BigInt(seq), 4);
	return nonce;
}

export function requestAAD(sid: string, seq: number): Buffer {
	return Buffer.from(`${TRANSCRIPT_DOMAIN}:req:${sid}:${seq}`, 'utf8');
}

export function responseAAD(sid: string, requestSeq: number, seq: number, fin: boolean): Buffer {
	return Buffer.from(
		`${TRANSCRIPT_DOMAIN}:resp:${sid}:${requestSeq}:${seq}:${fin ? 1 : 0}`,
		'utf8',
	);
}

/** ChaCha20-Poly1305 seal → base64url(ciphertext || 16-byte tag), matching CryptoKit's `combined` minus the nonce. */
export function seal(key: Uint8Array, seq: number, aad: Uint8Array, plaintext: Uint8Array): string {
	const cipher = createCipheriv('chacha20-poly1305', key, nonceForSequence(seq), {
		authTagLength: 16,
	});
	cipher.setAAD(aad, { plaintextLength: plaintext.length });
	const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	return base64urlEncode(Buffer.concat([ct, cipher.getAuthTag()]));
}

export function open(key: Uint8Array, seq: number, aad: Uint8Array, ctBase64url: string): Buffer {
	const combined = base64urlDecode(ctBase64url);
	if (combined.length < 16)
		throw new SecureChannelError('decryption_failed', 'Ciphertext too short.');
	const ct = combined.subarray(0, combined.length - 16);
	const tag = combined.subarray(combined.length - 16);
	const decipher = createDecipheriv('chacha20-poly1305', key, nonceForSequence(seq), {
		authTagLength: 16,
	});
	decipher.setAAD(aad, { plaintextLength: ct.length });
	decipher.setAuthTag(tag);
	const plaintext = attempt(() => Buffer.concat([decipher.update(ct), decipher.final()]));
	if (!plaintext)
		throw new SecureChannelError('decryption_failed', 'Failed to decrypt the peer response.');
	return plaintext;
}

/** Run `fn`, returning `undefined` instead of propagating a thrown error. */
function attempt<T>(fn: () => T): T | undefined {
	try {
		return fn();
	} catch {
		return undefined;
	}
}

// MARK: - Session

export class SecureSession {
	private nextSeq = 1;

	constructor(
		public readonly sid: string,
		private readonly c2s: Buffer,
		private readonly s2c: Buffer,
		/** Unix seconds. */
		public readonly expiresAt: number,
	) {}

	isUsable(nowSeconds = Date.now() / 1000): boolean {
		return this.expiresAt - SESSION_EXPIRY_MARGIN_SECONDS > nowSeconds;
	}

	sealCall(inner: InnerRequest): { call: CallRequest; requestSeq: number } {
		const seq = this.nextSeq;
		this.nextSeq += 1;
		const plaintext = Buffer.from(JSON.stringify(inner), 'utf8');
		const ct = seal(this.c2s, seq, requestAAD(this.sid, seq), plaintext);
		return { call: { v: SECURE_CHANNEL_VERSION, sid: this.sid, seq, ct }, requestSeq: seq };
	}

	makeResponseOpener(requestSeq: number): ResponseOpener {
		return new ResponseOpener(this.sid, requestSeq, responseKey(this.s2c, requestSeq));
	}
}

/** Opens response frames in order; refuses out-of-order, replayed, or post-fin frames. */
export class ResponseOpener {
	private expectedSeq = 0;
	private sawFin = false;

	constructor(
		private readonly sid: string,
		private readonly requestSeq: number,
		private readonly key: Buffer,
	) {}

	get finished(): boolean {
		return this.sawFin;
	}

	open(frame: Frame): { plaintext: Buffer; fin: boolean } {
		if (this.sawFin || frame.seq !== this.expectedSeq) {
			throw new SecureChannelError('out_of_order_frame', 'Response frame arrived out of order.');
		}
		const fin = frame.fin === true;
		const plaintext = open(
			this.key,
			frame.seq,
			responseAAD(this.sid, this.requestSeq, frame.seq, fin),
			frame.ct,
		);
		this.expectedSeq += 1;
		if (fin) this.sawFin = true;
		return { plaintext, fin };
	}
}

/** Decrypt a buffered `/secure/call` response: exactly one `fin` frame carrying an InnerResponse. */
export function openBufferedResponse(body: string, opener: ResponseOpener): InnerResponse {
	const frame = attempt(() => JSON.parse(body) as Frame);
	if (
		typeof frame !== 'object' ||
		frame === null ||
		typeof frame.seq !== 'number' ||
		typeof frame.ct !== 'string'
	) {
		throw new SecureChannelError('decryption_failed', 'Peer response was not an encrypted frame.');
	}
	const { plaintext, fin } = opener.open(frame);
	if (!fin)
		throw new SecureChannelError(
			'stream_truncated',
			'Encrypted response was truncated before completion.',
		);
	const inner = attempt(() => JSON.parse(plaintext.toString('utf8')) as InnerResponse);
	if (typeof inner !== 'object' || inner === null) {
		throw new SecureChannelError(
			'decryption_failed',
			'Decrypted response was not a valid envelope.',
		);
	}
	if (typeof inner.status !== 'number') {
		throw new SecureChannelError('decryption_failed', 'Decrypted response is missing its status.');
	}
	return inner;
}

// MARK: - Handshake

export function makeClientHello(
	agentAddress: string,
	ephemeralPrivate?: Uint8Array,
	nonce?: Uint8Array,
): {
	privateKey: ReturnType<typeof createPrivateKey>;
	hello: ClientHello;
} {
	let privateKey: ReturnType<typeof createPrivateKey>;
	let publicRaw: Buffer;
	if (ephemeralPrivate) {
		privateKey = x25519PrivateKeyFromRaw(ephemeralPrivate);
		publicRaw = x25519RawPublicKey(createPublicKey(privateKey));
	} else {
		const pair = generateKeyPairSync('x25519');
		privateKey = pair.privateKey;
		publicRaw = x25519RawPublicKey(pair.publicKey);
	}
	return {
		privateKey,
		hello: {
			v: SECURE_CHANNEL_VERSION,
			agentAddress: agentAddress.toLowerCase(),
			encPub: base64urlEncode(publicRaw),
			nonce: base64urlEncode(nonce ?? randomBytes(16)),
		},
	};
}

/** Verify the server hello against the pinned address and derive the session. */
export function establishClientSession(
	hello: ClientHello,
	ephemeralPrivate: ReturnType<typeof createPrivateKey>,
	serverHello: ServerHello,
	expectedAgentAddress: string,
): SecureSession {
	if (serverHello.v !== SECURE_CHANNEL_VERSION) {
		throw new SecureChannelError(
			'handshake_failed',
			`Peer answered Secure Channel v${serverHello.v}; this node speaks v1.`,
		);
	}
	if (
		!serverHello.sid ||
		typeof serverHello.encPub !== 'string' ||
		typeof serverHello.expiresAt !== 'number'
	) {
		throw new SecureChannelError('handshake_failed', 'Malformed server hello.');
	}
	const transcript = transcriptPayload(hello, serverHello);
	const recovered = attempt(() => recoverAddress(transcript, hexToBytes(serverHello.signature)));
	if (recovered === undefined) {
		throw new SecureChannelError('identity_mismatch', 'Peer signature could not be verified.');
	}
	if (recovered.toLowerCase() !== expectedAgentAddress.toLowerCase()) {
		throw new SecureChannelError(
			'identity_mismatch',
			`Peer identity mismatch: the pairing code pins ${expectedAgentAddress.toLowerCase()} but the server signed as ${recovered.toLowerCase()}. Re-copy the pairing code from Osaurus.`,
		);
	}
	const serverPub = attempt(() => x25519PublicKeyFromRaw(base64urlDecode(serverHello.encPub)));
	if (!serverPub) {
		throw new SecureChannelError('handshake_failed', 'Malformed server ephemeral key.');
	}
	const shared = diffieHellman({ privateKey: ephemeralPrivate, publicKey: serverPub });
	const { c2s, s2c } = deriveSessionKeys(shared, transcript);
	return new SecureSession(serverHello.sid, c2s, s2c, serverHello.expiresAt);
}

// MARK: - Client (session cache + retry semantics)

export type SecureCallResult = { status: number; body: string; contentType?: string };

const HANDLED_HEADERS = new Set([
	'authorization',
	'accept',
	'content-type',
	'content-length',
	'host',
	'connection',
]);

export class SecureChannelClient {
	private readonly sessions = new Map<string, SecureSession>();
	private readonly pending = new Map<string, Promise<SecureSession>>();

	constructor(
		private readonly http: HttpFn,
		private readonly timeoutMs = 15_000,
	) {}

	private static cacheKey(baseUrl: string, agentAddress: string): string {
		return `${baseUrl.replace(/\/+$/, '')}|${agentAddress.toLowerCase()}`;
	}

	invalidate(baseUrl: string, agentAddress: string): void {
		this.sessions.delete(SecureChannelClient.cacheKey(baseUrl, agentAddress));
	}

	/** Shared handshake: concurrent callers for the same peer await one promise. */
	async session(baseUrl: string, agentAddress: string): Promise<SecureSession> {
		const key = SecureChannelClient.cacheKey(baseUrl, agentAddress);
		const cached = this.sessions.get(key);
		if (cached && cached.isUsable()) return cached;
		const inflight = this.pending.get(key);
		if (inflight) return inflight;
		const promise = this.handshake(baseUrl, agentAddress)
			.then((session) => {
				this.sessions.set(key, session);
				return session;
			})
			.finally(() => this.pending.delete(key));
		this.pending.set(key, promise);
		return promise;
	}

	private async handshake(baseUrl: string, agentAddress: string): Promise<SecureSession> {
		const { privateKey, hello } = makeClientHello(agentAddress);
		const response = await this.http({
			method: 'POST',
			url: `${baseUrl.replace(/\/+$/, '')}/secure/session`,
			headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
			body: JSON.stringify(hello),
			timeoutMs: this.timeoutMs,
		});
		if (response.status === 404) {
			throw new SecureChannelError(
				'peer_unsupported',
				`${baseUrl} does not offer Secure Channel for agent ${agentAddress.toLowerCase()} (404 on /secure/session). Make sure the agent bound in Osaurus → Channels → n8n → How Osaurus replies still exists, then re-copy the pairing code.`,
			);
		}
		if (response.status === 429) {
			throw new SecureChannelError(
				'handshake_failed',
				'Osaurus is rate-limiting handshakes. Try again shortly.',
			);
		}
		if (response.status !== 200) {
			throw new SecureChannelError(
				'handshake_failed',
				`Secure Channel handshake failed: HTTP ${response.status} ${response.body.slice(0, 300)}`,
			);
		}
		const serverHello = attempt(() => JSON.parse(response.body) as ServerHello);
		if (typeof serverHello !== 'object' || serverHello === null) {
			throw new SecureChannelError('handshake_failed', 'Malformed server hello.');
		}
		return establishClientSession(hello, privateKey, serverHello, agentAddress);
	}

	/**
	 * Send one plaintext request through `/secure/call`. Retries exactly once
	 * on `401 secure_session_unknown` (re-handshake); never retransmits on
	 * `409 secure_replay`; never downgrades to plaintext.
	 */
	async request(
		baseUrl: string,
		agentAddress: string,
		inner: {
			method: string;
			path: string;
			headers?: Record<string, string>;
			body?: string | Buffer;
			accept?: string;
			contentType?: string;
		},
	): Promise<SecureCallResult> {
		const sendOnce = async (): Promise<SecureCallResult | 'retry'> => {
			const session = await this.session(baseUrl, agentAddress);
			const extra: Record<string, string> = {};
			for (const [name, value] of Object.entries(inner.headers ?? {})) {
				if (!HANDLED_HEADERS.has(name.toLowerCase())) extra[name] = value;
			}
			const innerRequest: InnerRequest = {
				method: inner.method,
				path: inner.path,
				accept: inner.accept ?? 'application/json',
			};
			if (inner.contentType) innerRequest.contentType = inner.contentType;
			if (Object.keys(extra).length > 0) innerRequest.headers = extra;
			if (inner.body !== undefined) {
				innerRequest.body = base64urlEncode(
					typeof inner.body === 'string' ? Buffer.from(inner.body, 'utf8') : inner.body,
				);
			}
			const { call, requestSeq } = session.sealCall(innerRequest);
			const outer = await this.http({
				method: 'POST',
				url: `${baseUrl.replace(/\/+$/, '')}/secure/call`,
				headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
				body: JSON.stringify(call),
				timeoutMs: this.timeoutMs,
			});
			if (outer.status === 401 && outer.body.includes('secure_session_unknown')) {
				this.invalidate(baseUrl, agentAddress);
				return 'retry';
			}
			if (outer.status === 409 && outer.body.includes('secure_replay')) {
				throw new SecureChannelError(
					'replay_rejected',
					'Osaurus rejected the call as a replay; it was not re-sent.',
				);
			}
			if (outer.status !== 200) {
				throw new SecureChannelError(
					'handshake_failed',
					`Secure Channel call failed: HTTP ${outer.status} ${outer.body.slice(0, 300)}`,
				);
			}
			const response = openBufferedResponse(outer.body, session.makeResponseOpener(requestSeq));
			const body = response.body ? base64urlDecode(response.body).toString('utf8') : '';
			return { status: response.status, body, contentType: response.contentType };
		};

		const first = await sendOnce();
		if (first !== 'retry') return first;
		const second = await sendOnce();
		if (second === 'retry') {
			throw new SecureChannelError(
				'session_unknown',
				'Osaurus did not recognise the Secure Channel session after a fresh handshake.',
			);
		}
		return second;
	}
}
