import type { ChannelVerificationMethod } from './channel';

/**
 * Pairing code issued by Osaurus → Settings → Channels → n8n → Connect n8n → "Pair with n8n".
 *
 *     osrs-n8n-1.<base64url(compact JSON)>
 *
 * The payload is `N8nPairingCode` on the Swift side. It contains the channel
 * secret, so the whole string must be treated as a secret.
 */
export const PAIRING_CODE_PREFIX = 'osrs-n8n-';
export const PAIRING_CODE_VERSION = 1;

export type PairingCodePayload = {
	v: number;
	/** Ordered base-URL candidates; try first-to-last. */
	urls: string[];
	/** Connection id. */
	cid: string;
	/** Channel secret. */
	secret: string;
	/** Verification method. */
	vfy: string;
	/** Header-name override, present only when the sheet set one. */
	hdr?: string;
	/** Pinned agent address (0x…). Present → Secure Channel to every candidate. */
	addr?: string;
	/** Display name. */
	name?: string;
};

/** Everything the node needs to reach one Osaurus channel. */
export type ChannelConfig = {
	/** Ordered base URLs to try. Never empty. */
	candidates: string[];
	connectionId: string;
	secret: string;
	verificationMethod: ChannelVerificationMethod;
	/** Empty string means "use the method's default header". */
	headerName: string;
	/** Lowercased 0x… address when the code carries one. */
	agentAddress?: string;
	/** Display name from the code, if any. */
	name?: string;
	/** Where the config came from — surfaced in credential-test messages. */
	source: 'pairing_code' | 'manual';
};

export class PairingCodeError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'PairingCodeError';
	}
}

function base64urlDecode(value: string): Buffer {
	const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
	const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
	return Buffer.from(padded, 'base64');
}

/** `JSON.parse` that yields `undefined` instead of throwing on malformed input. */
function tryParseJson(text: string): unknown {
	try {
		return JSON.parse(text) as unknown;
	} catch {
		return undefined;
	}
}

function stripTrailingSlashes(url: string): string {
	return url.trim().replace(/\/+$/, '');
}

function normalizeMethod(value: unknown): ChannelVerificationMethod {
	return value === 'shared_secret_header' ? 'shared_secret_header' : 'hmac_sha256';
}

/** Decode and validate a pairing code. Throws `PairingCodeError` with actionable text. */
export function decodePairingCode(code: string): PairingCodePayload {
	const trimmed = code.trim();
	if (!trimmed.startsWith(PAIRING_CODE_PREFIX)) {
		throw new PairingCodeError(
			'This is not an Osaurus pairing code. Copy it from Osaurus → Settings → Channels → n8n → Connect n8n → Pair with n8n (it starts with "osrs-n8n-1.").',
		);
	}
	const dot = trimmed.indexOf('.');
	if (dot < 0) {
		throw new PairingCodeError('Pairing code is truncated: missing the "." separator.');
	}
	const version = Number(trimmed.slice(PAIRING_CODE_PREFIX.length, dot));
	if (!Number.isInteger(version)) {
		throw new PairingCodeError('Pairing code has a malformed version prefix.');
	}
	if (version !== PAIRING_CODE_VERSION) {
		throw new PairingCodeError(
			`Pairing code version ${version} is not supported by this node (expected ${PAIRING_CODE_VERSION}). Update n8n-nodes-osaurus.`,
		);
	}
	const parsed = tryParseJson(base64urlDecode(trimmed.slice(dot + 1)).toString('utf8'));
	if (parsed === undefined) {
		throw new PairingCodeError('Pairing code payload is not valid; copy it again from Osaurus.');
	}
	if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
		throw new PairingCodeError('Pairing code payload must be a JSON object.');
	}
	const object = parsed as Record<string, unknown>;
	if (object.v !== PAIRING_CODE_VERSION) {
		throw new PairingCodeError(
			`Pairing code payload version ${String(object.v)} is not supported.`,
		);
	}
	const urls = Array.isArray(object.urls)
		? object.urls.filter((u): u is string => typeof u === 'string' && u.trim() !== '')
		: [];
	if (urls.length === 0) {
		throw new PairingCodeError('Pairing code carries no URLs.');
	}
	const cid = typeof object.cid === 'string' ? object.cid.trim() : '';
	if (!cid) {
		throw new PairingCodeError('Pairing code is missing the connection id.');
	}
	const secret = typeof object.secret === 'string' ? object.secret : '';
	if (!secret) {
		throw new PairingCodeError('Pairing code is missing the channel secret.');
	}
	const payload: PairingCodePayload = {
		v: PAIRING_CODE_VERSION,
		urls,
		cid,
		secret,
		vfy: typeof object.vfy === 'string' ? object.vfy : 'hmac_sha256',
	};
	if (typeof object.hdr === 'string' && object.hdr.trim()) payload.hdr = object.hdr.trim();
	if (typeof object.addr === 'string' && object.addr.trim())
		payload.addr = object.addr.trim().toLowerCase();
	if (typeof object.name === 'string' && object.name.trim()) payload.name = object.name.trim();
	return payload;
}

export function configFromPairingCode(code: string): ChannelConfig {
	const payload = decodePairingCode(code);
	return {
		candidates: payload.urls.map(stripTrailingSlashes).filter((u) => u !== ''),
		connectionId: payload.cid,
		secret: payload.secret,
		verificationMethod: normalizeMethod(payload.vfy),
		headerName: payload.hdr ?? '',
		agentAddress: payload.addr,
		name: payload.name,
		source: 'pairing_code',
	};
}

/**
 * Resolve the Channel credential into a config. `setup: "pairingCode"` (or a
 * non-empty `pairingCode` with no explicit setup, for forward compatibility)
 * decodes the code; anything else reads the legacy four fields.
 */
export function resolveChannelConfig(data: Record<string, unknown>): ChannelConfig {
	const setup = typeof data.setup === 'string' ? data.setup : '';
	const code = typeof data.pairingCode === 'string' ? data.pairingCode.trim() : '';
	const baseUrl = stripTrailingSlashes(String(data.baseUrl ?? ''));
	const connectionId = String(data.connectionId ?? '').trim();
	const secret = String(data.secret ?? '');
	const hasManualFields = baseUrl !== '' && connectionId !== '' && secret !== '';

	if (code !== '' && setup !== 'manual') {
		return configFromPairingCode(code);
	}
	if (setup === 'pairingCode' && !hasManualFields) {
		throw new PairingCodeError(
			'Paste the pairing code from Osaurus → Settings → Channels → n8n → Connect n8n → Pair with n8n, or switch Setup to Manual.',
		);
	}
	// Manual, or a credential saved by 0.1.x before the Setup field existed.
	if (!hasManualFields) {
		throw new PairingCodeError(
			'Manual setup needs Base URL, Connection ID and Channel Secret — or paste a pairing code instead.',
		);
	}
	return {
		candidates: [baseUrl],
		connectionId,
		secret,
		verificationMethod: normalizeMethod(data.verificationMethod),
		headerName: String(data.headerName ?? '').trim(),
		agentAddress: undefined,
		source: 'manual',
	};
}
