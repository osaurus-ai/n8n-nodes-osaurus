import { createHmac, timingSafeEqual } from 'crypto';

export const DEFAULT_SIGNATURE_HEADER = 'X-Osaurus-Channel-Signature';
export const DEFAULT_SECRET_HEADER = 'X-Osaurus-Channel-Secret';
export const SIGNATURE_PREFIX = 'sha256=';

export type ChannelVerificationMethod = 'hmac_sha256' | 'shared_secret_header';

export type InboundAttachment = {
	id: string;
	filename?: string;
	content_type?: string;
	size_bytes?: number;
	url?: string;
};

export type InboundEnvelopeInput = {
	eventId: string;
	conversationId: string;
	senderId: string;
	content: string;
	senderDisplay?: string;
	senderIsBot?: boolean;
	threadId?: string;
	attachments?: InboundAttachment[];
	replyToken?: string;
};

export type OutboundPushEnvelope = {
	v: number;
	event_id?: string;
	connection_id?: string;
	conversation_id?: string;
	thread_id?: string;
	sender?: { id?: string; display?: string; is_bot?: boolean };
	content?: string;
};

function utf8(value: string): Buffer {
	return Buffer.from(value, 'utf8');
}

function equal(a: string, b: string): boolean {
	const left = utf8(a);
	const right = utf8(b);
	if (left.length !== right.length) {
		return false;
	}
	return timingSafeEqual(left, right);
}

/** HMAC-SHA256 of the exact raw bytes, prefixed with `sha256=`. */
export function signBody(secret: string, raw: string): string {
	const hex = createHmac('sha256', secret).update(utf8(raw)).digest('hex');
	return `${SIGNATURE_PREFIX}${hex}`;
}

/**
 * Accepts `sha256=<hex>` or a bare hex digest. Comparison is constant-time
 * against the expected HMAC of `raw`.
 */
export function verifySignature(secret: string, raw: string, header: string): boolean {
	const trimmed = header.trim();
	const provided = trimmed.toLowerCase().startsWith(SIGNATURE_PREFIX)
		? trimmed.slice(SIGNATURE_PREFIX.length)
		: trimmed;
	const expected = createHmac('sha256', secret).update(utf8(raw)).digest('hex');
	return equal(provided.toLowerCase(), expected.toLowerCase());
}

export function verifySharedSecret(secret: string, header: string): boolean {
	return equal(header, secret);
}

export function defaultHeaderName(method: ChannelVerificationMethod): string {
	return method === 'hmac_sha256' ? DEFAULT_SIGNATURE_HEADER : DEFAULT_SECRET_HEADER;
}

export function channelAuthHeaders(
	method: ChannelVerificationMethod,
	secret: string,
	raw: string,
	headerName?: string,
): Record<string, string> {
	const name = (headerName ?? '').trim() || defaultHeaderName(method);
	if (method === 'shared_secret_header') {
		return { [name]: secret };
	}
	return { [name]: signBody(secret, raw) };
}

/** Compact JSON. Key order is stable so HMAC bytes match the transmitted body. */
export function buildInboundEnvelope(input: InboundEnvelopeInput): string {
	const sender: Record<string, unknown> = { id: input.senderId };
	if (input.senderDisplay !== undefined && input.senderDisplay !== '') {
		sender.display = input.senderDisplay;
	}
	if (input.senderIsBot !== undefined) {
		sender.is_bot = input.senderIsBot;
	}

	const body: Record<string, unknown> = {
		v: 1,
		event_id: input.eventId,
		conversation_id: input.conversationId,
		sender,
		content: input.content,
	};
	if (input.threadId) {
		body.thread_id = input.threadId;
	}
	if (input.attachments && input.attachments.length > 0) {
		body.attachments = input.attachments;
	}
	if (input.replyToken) {
		body.reply_token = input.replyToken;
	}
	return JSON.stringify(body);
}

export function parseOutboundPushEnvelope(raw: string): OutboundPushEnvelope {
	const parsed = JSON.parse(raw) as unknown;
	if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
		throw new Error('Outbound push body must be a JSON object.');
	}
	const object = parsed as Record<string, unknown>;
	const version = typeof object.v === 'number' ? object.v : Number(object.v);
	if (version !== 1) {
		throw new Error(`Unsupported outbound envelope version ${String(object.v)}; expected v=1.`);
	}
	return object as OutboundPushEnvelope;
}

export function joinUrl(baseUrl: string, path: string): string {
	const base = baseUrl.replace(/\/+$/, '');
	const suffix = path.startsWith('/') ? path : `/${path}`;
	return `${base}${suffix}`;
}

export function inboundUrl(baseUrl: string, connectionId: string): string {
	return joinUrl(baseUrl, `/channels/n8n/${connectionId}/inbound`);
}

export function taskUrl(baseUrl: string, connectionId: string, taskId: string): string {
	return joinUrl(baseUrl, `/channels/n8n/${connectionId}/tasks/${taskId}`);
}

export function pingUrl(baseUrl: string, connectionId: string): string {
	return joinUrl(baseUrl, `/channels/n8n/${connectionId}/ping`);
}

export function isTerminalTaskStatus(status: string): boolean {
	return status === 'completed' || status === 'failed' || status === 'cancelled';
}
