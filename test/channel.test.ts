import { describe, expect, it } from 'vitest';

import {
	buildInboundEnvelope,
	channelAuthHeaders,
	inboundUrl,
	isTerminalTaskStatus,
	parseOutboundPushEnvelope,
	signBody,
	taskUrl,
	verifySharedSecret,
	verifySignature,
} from '../src/channel';

const HMAC_FIXTURE = 'n8n-outbound-secret-0123456789';
const KNOWN_BODY = '{"content":"hello n8n"}';
const KNOWN_HEX = '443fd1daf84b1ab9f3c22c2a1bf0fc26c4d0359d8496407a60288833422eb0ef';

describe('signBody / verifySignature', () => {
	it('matches the Osaurus custom-HTTP known answer', () => {
		expect(signBody(HMAC_FIXTURE, KNOWN_BODY)).toBe(`sha256=${KNOWN_HEX}`);
		expect(verifySignature(HMAC_FIXTURE, KNOWN_BODY, `sha256=${KNOWN_HEX}`)).toBe(true);
		expect(verifySignature(HMAC_FIXTURE, KNOWN_BODY, KNOWN_HEX)).toBe(true);
	});

	it('rejects a tampered body or secret', () => {
		expect(verifySignature(HMAC_FIXTURE, '{"content":"nope"}', `sha256=${KNOWN_HEX}`)).toBe(false);
		expect(verifySignature('wrong-secret', KNOWN_BODY, `sha256=${KNOWN_HEX}`)).toBe(false);
	});

	it('signs the empty body used by poll GET', () => {
		const empty = signBody(HMAC_FIXTURE, '');
		expect(empty.startsWith('sha256=')).toBe(true);
		expect(verifySignature(HMAC_FIXTURE, '', empty)).toBe(true);
	});
});

describe('channelAuthHeaders', () => {
	it('sends HMAC of the raw body', () => {
		expect(channelAuthHeaders('hmac_sha256', HMAC_FIXTURE, KNOWN_BODY)).toEqual({
			'X-Osaurus-Channel-Signature': `sha256=${KNOWN_HEX}`,
		});
	});

	it('sends the shared secret verbatim', () => {
		expect(channelAuthHeaders('shared_secret_header', 's3cret', '')).toEqual({
			'X-Osaurus-Channel-Secret': 's3cret',
		});
		expect(verifySharedSecret('s3cret', 's3cret')).toBe(true);
		expect(verifySharedSecret('s3cret', 'nope')).toBe(false);
	});

	it('honors a custom header name', () => {
		expect(
			channelAuthHeaders('shared_secret_header', 's3cret', '', 'X-Custom-Secret'),
		).toEqual({
			'X-Custom-Secret': 's3cret',
		});
	});
});

describe('buildInboundEnvelope', () => {
	it('emits compact v1 JSON with stable key order', () => {
		const raw = buildInboundEnvelope({
			eventId: 'n8n:exec-1',
			conversationId: 'n8n-test',
			senderId: 'tpae',
			content: 'Reply with the single word PONG',
		});
		expect(raw).toBe(
			'{"v":1,"event_id":"n8n:exec-1","conversation_id":"n8n-test","sender":{"id":"tpae"},"content":"Reply with the single word PONG"}',
		);
		expect(raw.includes('\n')).toBe(false);
	});

	it('includes optional sender and thread fields when set', () => {
		const raw = buildInboundEnvelope({
			eventId: 'evt',
			conversationId: 'n8n-test',
			senderId: 'workflow',
			senderDisplay: 'n8n',
			senderIsBot: true,
			threadId: 'thread-1',
			content: 'hi',
		});
		const parsed = JSON.parse(raw) as {
			sender: { id: string; display: string; is_bot: boolean };
			thread_id: string;
		};
		expect(parsed.sender).toEqual({ id: 'workflow', display: 'n8n', is_bot: true });
		expect(parsed.thread_id).toBe('thread-1');
	});
});

describe('parseOutboundPushEnvelope', () => {
	it('accepts a v1 outbound push', () => {
		const envelope = parseOutboundPushEnvelope(
			'{"v":1,"connection_id":"n8n-local","conversation_id":"n8n-test","content":"PONG"}',
		);
		expect(envelope.connection_id).toBe('n8n-local');
		expect(envelope.content).toBe('PONG');
	});

	it('rejects a non-v1 body', () => {
		expect(() => parseOutboundPushEnvelope('{"v":2}')).toThrow(/version/);
	});
});

describe('urls and task status', () => {
	it('joins inbound and poll URLs', () => {
		expect(inboundUrl('http://127.0.0.1:1337/', 'n8n-local')).toBe(
			'http://127.0.0.1:1337/channels/n8n/n8n-local/inbound',
		);
		expect(taskUrl('http://host.docker.internal:1337', 'n8n-local', 'abc')).toBe(
			'http://host.docker.internal:1337/channels/n8n/n8n-local/tasks/abc',
		);
	});

	it('treats completed, failed, and cancelled as terminal', () => {
		expect(isTerminalTaskStatus('queued')).toBe(false);
		expect(isTerminalTaskStatus('running')).toBe(false);
		expect(isTerminalTaskStatus('completed')).toBe(true);
		expect(isTerminalTaskStatus('failed')).toBe(true);
		expect(isTerminalTaskStatus('cancelled')).toBe(true);
	});
});
