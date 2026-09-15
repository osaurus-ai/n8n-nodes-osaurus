import { describe, expect, it } from 'vitest';

import { describeInboundOutcome } from '../src/inboundOutcome';

const cfg = { connectionId: 'n8n-local' };
const sent = { conversationId: 'invoice-sync', senderId: 'workflow' };

describe('describeInboundOutcome', () => {
	it('returns null when the event was accepted and dispatched', () => {
		expect(describeInboundOutcome({ status: 'accepted', dispatch: 'agent' }, cfg, sent)).toBeNull();
		expect(describeInboundOutcome({ status: 'accepted' }, cfg, sent)).toBeNull();
	});

	it('explains pending_approval with the exact ids and the Prove it step', () => {
		const failure = describeInboundOutcome(
			{ status: 'rejected', reason: 'pending_approval' },
			cfg,
			sent,
		);
		expect(failure).not.toBeNull();
		expect(failure?.message).toContain("connection 'n8n-local'");
		expect(failure?.message).toContain('Prove it');
		expect(failure?.message).toContain("conversation 'invoice-sync'");
		expect(failure?.message).toContain("sender 'workflow'");
		expect(failure?.message).toMatch(/run this workflow again/);
		expect(failure?.description).toMatch(/Nothing was sent to the agent/);
	});

	it('still handles the bare allowlist verdicts from older Osaurus builds', () => {
		const sender = describeInboundOutcome(
			{ status: 'rejected', reason: 'sender_not_allowlisted' },
			cfg,
			sent,
		);
		expect(sender?.message).toContain("sender 'workflow'");
		expect(sender?.message).toContain('Prove it → Advanced → Allowed Senders');

		const room = describeInboundOutcome(
			{ status: 'rejected', reason: 'room_not_allowlisted' },
			cfg,
			sent,
		);
		expect(room?.message).toContain("conversation 'invoice-sync'");
		expect(room?.message).toContain('Prove it → Advanced → Allowed Conversations');
	});

	it('points bot denials and unknown reasons at Prove it', () => {
		expect(
			describeInboundOutcome({ status: 'rejected', reason: 'bot_message_denied' }, cfg, sent)
				?.message,
		).toContain('Accept Bot Senders under Prove it → Advanced');
		expect(describeInboundOutcome({ status: 'rejected' }, cfg, sent)?.message).toContain(
			'unknown reason',
		);
	});

	it('points a suppressed dispatch at Who answers?', () => {
		const failure = describeInboundOutcome(
			{ status: 'accepted', dispatch: 'suppressed:no_agent_bound' },
			cfg,
			sent,
		);
		expect(failure?.message).toContain('no_agent_bound');
		expect(failure?.message).toContain('Who answers?');
	});

	it('never mentions the retired step names', () => {
		const reasons = [
			'pending_approval',
			'sender_not_allowlisted',
			'room_not_allowlisted',
			'bot_message_denied',
			'x',
		];
		const messages = reasons.map(
			(reason) => describeInboundOutcome({ status: 'rejected', reason }, cfg, sent)?.message ?? '',
		);
		messages.push(
			describeInboundOutcome({ status: 'accepted', dispatch: 'suppressed:disabled' }, cfg, sent)
				?.message ?? '',
		);
		for (const message of messages) {
			expect(message).not.toMatch(/Who may speak|How Osaurus replies|Connect n8n|Live check/);
		}
	});
});
