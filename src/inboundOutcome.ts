import type { ChannelConfig } from './pairing';

/** Operator-facing failure for a 202 body that did not reach an agent. */
export type InboundOutcomeFailure = { message: string; description?: string };

/**
 * The Osaurus ingress answers 202 for accepted, rejected and suppressed
 * events alike. This is the pure mapping from that body to the failure the
 * node raises, so the copy (and the step names it points at) is unit-testable
 * without an n8n execution context. Returns null when the event was accepted
 * and dispatched.
 */
export function describeInboundOutcome(
	response: Record<string, unknown>,
	config: Pick<ChannelConfig, 'connectionId'>,
	sent: { conversationId: string; senderId: string },
): InboundOutcomeFailure | null {
	const status = String(response.status ?? '');
	const reason = String(response.reason ?? '');
	const where = `Osaurus → Settings → Channels → n8n (connection '${config.connectionId}')`;
	if (status === 'rejected') {
		switch (reason) {
			case 'pending_approval':
				return {
					message: `Osaurus is waiting for you to approve this workflow. Open ${where} → Prove it, press Allow for conversation '${sent.conversationId}' / sender '${sent.senderId}', then run this workflow again.`,
					description:
						'Approve-on-first-contact: the event reached Osaurus with a valid secret, but this conversation / sender pair has not been allowed yet. Nothing was sent to the agent. Approving is remembered for future runs.',
				};
			// Older Osaurus builds (and identities denied this session) answer
			// with the bare allowlist verdict.
			case 'sender_not_allowlisted':
				return {
					message: `Osaurus rejected the event: sender '${sent.senderId}' is not allowed on connection '${config.connectionId}'. Allow it under Prove it (or add it by hand under Prove it → Advanced → Allowed Senders) in ${where}, then run again.`,
					description:
						'The Sender ID this node sends must exactly match an allowed sender. If you pressed Deny for it in Osaurus, it stays rejected until you add it by hand.',
				};
			case 'room_not_allowlisted':
				return {
					message: `Osaurus rejected the event: conversation '${sent.conversationId}' is not allowed on connection '${config.connectionId}'. Allow it under Prove it (or add it by hand under Prove it → Advanced → Allowed Conversations) in ${where}, then run again.`,
					description:
						'The Conversation ID this node sends must exactly match an allowed conversation. If you pressed Deny for it in Osaurus, it stays rejected until you add it by hand.',
				};
			case 'bot_message_denied':
				return {
					message: `Osaurus rejected the event: bot senders are not allowed. Turn off "Sender is bot" on this node or enable Accept Bot Senders under Prove it → Advanced in ${where}.`,
				};
			default:
				return {
					message: `Osaurus rejected the event (${reason || 'unknown reason'}). Check Prove it in ${where}.`,
				};
		}
	}
	const dispatch = String(response.dispatch ?? '');
	if (dispatch.startsWith('suppressed')) {
		const detail = dispatch.slice('suppressed:'.length) || 'unknown';
		return {
			message: `Osaurus stored the event but did not run an agent (${detail}). Turn on Reply with an Agent and pick an agent under Who answers? in ${where}.`,
		};
	}
	return null;
}
