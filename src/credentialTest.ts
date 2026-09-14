import type {
	ICredentialTestFunctions,
	ICredentialsDecrypted,
	INodeCredentialTestResult,
} from 'n8n-workflow';

import { httpFromCredentialTest } from './n8nHttp';
import { resolveChannelConfig } from './pairing';
import {
	describeConnection,
	forgetSelectedBaseUrl,
	makeTransport,
	selectBaseUrl,
} from './transport';

/**
 * Shared `osaurusChannelApi` credential test. Both the Osaurus node and the
 * Osaurus Trigger reference it via `testedBy`, so pressing **Test** on the
 * credential decodes the pairing code (or manual fields), probes every URL
 * candidate with `GET /channels/n8n/{id}/ping` — over Secure Channel when the
 * code pins an agent — and names the URL it reached.
 */
export async function testOsaurusChannelCredential(
	this: ICredentialTestFunctions,
	credential: ICredentialsDecrypted,
): Promise<INodeCredentialTestResult> {
	const resolved = resolveOrError((credential.data ?? {}) as Record<string, unknown>);
	if ('error' in resolved) return { status: 'Error', message: resolved.error };
	const { config } = resolved;
	const transport = makeTransport(config, httpFromCredentialTest(this));
	try {
		// Always re-probe on an explicit Test so a stale cached winner never
		// masks a changed network.
		const selected = await selectBaseUrl(config, transport, { forceProbe: true });
		return { status: 'OK', message: describeConnection(selected, transport) };
	} catch (error) {
		forgetSelectedBaseUrl(config);
		return { status: 'Error', message: (error as Error).message };
	}
}

function resolveOrError(
	data: Record<string, unknown>,
): { config: ReturnType<typeof resolveChannelConfig> } | { error: string } {
	try {
		return { config: resolveChannelConfig(data) };
	} catch (error) {
		return { error: (error as Error).message };
	}
}
