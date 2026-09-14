import { createHash } from 'crypto';

import { channelAuthHeaders, joinUrl } from './channel';
import type { ChannelConfig } from './pairing';
import type { HttpFn } from './secureChannel';
import { SecureChannelClient, SecureChannelError } from './secureChannel';

/** Result of one channel request, transport-agnostic. */
export type ChannelResponse = { status: number; body: string };

/**
 * A way to reach `/channels/n8n/...` on one Osaurus base URL. `Plaintext`
 * speaks HTTP directly; `SecureChannel` wraps every request in `/secure/call`
 * pinned to the pairing code's agent address.
 */
export interface ChannelTransport {
	readonly kind: 'plaintext' | 'secure_channel';
	request(
		baseUrl: string,
		method: 'GET' | 'POST',
		path: string,
		rawBody: string,
		headers: Record<string, string>,
	): Promise<ChannelResponse>;
}

export class PlaintextTransport implements ChannelTransport {
	readonly kind = 'plaintext' as const;

	constructor(
		private readonly http: HttpFn,
		private readonly timeoutMs = 30_000,
	) {}

	async request(
		baseUrl: string,
		method: 'GET' | 'POST',
		path: string,
		rawBody: string,
		headers: Record<string, string>,
	): Promise<ChannelResponse> {
		const merged: Record<string, string> = { Accept: 'application/json', ...headers };
		if (method === 'POST') merged['Content-Type'] = 'application/json';
		const response = await this.http({
			method,
			url: joinUrl(baseUrl, path),
			headers: merged,
			body: method === 'POST' ? rawBody : undefined,
			timeoutMs: this.timeoutMs,
		});
		return { status: response.status, body: response.body };
	}
}

export class SecureChannelTransport implements ChannelTransport {
	readonly kind = 'secure_channel' as const;

	constructor(
		private readonly client: SecureChannelClient,
		private readonly agentAddress: string,
	) {}

	async request(
		baseUrl: string,
		method: 'GET' | 'POST',
		path: string,
		rawBody: string,
		headers: Record<string, string>,
	): Promise<ChannelResponse> {
		const response = await this.client.request(baseUrl, this.agentAddress, {
			method,
			path,
			headers,
			accept: 'application/json',
			contentType: method === 'POST' ? 'application/json' : undefined,
			body: method === 'POST' ? rawBody : undefined,
		});
		return { status: response.status, body: response.body };
	}
}

/** Rule: an agent address in the code means Secure Channel for every candidate. */
export function makeTransport(
	config: ChannelConfig,
	http: HttpFn,
	secureClient?: SecureChannelClient,
): ChannelTransport {
	if (config.agentAddress) {
		return new SecureChannelTransport(
			secureClient ?? new SecureChannelClient(http),
			config.agentAddress,
		);
	}
	return new PlaintextTransport(http);
}

export function pingPath(connectionId: string): string {
	return `/channels/n8n/${connectionId}/ping`;
}

export type PingResult = {
	baseUrl: string;
	status: number;
	body: string;
	/** Parsed `/ping` body when it was 200. */
	ok?: {
		connection_id?: string;
		verification?: string;
		secure_channel?: boolean;
		transport?: string;
	};
	/** Network / handshake failure when no HTTP status came back. */
	error?: string;
};

export type ProbeAttempt = PingResult;

export class NoReachableCandidateError extends Error {
	constructor(
		message: string,
		public readonly attempts: ProbeAttempt[],
	) {
		super(message);
		this.name = 'NoReachableCandidateError';
	}
}

/** Selected base URL per config hash; survives across executions in one n8n process. */
const selectedBaseUrls = new Map<string, string>();

export function configCacheKey(config: ChannelConfig): string {
	return createHash('sha256')
		.update(
			JSON.stringify([
				config.candidates,
				config.connectionId,
				config.secret,
				config.verificationMethod,
				config.headerName,
				config.agentAddress ?? '',
			]),
		)
		.digest('hex');
}

export function forgetSelectedBaseUrl(config: ChannelConfig): void {
	selectedBaseUrls.delete(configCacheKey(config));
}

/** Test seam. */
export function resetSelectedBaseUrls(): void {
	selectedBaseUrls.clear();
}

export async function pingCandidate(
	config: ChannelConfig,
	transport: ChannelTransport,
	baseUrl: string,
): Promise<PingResult> {
	const headers = channelAuthHeaders(
		config.verificationMethod,
		config.secret,
		'',
		config.headerName,
	);
	try {
		const response = await transport.request(
			baseUrl,
			'GET',
			pingPath(config.connectionId),
			'',
			headers,
		);
		const result: PingResult = { baseUrl, status: response.status, body: response.body };
		if (response.status === 200) {
			try {
				result.ok = JSON.parse(response.body) as PingResult['ok'];
			} catch {
				result.ok = {};
			}
		}
		return result;
	} catch (error) {
		return { baseUrl, status: 0, body: '', error: describeError(error) };
	}
}

function describeError(error: unknown): string {
	if (error instanceof SecureChannelError) return error.message;
	if (error instanceof Error) return error.message;
	return String(error);
}

/** Human-readable reason for a failed candidate, with the fix the user can apply. */
export function explainProbe(result: PingResult, config: ChannelConfig): string {
	if (result.error) return `${result.baseUrl}: ${result.error}`;
	switch (result.status) {
		case 401:
			return `${result.baseUrl}: channel secret rejected (401). The pairing code is stale — regenerate the secret in Osaurus and copy a fresh code.`;
		case 403:
			return `${result.baseUrl}: connection is disabled in Osaurus (403).`;
		case 404:
			return `${result.baseUrl}: connection '${config.connectionId}' not found (404). Check the connection still exists in Osaurus → Settings → Channels → n8n.`;
		case 426:
			return `${result.baseUrl}: remote callers need Secure Channel (426). Bind a local agent in Osaurus → Channels → n8n → How Osaurus replies and copy a fresh pairing code from Connect n8n, or turn on Remote callers there.`;
		case 429:
			return `${result.baseUrl}: rate limited (429). Wait a few seconds and test again.`;
		default:
			return `${result.baseUrl}: HTTP ${result.status} ${result.body.slice(0, 200)}`;
	}
}

/**
 * Try candidates in order with `/ping`; first 200 wins and is cached. A
 * cached winner is re-verified only on network error (not on HTTP errors,
 * which are authoritative answers from the right server).
 */
export async function selectBaseUrl(
	config: ChannelConfig,
	transport: ChannelTransport,
	options: { forceProbe?: boolean } = {},
): Promise<{ baseUrl: string; ping: PingResult; attempts: PingResult[] }> {
	const key = configCacheKey(config);
	const attempts: PingResult[] = [];
	if (!options.forceProbe) {
		const cached = selectedBaseUrls.get(key);
		if (cached) {
			const ping = await pingCandidate(config, transport, cached);
			attempts.push(ping);
			if (ping.status === 200) return { baseUrl: cached, ping, attempts };
			// Authoritative HTTP answer (401/403/404/426): no other candidate
			// will do better; surface it now.
			if (!ping.error && ping.status !== 0) {
				throw new NoReachableCandidateError(explainProbe(ping, config), attempts);
			}
			selectedBaseUrls.delete(key);
		}
	}
	for (const candidate of config.candidates) {
		if (attempts.some((a) => a.baseUrl === candidate)) continue;
		const ping = await pingCandidate(config, transport, candidate);
		attempts.push(ping);
		if (ping.status === 200) {
			selectedBaseUrls.set(key, candidate);
			return { baseUrl: candidate, ping, attempts };
		}
	}
	const summary = attempts.map((a) => `• ${explainProbe(a, config)}`).join('\n');
	const where = config.source === 'pairing_code' ? 'in the pairing code' : 'in the credential';
	throw new NoReachableCandidateError(
		`No Osaurus URL ${where} answered /ping for connection '${config.connectionId}'.\n${summary}`,
		attempts,
	);
}

/** Describe a successful probe for the credential-test banner. */
export function describeConnection(
	result: { baseUrl: string; ping: PingResult },
	transport: ChannelTransport,
): string {
	const verification = result.ping.ok?.verification ?? 'unknown verification';
	const encrypted = transport.kind === 'secure_channel' ? ', end-to-end encrypted' : ', plaintext';
	return `Connected to ${result.baseUrl} (${verification}${encrypted}).`;
}
