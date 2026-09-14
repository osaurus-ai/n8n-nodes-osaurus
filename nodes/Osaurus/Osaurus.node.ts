import type {
	ICredentialDataDecryptedObject,
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError, sleep } from 'n8n-workflow';

import type { InboundAttachment } from '../../src/channel';
import {
	DEFAULT_SECRET_HEADER,
	DEFAULT_SIGNATURE_HEADER,
	buildInboundEnvelope,
	channelAuthHeaders,
	isTerminalTaskStatus,
	joinUrl,
	parseOutboundPushEnvelope,
	verifySharedSecret,
	verifySignature,
} from '../../src/channel';
import { testOsaurusChannelCredential } from '../../src/credentialTest';
import { httpFromExecute } from '../../src/n8nHttp';
import type { ChannelConfig } from '../../src/pairing';
import { resolveChannelConfig } from '../../src/pairing';
import { SecureChannelError } from '../../src/secureChannel';
import { collectSseContent } from '../../src/sse';
import type { ChannelTransport } from '../../src/transport';
import { forgetSelectedBaseUrl, makeTransport, selectBaseUrl } from '../../src/transport';

type ApiCredentials = {
	baseUrl: string;
	accessKey: string;
};

/** Resolved channel credential plus the transport that reaches it. */
type ChannelContext = {
	config: ChannelConfig;
	transport: ChannelTransport;
	baseUrl: string;
};

function asChannelConfig(
	this: IExecuteFunctions,
	data: ICredentialDataDecryptedObject,
): ChannelConfig {
	try {
		return resolveChannelConfig(data as Record<string, unknown>);
	} catch (error) {
		// PairingCodeError text is already user-facing; surface it verbatim.
		throw new NodeOperationError(this.getNode(), error as Error);
	}
}

/** Resolve credential → config → transport → reachable base URL. */
async function channelContext(this: IExecuteFunctions): Promise<ChannelContext> {
	const config = asChannelConfig.call(this, await this.getCredentials('osaurusChannelApi'));
	const transport = makeTransport(config, httpFromExecute(this));
	try {
		const selected = await selectBaseUrl(config, transport);
		return { config, transport, baseUrl: selected.baseUrl };
	} catch (error) {
		// NoReachableCandidateError / SecureChannelError carry actionable text.
		throw new NodeOperationError(this.getNode(), error as Error);
	}
}

function asApi(data: ICredentialDataDecryptedObject): ApiCredentials {
	return {
		baseUrl: String(data.baseUrl ?? '').replace(/\/+$/, ''),
		accessKey: String(data.apiKey ?? data.accessKey ?? ''),
	};
}

function responseBody(value: unknown): unknown {
	if (typeof value === 'string') {
		try {
			return JSON.parse(value);
		} catch {
			return value;
		}
	}
	return value;
}

function statusOf(response: { statusCode?: number; status?: number }): number {
	return response.statusCode ?? response.status ?? 0;
}

export class Osaurus implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Osaurus',
		name: 'osaurus',
		icon: { light: 'file:osaurus.svg', dark: 'file:osaurus.dark.svg' },
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description: 'Send a message to an Osaurus agent through an n8n channel, or run a local agent directly',
		defaults: {
			name: 'Osaurus',
		},
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'osaurusChannelApi',
				required: true,
				testedBy: 'osaurusChannelApiTest',
				displayOptions: {
					show: {
						resource: ['channel'],
					},
				},
			},
			{
				name: 'osaurusApi',
				required: true,
				displayOptions: {
					show: {
						resource: ['agent'],
					},
				},
			},
		],
		properties: [
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Channel',
						value: 'channel',
						description: 'Send a message to an n8n channel and wait for the agent reply. Uses the Osaurus Channel credential.',
					},
					{
						name: 'Agent',
						value: 'agent',
						description: 'Run a local agent directly with an osk-v1 access key. Plaintext HTTP: same Mac or trusted LAN only.',
					},
				],
				default: 'channel',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['channel'] } },
				options: [
					{
						name: 'Send Message and Wait',
						value: 'sendAndWait',
						description: 'Deliver the message and poll until the agent has replied, been rejected, or failed',
						action: 'Send a channel message and wait',
					},
					{
						name: 'Poll Task',
						value: 'pollTask',
						description: 'Check one reply task once instead of waiting',
						action: 'Poll a channel task',
					},
					{
						name: 'Verify Inbound Push',
						value: 'verifyPush',
						description: 'Check the signature on a reply Osaurus pushed to a Webhook node and parse it',
						action: 'Verify an inbound push',
					},
				],
				default: 'sendAndWait',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['agent'] } },
				options: [
					{
						name: 'Run',
						value: 'run',
						description: 'Run the agent and return the whole answer',
						action: 'Run an agent',
					},
					{
						name: 'Dispatch',
						value: 'dispatch',
						description: 'Start the agent in the background and optionally wait for the result',
						action: 'Dispatch an agent',
					},
				],
				default: 'run',
			},
			{
				displayName: 'Conversation ID',
				name: 'conversationId',
				type: 'string',
				default: 'n8n-test',
				required: true,
				displayOptions: { show: { resource: ['channel'], operation: ['sendAndWait'] } },
				description: 'Must be listed under Allowed Conversations in Osaurus → Channels → n8n → Who may speak',
			},
			{
				displayName: 'Sender ID',
				name: 'senderId',
				type: 'string',
				default: 'workflow',
				required: true,
				displayOptions: { show: { resource: ['channel'], operation: ['sendAndWait'] } },
				description: 'Must be listed under Allowed Senders in Osaurus → Channels → n8n → Who may speak',
			},
			{
				displayName: 'Content',
				name: 'content',
				type: 'string',
				typeOptions: { rows: 4 },
				default: '',
				required: true,
				displayOptions: { show: { resource: ['channel'], operation: ['sendAndWait'] } },
			},
			{
				displayName: 'Event ID',
				name: 'eventId',
				type: 'string',
				default: '={{`n8n:${$execution.id}`}}',
				displayOptions: { show: { resource: ['channel'], operation: ['sendAndWait'] } },
				description: 'Idempotency key. Sending the same ID twice returns the first result instead of a new event.',
			},
			{
				displayName: 'Sender Display Name',
				name: 'senderDisplay',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['channel'], operation: ['sendAndWait'] } },
			},
			{
				displayName: 'Sender Is Bot',
				name: 'senderIsBot',
				type: 'boolean',
				default: false,
				displayOptions: { show: { resource: ['channel'], operation: ['sendAndWait'] } },
			},
			{
				displayName: 'Thread ID',
				name: 'threadId',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['channel'], operation: ['sendAndWait'] } },
			},
			{
				displayName: 'Attachments JSON',
				name: 'attachmentsJson',
				type: 'json',
				default: '[]',
				displayOptions: { show: { resource: ['channel'], operation: ['sendAndWait'] } },
				description: 'Metadata only (name, type, URL). Osaurus does not download the files.',
			},
			{
				displayName: 'Poll Interval (Seconds)',
				name: 'pollInterval',
				type: 'number',
				default: 2,
				typeOptions: { minValue: 0.2 },
				displayOptions: {
					show: {
						resource: ['channel'],
						operation: ['sendAndWait'],
					},
				},
			},
			{
				displayName: 'Timeout (Seconds)',
				name: 'timeout',
				type: 'number',
				default: 90,
				typeOptions: { minValue: 1 },
				displayOptions: {
					show: {
						resource: ['channel'],
						operation: ['sendAndWait'],
					},
				},
			},
			{
				displayName: 'Poll URL',
				name: 'pollUrl',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['channel'], operation: ['pollTask'] } },
				description: 'The poll_url from a Send Message and Wait result, or leave empty and set Task ID',
			},
			{
				displayName: 'Task ID',
				name: 'taskId',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['channel'], operation: ['pollTask'] } },
			},
			{
				displayName: 'Raw Body',
				name: 'rawBody',
				type: 'string',
				typeOptions: { rows: 6 },
				default: '',
				required: true,
				displayOptions: { show: { resource: ['channel'], operation: ['verifyPush'] } },
				description: 'The exact request body Osaurus posted, unmodified',
			},
			{
				displayName: 'Signature Header',
				name: 'signatureHeader',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['channel'], operation: ['verifyPush'] } },
				description: `Value of ${DEFAULT_SIGNATURE_HEADER} or ${DEFAULT_SECRET_HEADER}`,
			},
			{
				displayName: 'Agent ID',
				name: 'agentId',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { resource: ['agent'] } },
				description: 'Agent UUID or address from Osaurus → Agents, or "default" from the same Mac',
			},
			{
				displayName: 'Message',
				name: 'message',
				type: 'string',
				typeOptions: { rows: 4 },
				default: '',
				required: true,
				displayOptions: { show: { resource: ['agent'] } },
			},
			{
				displayName: 'Wait for Dispatch',
				name: 'waitForDispatch',
				type: 'boolean',
				default: false,
				displayOptions: { show: { resource: ['agent'], operation: ['dispatch'] } },
			},
			{
				displayName: 'Poll Interval (Seconds)',
				name: 'pollInterval',
				type: 'number',
				default: 2,
				displayOptions: {
					show: { resource: ['agent'], operation: ['dispatch'], waitForDispatch: [true] },
				},
			},
			{
				displayName: 'Timeout (Seconds)',
				name: 'timeout',
				type: 'number',
				default: 90,
				displayOptions: {
					show: { resource: ['agent'], operation: ['dispatch'], waitForDispatch: [true] },
				},
			},
		],
	};

	methods = {
		credentialTest: {
			osaurusChannelApiTest: testOsaurusChannelCredential,
		},
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const resource = this.getNodeParameter('resource', 0) as string;

		for (let i = 0; i < items.length; i++) {
			if (resource === 'channel') {
				returnData.push({
					json: (await executeChannel.call(this, i)) as IDataObject,
					pairedItem: { item: i },
				});
			} else {
				returnData.push({
					json: (await executeAgent.call(this, i)) as IDataObject,
					pairedItem: { item: i },
				});
			}
		}

		return [returnData];
	}
}

async function executeChannel(this: IExecuteFunctions, index: number): Promise<IDataObject> {
	const operation = this.getNodeParameter('operation', index) as string;

	if (operation === 'verifyPush') {
		// Pure verification: no network, so no candidate probing.
		const config = asChannelConfig.call(this, await this.getCredentials('osaurusChannelApi'));
		return verifyPush.call(this, index, config);
	}

	const context = await channelContext.call(this);
	if (operation === 'pollTask') {
		const pollUrl = (this.getNodeParameter('pollUrl', index, '') as string).trim();
		const taskId = (this.getNodeParameter('taskId', index, '') as string).trim();
		const path = resolvePollPath.call(this, context.config, pollUrl, taskId);
		return (await channelRequest.call(this, context, 'GET', path, '')) as IDataObject;
	}

	const conversationId = this.getNodeParameter('conversationId', index) as string;
	const senderId = this.getNodeParameter('senderId', index) as string;
	const content = this.getNodeParameter('content', index) as string;
	const eventId = (this.getNodeParameter('eventId', index) as string).trim();
	const senderDisplay = (this.getNodeParameter('senderDisplay', index, '') as string).trim();
	const senderIsBot = this.getNodeParameter('senderIsBot', index, false) as boolean;
	const threadId = (this.getNodeParameter('threadId', index, '') as string).trim();
	const attachments = parseAttachments(this.getNodeParameter('attachmentsJson', index, '[]'));
	const pollInterval = Number(this.getNodeParameter('pollInterval', index, 2)) * 1000;
	const timeoutMs = Number(this.getNodeParameter('timeout', index, 90)) * 1000;

	const raw = buildInboundEnvelope({
		eventId: eventId || `n8n:${Date.now()}`,
		conversationId,
		senderId,
		content,
		senderDisplay: senderDisplay || undefined,
		senderIsBot,
		threadId: threadId || undefined,
		attachments,
	});

	const accepted = await channelRequest.call(
		this,
		context,
		'POST',
		`/channels/n8n/${context.config.connectionId}/inbound`,
		raw,
	);
	const acceptedObject = accepted as IDataObject;
	assertInboundAccepted.call(this, acceptedObject, context.config, { conversationId, senderId });
	const pollPath = String(acceptedObject.poll_url ?? '');
	if (!pollPath) {
		return acceptedObject;
	}

	const path = pathOnly(pollPath);
	const deadline = Date.now() + timeoutMs;
	let last: IDataObject = acceptedObject;
	while (Date.now() < deadline) {
		await sleep(pollInterval);
		last = (await channelRequest.call(this, context, 'GET', path, '')) as IDataObject;
		const status = String(last.status ?? '');
		if (isTerminalTaskStatus(status)) {
			return last;
		}
	}
	throw new NodeOperationError(
		this.getNode(),
		`Timed out waiting for an Osaurus reply (last status: ${String(last.status ?? 'unknown')}).`,
	);
}

/**
 * The ingress answers 202 for both accepted and rejected events. A rejected
 * or suppressed event is the likeliest first-run failure right after pairing,
 * so surface it as a node error with the fix instead of a green item.
 */
function assertInboundAccepted(
	this: IExecuteFunctions,
	response: IDataObject,
	config: ChannelConfig,
	sent: { conversationId: string; senderId: string },
): void {
	const status = String(response.status ?? '');
	const reason = String(response.reason ?? '');
	const where = `Osaurus → Settings → Channels → n8n (connection '${config.connectionId}')`;
	if (status === 'rejected') {
		const conversationHint = ` Add it under Who may speak in ${where}.`;
		switch (reason) {
			case 'sender_not_allowlisted':
				throw new NodeOperationError(
					this.getNode(),
					`Osaurus rejected the event: sender '${sent.senderId}' is not allowlisted on connection '${config.connectionId}'.${conversationHint}`,
					{
						description:
							'The Sender ID this node sends must exactly match a line in the sender allowlist.',
					},
				);
			case 'room_not_allowlisted':
				throw new NodeOperationError(
					this.getNode(),
					`Osaurus rejected the event: conversation '${sent.conversationId}' is not allowlisted on connection '${config.connectionId}'.${conversationHint}`,
					{
						description:
							'The Conversation ID this node sends must exactly match a line in the conversation allowlist.',
					},
				);
			case 'bot_message_denied':
				throw new NodeOperationError(
					this.getNode(),
					`Osaurus rejected the event: bot senders are not allowed. Turn off "Sender is bot" on this node or allow bot messages in ${where}.`,
				);
			default:
				throw new NodeOperationError(
					this.getNode(),
					`Osaurus rejected the event (${reason || 'unknown reason'}). Check the allowlists in ${where}.`,
				);
		}
	}
	const dispatch = String(response.dispatch ?? '');
	if (dispatch.startsWith('suppressed')) {
		const detail = dispatch.slice('suppressed:'.length) || 'unknown';
		throw new NodeOperationError(
			this.getNode(),
			`Osaurus stored the event but did not run an agent (${detail}). Turn on Reply with an Agent and pick an agent in How Osaurus replies, ${where}.`,
		);
	}
}

/** Strip scheme/host from a `poll_url`; the transport supplies the base. */
function pathOnly(urlOrPath: string): string {
	if (!urlOrPath.startsWith('http')) return urlOrPath.startsWith('/') ? urlOrPath : `/${urlOrPath}`;
	try {
		const url = new URL(urlOrPath);
		return `${url.pathname}${url.search}`;
	} catch {
		return urlOrPath;
	}
}

function verifyPush(this: IExecuteFunctions, index: number, config: ChannelConfig): IDataObject {
	const raw = this.getNodeParameter('rawBody', index) as string;
	const header = (this.getNodeParameter('signatureHeader', index, '') as string).trim();
	assertPushVerified.call(this, config, raw, header);
	return parseOutboundPushEnvelope(raw) as IDataObject;
}

function assertPushVerified(
	this: IExecuteFunctions,
	credentials: Pick<ChannelConfig, 'verificationMethod' | 'secret'>,
	raw: string,
	header: string,
): void {
	if (!header) {
		throw new NodeOperationError(
			this.getNode(),
			'Signature header is required to verify an inbound push',
		);
	}
	const ok =
		credentials.verificationMethod === 'shared_secret_header'
			? verifySharedSecret(credentials.secret, header)
			: verifySignature(credentials.secret, raw, header);
	if (!ok) {
		throw new NodeOperationError(
			this.getNode(),
			'Inbound push signature did not match the channel secret',
		);
	}
}

async function executeAgent(this: IExecuteFunctions, index: number): Promise<IDataObject> {
	const credentials = asApi(await this.getCredentials('osaurusApi'));
	const operation = this.getNodeParameter('operation', index) as string;
	const agentId = this.getNodeParameter('agentId', index) as string;
	const message = this.getNodeParameter('message', index) as string;
	const body = { messages: [{ role: 'user', content: message }] };

	if (operation === 'run') {
		const raw = await apiRequest.call(
			this,
			credentials,
			'POST',
			joinUrl(credentials.baseUrl, `/agents/${agentId}/run`),
			body,
			{ Accept: 'text/event-stream' },
		);
		const text = typeof raw === 'string' ? raw : JSON.stringify(raw);
		const collected = collectSseContent(text);
		if (collected.frames.length === 0 && raw && typeof raw === 'object') {
			return raw as IDataObject;
		}
		return {
			content: collected.content,
			frames: collected.frames as unknown as IDataObject[],
		};
	}

	const dispatched = await apiRequest.call(
		this,
		credentials,
		'POST',
		joinUrl(credentials.baseUrl, `/agents/${agentId}/dispatch`),
		body,
	);
	const object = (
		typeof dispatched === 'string' ? responseBody(dispatched) : dispatched
	) as IDataObject;
	const wait = this.getNodeParameter('waitForDispatch', index, false) as boolean;
	if (!wait) {
		return object;
	}
	const pollPath = String(object.poll_url ?? '');
	if (!pollPath) {
		return object;
	}
	const url = pollPath.startsWith('http') ? pollPath : joinUrl(credentials.baseUrl, pollPath);
	const pollInterval = Number(this.getNodeParameter('pollInterval', index, 2)) * 1000;
	const timeoutMs = Number(this.getNodeParameter('timeout', index, 90)) * 1000;
	const deadline = Date.now() + timeoutMs;
	let last = object;
	while (Date.now() < deadline) {
		await sleep(pollInterval);
		last = (await apiRequest.call(this, credentials, 'GET', url, undefined)) as IDataObject;
		const status = String(last.status ?? last.state ?? '');
		if (isTerminalTaskStatus(status) || status === 'done' || status === 'success') {
			return last;
		}
	}
	throw new NodeOperationError(this.getNode(), 'Timed out waiting for a dispatched agent run.');
}

/** One secret-authenticated channel request over the selected transport and base URL. */
async function channelRequest(
	this: IExecuteFunctions,
	context: ChannelContext,
	method: 'GET' | 'POST',
	path: string,
	raw: string,
): Promise<unknown> {
	const { config, transport, baseUrl } = context;
	const headers = channelAuthHeaders(
		config.verificationMethod,
		config.secret,
		raw,
		config.headerName,
	);
	let response: { status: number; body: string };
	try {
		response = await transport.request(baseUrl, method, path, raw, headers);
	} catch (error) {
		// Network-level failure: forget the cached winner so the next run re-probes.
		forgetSelectedBaseUrl(config);
		if (error instanceof SecureChannelError) {
			throw new NodeOperationError(this.getNode(), error.message);
		}
		throw new NodeOperationError(
			this.getNode(),
			`Osaurus channel ${method} ${baseUrl}${path} failed: ${(error as Error).message}`,
		);
	}

	const code = response.status;
	const parsed = responseBody(response.body);
	if (code >= 400) {
		const detail =
			parsed && typeof parsed === 'object'
				? JSON.stringify(parsed)
				: String(parsed ?? `HTTP ${code}`);
		const hint =
			code === 426
				? ' Remote callers need Secure Channel: bind a local agent in Osaurus → Channels → n8n → How Osaurus replies and copy a fresh pairing code from Connect n8n, or turn on Remote callers there.'
				: code === 401
					? ' The pairing code is stale: regenerate the secret in Osaurus and paste a fresh code.'
					: '';
		throw new NodeOperationError(
			this.getNode(),
			`Osaurus channel ${method} ${baseUrl}${path} failed (${code}): ${detail}${hint}`,
		);
	}
	return parsed;
}

async function apiRequest(
	this: IExecuteFunctions,
	credentials: ApiCredentials,
	method: 'GET' | 'POST',
	url: string,
	body?: IDataObject,
	extraHeaders?: Record<string, string>,
): Promise<unknown> {
	const response = (await this.helpers.httpRequest({
		method,
		url,
		headers: {
			Authorization: `Bearer ${credentials.accessKey}`,
			...(body ? { 'Content-Type': 'application/json' } : {}),
			...extraHeaders,
		},
		body,
		json: body !== undefined,
		returnFullResponse: true,
		ignoreHttpStatusErrors: true,
	})) as { statusCode?: number; status?: number; body?: unknown };

	const code = statusOf(response);
	const parsed = responseBody(response.body);
	if (code >= 400) {
		const hint =
			code === 426
				? ' Remote /agents calls require Secure Channel, which this package does not implement. Use the Channel resource from the same Mac or Docker Desktop, or Share Agent + /secure/call from another client.'
				: '';
		const error =
			parsed && typeof parsed === 'object'
				? JSON.stringify(parsed)
				: String(parsed ?? `HTTP ${code}`);
		throw new NodeOperationError(
			this.getNode(),
			`Osaurus API ${method} ${url} failed (${code}): ${error}.${hint}`,
		);
	}
	return parsed;
}

function resolvePollPath(
	this: IExecuteFunctions,
	config: ChannelConfig,
	pollUrl: string,
	taskId: string,
): string {
	if (pollUrl) {
		return pathOnly(pollUrl);
	}
	if (taskId) {
		return `/channels/n8n/${config.connectionId}/tasks/${taskId}`;
	}
	throw new NodeOperationError(this.getNode(), 'Set Poll URL or Task ID');
}

function parseAttachments(value: unknown): InboundAttachment[] | undefined {
	if (value === undefined || value === null || value === '') {
		return undefined;
	}
	const parsed = typeof value === 'string' ? (JSON.parse(value) as unknown) : value;
	if (!Array.isArray(parsed) || parsed.length === 0) {
		return undefined;
	}
	return parsed as InboundAttachment[];
}
