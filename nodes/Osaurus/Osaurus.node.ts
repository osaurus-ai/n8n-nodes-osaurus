import type {
	ICredentialDataDecryptedObject,
	ICredentialTestFunctions,
	ICredentialsDecrypted,
	IDataObject,
	IExecuteFunctions,
	IHttpRequestOptions,
	INodeCredentialTestResult,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError, sleep } from 'n8n-workflow';

import type { ChannelVerificationMethod, InboundAttachment } from '../../src/channel';
import {
	DEFAULT_SECRET_HEADER,
	DEFAULT_SIGNATURE_HEADER,
	buildInboundEnvelope,
	channelAuthHeaders,
	inboundUrl,
	isTerminalTaskStatus,
	joinUrl,
	parseOutboundPushEnvelope,
	PROBE_TASK_ID,
	taskUrl,
	verifySharedSecret,
	verifySignature,
} from '../../src/channel';
import { collectSseContent } from '../../src/sse';

type ChannelCredentials = {
	baseUrl: string;
	connectionId: string;
	secret: string;
	verificationMethod: ChannelVerificationMethod;
	headerName?: string;
};

type ApiCredentials = {
	baseUrl: string;
	accessKey: string;
};

function asChannel(data: ICredentialDataDecryptedObject): ChannelCredentials {
	return {
		baseUrl: String(data.baseUrl ?? '').replace(/\/+$/, ''),
		connectionId: String(data.connectionId ?? ''),
		secret: String(data.secret ?? ''),
		verificationMethod:
			data.verificationMethod === 'shared_secret_header' ? 'shared_secret_header' : 'hmac_sha256',
		headerName: String(data.headerName ?? ''),
	};
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
		description: 'Talk to an Osaurus n8n channel or run a local agent',
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
						description: 'Secret-verified /channels/n8n webhook and poll',
					},
					{
						name: 'Agent',
						value: 'agent',
						description: 'Plaintext osk-v1 /agents run or dispatch (loopback / trusted LAN)',
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
						description: 'POST the v1 envelope and poll until the agent reply is terminal',
						action: 'Send a channel message and wait',
					},
					{
						name: 'Poll Task',
						value: 'pollTask',
						description: 'GET one poll_url / task once',
						action: 'Poll a channel task',
					},
					{
						name: 'Verify Inbound Push',
						value: 'verifyPush',
						description: 'Verify an Osaurus outbound HMAC body and parse the envelope',
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
						description: 'POST /agents/{ID}/run and collect the SSE answer',
						action: 'Run an agent',
					},
					{
						name: 'Dispatch',
						value: 'dispatch',
						description: 'POST /agents/{ID}/dispatch and optionally wait on poll_url',
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
				description: 'Must match an allowlisted line on the Osaurus n8n channel',
			},
			{
				displayName: 'Sender ID',
				name: 'senderId',
				type: 'string',
				default: 'workflow',
				required: true,
				displayOptions: { show: { resource: ['channel'], operation: ['sendAndWait'] } },
				description: 'Must match an allowlisted sender.ID on the Osaurus n8n channel',
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
				description: 'Idempotency key. Reusing the same ID returns 200 duplicate.',
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
				description: 'Metadata only. Osaurus does not fetch file bytes.',
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
				description: 'Absolute poll_url from a 202, or leave empty and set Task ID',
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
				description: 'Exact JSON bytes Osaurus posted to the webhook',
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
				description: 'Agent UUID, crypto address, or "default" on loopback',
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
			async osaurusChannelApiTest(
				this: ICredentialTestFunctions,
				credential: ICredentialsDecrypted,
			): Promise<INodeCredentialTestResult> {
				const credentials = asChannel(credential.data ?? {});
				try {
					// ICredentialTestFunctions only exposes helpers.request.
					// eslint-disable-next-line @n8n/community-nodes/no-deprecated-workflow-functions
					const response = (await this.helpers.request({
						method: 'GET',
						uri: taskUrl(credentials.baseUrl, credentials.connectionId, PROBE_TASK_ID),
						headers: channelAuthHeaders(
							credentials.verificationMethod,
							credentials.secret,
							'',
							credentials.headerName,
						),
						resolveWithFullResponse: true,
						simple: false,
					})) as { statusCode?: number; status?: number };
					const code = response.statusCode ?? response.status ?? 0;
					if (code === 401) {
						return { status: 'Error', message: 'Channel secret was rejected (401).' };
					}
					if (code === 404 || code === 200 || code === 202 || code === 403) {
						return {
							status: 'OK',
							message: 'Channel secret was accepted (probe task is expected to be missing).',
						};
					}
					return { status: 'Error', message: `Unexpected status ${code} from the probe poll.` };
				} catch (error) {
					return { status: 'Error', message: (error as Error).message };
				}
			},
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
	const credentials = asChannel(await this.getCredentials('osaurusChannelApi'));
	const operation = this.getNodeParameter('operation', index) as string;

	if (operation === 'verifyPush') {
		return verifyPush.call(this, index, credentials);
	}
	if (operation === 'pollTask') {
		const pollUrl = (this.getNodeParameter('pollUrl', index, '') as string).trim();
		const taskId = (this.getNodeParameter('taskId', index, '') as string).trim();
		const url = resolvePollUrl.call(this, credentials, pollUrl, taskId);
		return (await channelRequest.call(this, credentials, 'GET', url, '')) as IDataObject;
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
		credentials,
		'POST',
		inboundUrl(credentials.baseUrl, credentials.connectionId),
		raw,
	);
	const acceptedObject = accepted as IDataObject;
	const pollPath = String(acceptedObject.poll_url ?? '');
	if (!pollPath) {
		return acceptedObject;
	}

	const url = pollPath.startsWith('http')
		? pollPath
		: joinUrl(credentials.baseUrl, pollPath);
	const deadline = Date.now() + timeoutMs;
	let last: IDataObject = acceptedObject;
	while (Date.now() < deadline) {
		await sleep(pollInterval);
		last = (await channelRequest.call(this, credentials, 'GET', url, '')) as IDataObject;
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

function verifyPush(
	this: IExecuteFunctions,
	index: number,
	credentials: ChannelCredentials,
): IDataObject {
	const raw = this.getNodeParameter('rawBody', index) as string;
	const header = (this.getNodeParameter('signatureHeader', index, '') as string).trim();
	assertPushVerified.call(this, credentials, raw, header);
	return parseOutboundPushEnvelope(raw) as IDataObject;
}

function assertPushVerified(
	this: IExecuteFunctions,
	credentials: ChannelCredentials,
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
	const object = (typeof dispatched === 'string' ? responseBody(dispatched) : dispatched) as IDataObject;
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

async function channelRequest(
	this: IExecuteFunctions,
	credentials: ChannelCredentials,
	method: 'GET' | 'POST',
	url: string,
	raw: string,
): Promise<unknown> {
	const headers: IHttpRequestOptions['headers'] = {
		...channelAuthHeaders(
			credentials.verificationMethod,
			credentials.secret,
			raw,
			credentials.headerName,
		),
	};
	if (method === 'POST') {
		headers['Content-Type'] = 'application/json';
	}
	const response = (await this.helpers.httpRequest({
		method,
		url,
		headers,
		body: method === 'POST' ? raw : undefined,
		json: false,
		returnFullResponse: true,
		ignoreHttpStatusErrors: true,
	})) as { statusCode?: number; status?: number; body?: unknown };

	const code = statusOf(response);
	const parsed = responseBody(response.body);
	if (code >= 400) {
		const error =
			parsed && typeof parsed === 'object'
				? JSON.stringify(parsed)
				: String(parsed ?? `HTTP ${code}`);
		throw new NodeOperationError(this.getNode(), `Osaurus channel ${method} ${url} failed (${code}): ${error}`);
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
		throw new NodeOperationError(this.getNode(), `Osaurus API ${method} ${url} failed (${code}): ${error}.${hint}`);
	}
	return parsed;
}

function resolvePollUrl(
	this: IExecuteFunctions,
	credentials: ChannelCredentials,
	pollUrl: string,
	taskId: string,
): string {
	if (pollUrl) {
		return pollUrl.startsWith('http') ? pollUrl : joinUrl(credentials.baseUrl, pollUrl);
	}
	if (taskId) {
		return taskUrl(credentials.baseUrl, credentials.connectionId, taskId);
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
