import type {
	ICredentialDataDecryptedObject,
	IDataObject,
	INodeType,
	INodeTypeDescription,
	IWebhookFunctions,
	IWebhookResponseData,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

import type { ChannelVerificationMethod } from '../../src/channel';
import {
	DEFAULT_SECRET_HEADER,
	DEFAULT_SIGNATURE_HEADER,
	defaultHeaderName,
	parseOutboundPushEnvelope,
	verifySharedSecret,
	verifySignature,
} from '../../src/channel';

function asChannel(data: ICredentialDataDecryptedObject): {
	secret: string;
	verificationMethod: ChannelVerificationMethod;
	headerName: string;
} {
	return {
		secret: String(data.secret ?? ''),
		verificationMethod:
			data.verificationMethod === 'shared_secret_header' ? 'shared_secret_header' : 'hmac_sha256',
		headerName: String(data.headerName ?? ''),
	};
}

function headerValue(headers: IDataObject, name: string): string {
	const lower = name.toLowerCase();
	for (const [key, value] of Object.entries(headers)) {
		if (key.toLowerCase() === lower) {
			return Array.isArray(value) ? String(value[0] ?? '') : String(value ?? '');
		}
	}
	return '';
}

export class OsaurusTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Osaurus Trigger',
		name: 'osaurusTrigger',
		icon: { light: 'file:osaurus.svg', dark: 'file:osaurus.dark.svg' },
		group: ['trigger'],
		version: 1,
		subtitle: 'Outbound push',
		description: 'Receive an HMAC-verified outbound push from an Osaurus n8n channel',
		defaults: {
			name: 'Osaurus Trigger',
		},
		inputs: [],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'osaurusChannelApi',
				required: true,
			},
		],
		webhooks: [
			{
				name: 'default',
				httpMethod: 'POST',
				responseMode: 'onReceived',
				path: 'osaurus',
			},
		],
		properties: [
			{
				displayName:
					'Point the Osaurus channel outbound webhook at this node’s Production URL (HTTPS). The channel secret verifies the raw body. This is not an osk-v1 key.',
				name: 'notice',
				type: 'notice',
				default: '',
			},
		],
	};

	webhookMethods = {
		default: {
			async checkExists(): Promise<boolean> {
				return true;
			},
			async create(): Promise<boolean> {
				return true;
			},
			async delete(): Promise<boolean> {
				return true;
			},
		},
	};

	async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
		const credentials = asChannel(await this.getCredentials('osaurusChannelApi'));
		const req = this.getRequestObject() as { rawBody?: Buffer | string; body?: unknown };
		const raw =
			typeof req.rawBody === 'string'
				? req.rawBody
				: Buffer.isBuffer(req.rawBody)
					? req.rawBody.toString('utf8')
					: JSON.stringify(req.body ?? this.getBodyData());
		const headerName = credentials.headerName.trim() || defaultHeaderName(credentials.verificationMethod);
		const provided = headerValue(this.getHeaderData() as IDataObject, headerName);
		const fallback = headerValue(
			this.getHeaderData() as IDataObject,
			credentials.verificationMethod === 'hmac_sha256'
				? DEFAULT_SIGNATURE_HEADER
				: DEFAULT_SECRET_HEADER,
		);
		const header = provided || fallback;

		const ok =
			credentials.verificationMethod === 'shared_secret_header'
				? verifySharedSecret(credentials.secret, header)
				: verifySignature(credentials.secret, raw, header);
		if (!ok) {
			throw new NodeOperationError(this.getNode(), 'Rejected Osaurus push: signature did not verify.');
		}

		const envelope = parseOutboundPushEnvelope(raw);
		return {
			workflowData: [this.helpers.returnJsonArray([envelope as IDataObject])],
		};
	}
}
