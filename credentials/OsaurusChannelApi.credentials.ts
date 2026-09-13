import type {
	ICredentialDataDecryptedObject,
	ICredentialTestRequest,
	ICredentialType,
	IHttpRequestOptions,
	INodeProperties,
	Icon,
} from 'n8n-workflow';

import {
	DEFAULT_SECRET_HEADER,
	DEFAULT_SIGNATURE_HEADER,
	channelAuthHeaders,
	type ChannelVerificationMethod,
} from '../src/channel';

export class OsaurusChannelApi implements ICredentialType {
	name = 'osaurusChannelApi';

	displayName = 'Osaurus Channel API';

	icon: Icon = {
		light: 'file:../nodes/Osaurus/osaurus.svg',
		dark: 'file:../nodes/Osaurus/osaurus.dark.svg',
	};

	documentationUrl = 'https://github.com/osaurus-ai/n8n-nodes-osaurus#credentials';

	properties: INodeProperties[] = [
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: 'http://127.0.0.1:1337',
			placeholder: 'http://host.docker.internal:1337',
			description:
				'Osaurus origin. Use 127.0.0.1 from this Mac, or host.docker.internal from Docker Desktop.',
			required: true,
		},
		{
			displayName: 'Connection ID',
			name: 'connectionId',
			type: 'string',
			default: '',
			placeholder: 'n8n-local',
			description: 'The n8n channel id from Osaurus Settings → Channels.',
			required: true,
		},
		{
			displayName: 'Channel Secret',
			name: 'secret',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description:
				'Shared secret from the n8n channel sheet. This is not an osk-v1 access key.',
			required: true,
		},
		{
			displayName: 'Verification Method',
			name: 'verificationMethod',
			type: 'options',
			options: [
				{
					name: 'HMAC-SHA256 Signature',
					value: 'hmac_sha256',
				},
				{
					name: 'Shared Secret Header',
					value: 'shared_secret_header',
				},
			],
			default: 'hmac_sha256',
			description: 'Must match the channel sheet. HMAC signs the exact raw body; poll signs empty.',
		},
		{
			displayName: 'Header Name',
			name: 'headerName',
			type: 'string',
			default: '',
			placeholder: DEFAULT_SIGNATURE_HEADER,
			description: `Leave empty for ${DEFAULT_SIGNATURE_HEADER} (HMAC) or ${DEFAULT_SECRET_HEADER} (header).`,
		},
	];

	async authenticate(
		credentials: ICredentialDataDecryptedObject,
		requestOptions: IHttpRequestOptions,
	): Promise<IHttpRequestOptions> {
		const method: ChannelVerificationMethod =
			credentials.verificationMethod === 'shared_secret_header'
				? 'shared_secret_header'
				: 'hmac_sha256';
		const raw = typeof requestOptions.body === 'string' ? requestOptions.body : '';
		requestOptions.headers = {
			...requestOptions.headers,
			...channelAuthHeaders(
				method,
				String(credentials.secret ?? ''),
				raw,
				String(credentials.headerName ?? ''),
			),
		};
		return requestOptions;
	}

	// Probe poll: 404 means the secret verified. The node also exposes
	// `testedBy: osaurusChannelApiTest`, which treats 404 as success.
	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl}}',
			url: '=/channels/n8n/{{$credentials.connectionId}}/tasks/00000000-0000-0000-0000-000000000000',
			method: 'GET',
		},
	};
}
