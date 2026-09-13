import type {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
	Icon,
} from 'n8n-workflow';

export class OsaurusApi implements ICredentialType {
	name = 'osaurusApi';

	displayName = 'Osaurus API';

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
			placeholder: 'http://127.0.0.1:1337',
			description:
				'Osaurus origin. Plaintext /agents/.../run is for loopback or a trusted LAN only.',
			required: true,
		},
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			placeholder: 'osk-v1-...',
			description:
				'Agent-scoped osk-v1 key from Share Agent. This is not the n8n inbound channel secret. Remote callers need Secure Channel, which this package does not implement',
			required: true,
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '=Bearer {{$credentials.apiKey}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl}}',
			url: '/agents',
			method: 'GET',
		},
	};
}
