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
				'Agent-scoped osk-v1 key from Share Agent (also under Pair → Advanced in the n8n channel). This is not the n8n inbound channel secret. The Agent resource is plaintext-only, so it works from the same Mac or LAN; from another machine Osaurus answers 426 — use the Channel resource with a pairing code instead',
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
