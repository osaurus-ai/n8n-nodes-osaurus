import type {
	ICredentialDataDecryptedObject,
	ICredentialType,
	IHttpRequestOptions,
	INodeProperties,
	Icon,
} from 'n8n-workflow';

import {
	DEFAULT_SECRET_HEADER,
	DEFAULT_SIGNATURE_HEADER,
	channelAuthHeaders,
} from '../src/channel';
import { resolveChannelConfig } from '../src/pairing';

/**
 * Osaurus Channel credential.
 *
 * Default setup is a single **pairing code** copied from Osaurus → Settings →
 * Channels → n8n → Connect n8n. It carries the URL candidates, connection
 * id, secret, verification method, and (when a local agent is bound) the
 * agent address that switches the node to Secure Channel. **Manual** keeps
 * the original four fields for saved credentials and unusual topologies.
 *
 * There is no static `test` block: the probe has to walk candidates and, for
 * Secure Channel, run a handshake, so the node's `osaurusChannelApiTest`
 * (`testedBy`) does it.
 */
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
			displayName: 'Setup',
			name: 'setup',
			type: 'options',
			options: [
				{
					name: 'Pairing Code (Recommended)',
					value: 'pairingCode',
					description: 'One string copied from Osaurus. Picks the URL and encryption for you.',
				},
				{
					name: 'Manual (Advanced)',
					value: 'manual',
					description: 'Type the base URL, connection ID and secret yourself. Plaintext HTTP only.',
				},
			],
			default: 'pairingCode',
		},
		// The pairing code embeds the channel secret, so it must be masked.
		// eslint-disable-next-line @n8n/community-nodes/credential-unnecessary-password
		{
			displayName: 'Pairing Code',
			name: 'pairingCode',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			placeholder: 'osrs-n8n-1.eyJ2IjoxLCJ1cmxzIjpb…',
			description:
				'From Osaurus → Settings → Channels → n8n → Connect n8n → Pair with n8n. It contains the channel secret; treat it like one.',
			displayOptions: { show: { setup: ['pairingCode'] } },
		},
		{
			displayName:
				'Press Test. The node picks the first URL in the code that answers, and encrypts end-to-end when the code carries an agent address.',
			name: 'pairingNotice',
			type: 'notice',
			default: '',
			displayOptions: { show: { setup: ['pairingCode'] } },
		},
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: 'http://127.0.0.1:1337',
			placeholder: 'http://host.docker.internal:1337',
			description:
				'Where Osaurus listens: 127.0.0.1 from the same Mac, host.docker.internal from Docker Desktop.',
			displayOptions: { show: { setup: ['manual'] } },
		},
		{
			displayName: 'Connection ID',
			name: 'connectionId',
			type: 'string',
			default: '',
			placeholder: 'n8n-local',
			description: 'The ID from Osaurus → Settings → Channels → n8n → Name this channel.',
			displayOptions: { show: { setup: ['manual'] } },
		},
		{
			displayName: 'Channel Secret',
			name: 'secret',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description:
				'The channel secret from Osaurus → Connect n8n. Not an osk-v1 access key.',
			displayOptions: { show: { setup: ['manual'] } },
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
			description:
				'Must match Osaurus → Connect n8n → Advanced → Verification. HMAC signs the exact raw body; poll signs the empty body.',
			displayOptions: { show: { setup: ['manual'] } },
		},
		{
			displayName: 'Header Name',
			name: 'headerName',
			type: 'string',
			default: '',
			placeholder: DEFAULT_SIGNATURE_HEADER,
			description: `Leave empty for ${DEFAULT_SIGNATURE_HEADER} (HMAC) or ${DEFAULT_SECRET_HEADER} (header).`,
			displayOptions: { show: { setup: ['manual'] } },
		},
	];

	/**
	 * Plaintext auth for generic HTTP Request nodes that reference this
	 * credential. Decodes the pairing code so the secret/method/header come
	 * from the same source as the Osaurus node. (Secure Channel wrapping is
	 * only available through the Osaurus node itself.)
	 */
	async authenticate(
		credentials: ICredentialDataDecryptedObject,
		requestOptions: IHttpRequestOptions,
	): Promise<IHttpRequestOptions> {
		const config = resolveChannelConfig(credentials as Record<string, unknown>);
		const raw = typeof requestOptions.body === 'string' ? requestOptions.body : '';
		requestOptions.headers = {
			...requestOptions.headers,
			...channelAuthHeaders(config.verificationMethod, config.secret, raw, config.headerName),
		};
		return requestOptions;
	}
}
