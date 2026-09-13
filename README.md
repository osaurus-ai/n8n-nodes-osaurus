# n8n-nodes-osaurus

This is an n8n community node. It lets an n8n workflow talk to [Osaurus](https://osaurus.ai) — a local agent runtime — over the first-party **n8n agent channel** (secret-verified webhook in, poll or webhook out) and, optionally, the plaintext **agent API** on the same Mac.

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/reference/license/) workflow automation platform.

- [Installation](#installation)
- [Operations](#operations)
- [Credentials](#credentials)
- [Compatibility](#compatibility)
- [Usage](#usage)
- [Resources](#resources)
- [Version history](#version-history)
- [Development](#development)
- [Releasing](#releasing)

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) in the n8n community nodes documentation.

1. In n8n, open **Settings → Community Nodes**.
2. Install `n8n-nodes-osaurus`.
3. Restart n8n if it does not reload nodes automatically.

For local development, install from this repo instead of npm:

```bash
# in this repository
pnpm install && pnpm build

# n8n custom extension dir
mkdir -p ~/.n8n/custom
cd ~/.n8n/custom
npm init -y
npm install /absolute/path/to/n8n-nodes-osaurus
```

Or run `pnpm dev` (`n8n-node dev`) while developing.

## Operations

### Osaurus (action)

| Resource | Operation | What it does |
| --- | --- | --- |
| Channel | **Send message and wait** | Builds envelope v1, signs the **exact JSON bytes**, `POST /channels/n8n/{id}/inbound`, then polls `poll_url` until `completed` / `failed` / `cancelled` or timeout. |
| Channel | **Poll task** | One `GET` of `poll_url` or `/tasks/{task_id}`. HMAC callers sign the empty body. |
| Channel | **Verify inbound push** | Constant-time verify of an Osaurus outbound body + `X-Osaurus-Channel-Signature` (or shared-secret header), then parse the v1 envelope. |
| Agent | **Run** | `POST /agents/{id}/run` with `{ messages: [{ role, content }] }`, collect SSE until `[DONE]`. |
| Agent | **Dispatch** | `POST /agents/{id}/dispatch`; optionally wait on `poll_url`. |

### Osaurus Trigger

Webhook trigger for the optional **HTTPS outbound push**. Point the Osaurus channel “Outbound Webhook URL” at this node’s Production URL. The trigger verifies HMAC (or the shared secret header) with the **Channel** credential and emits the parsed envelope.

Attachments on the inbound envelope are **metadata-only**. Osaurus does not fetch file bytes.

## Credentials

There are two credentials. They are not interchangeable.

### Osaurus Channel

Used for `/channels/n8n/...`. That prefix is bearer-exempt. The **channel secret** is the only authentication.

| Field | Notes |
| --- | --- |
| Base URL | `http://127.0.0.1:1337` from this Mac; `http://host.docker.internal:1337` from Docker Desktop on this Mac |
| Connection ID | Id from Osaurus **Settings → Channels → n8n** |
| Channel Secret | Generated on the n8n sheet and stored in the Osaurus Keychain |
| Verification Method | `HMAC-SHA256` (default) or `Shared secret header` — must match the sheet |
| Header Name | Optional override; defaults `X-Osaurus-Channel-Signature` / `X-Osaurus-Channel-Secret` |

The credential test `GET`s a dummy task id with a correctly signed empty body. **`404 task_not_found` means the secret is accepted.** `401` means the secret is wrong.

### Osaurus API

Used for `/agents/{id}/run` and `/dispatch` on **loopback or a trusted LAN**.

| Field | Notes |
| --- | --- |
| Base URL | Usually `http://127.0.0.1:1337` |
| Access Key | Agent-scoped `osk-v1-...` from **Share Agent** |

**The access key is not the inbound channel secret.** Remote `/agents/.../run` without Secure Channel returns `426 Upgrade Required`. This package does **not** implement `/secure/session` or `/secure/call`. For remote n8n, use the Channel resource (webhook + poll) or a client that speaks Secure Channel.

## Compatibility

- Built against the current n8n community-node API (`n8nNodesApiVersion: 1`, `@n8n/node-cli`).
- Tested conceptually against Osaurus n8n channel contract v1 (HMAC or shared-secret header, poll-based replies, optional signed push).
- Requires n8n 1.x that can load community node packages.

## Usage

### Map the node to the Osaurus n8n sheet

In Osaurus, **Settings → Channels → n8n**:

1. **Where is n8n?** — pick This Mac / Docker Desktop / LAN / Remote. Copy the matching inbound URL host into the Channel credential Base URL.
2. **How n8n calls Osaurus** — paste the same secret and verification method into the Channel credential.
3. **Who may speak** — `conversation_id` and `sender.id` on **Send message and wait** must each match an allowlisted line (`conversation_id: "n8n-test"` is the usual first test).
4. **How Osaurus replies** — default is poll (this node waits for you). Optional push needs a public **HTTPS** webhook (loopback / RFC1918 / `http://` are refused by C2). If **Allow Agents to Send Messages** is off, push fails; poll still returns the reply.

### Send a message and use the reply

1. Add **Osaurus** → Channel → **Send message and wait**.
2. Set Conversation ID and Sender ID to allowlisted values.
3. Set Content, e.g. `Reply with the single word PONG`.
4. The item output is the poll JSON: `status`, `output`, `task_id`.

### Receive an auto-reply push

1. Add **Osaurus Trigger** and activate the workflow.
2. Copy the Production HTTPS URL into the Osaurus channel outbound webhook field and enable sign + auto-reply.
3. The trigger item is the outbound v1 envelope (`content` is the agent reply).

### Stock HTTP fallback

You do not need this package. The same contract works with HTTP Request + Code + Wait. See [Osaurus n8n channel docs](https://github.com/osaurus-ai/osaurus/blob/main/docs/AGENT_CHANNELS_N8N.md).

## Resources

- [n8n community nodes documentation](https://docs.n8n.io/integrations/#community-nodes)
- [Osaurus n8n agent channel](https://github.com/osaurus-ai/osaurus/blob/main/docs/AGENT_CHANNELS_N8N.md)
- [Osaurus](https://osaurus.ai)

## Version history

### 0.1.0

First npm release (`n8n-nodes-osaurus@0.1.0`), published from GitHub Actions with provenance.

- Channel credential (HMAC / shared-secret header) with a 404-as-success probe.
- Channel operations: send-and-wait, poll, verify push.
- Osaurus Trigger for verified outbound pushes.
- API credential (`osk-v1`) plus agent run / dispatch for loopback. No Secure Channel client.

## Development

```bash
pnpm install
pnpm test
pnpm build
pnpm lint
pnpm dev
```

`pnpm test` is Vitest coverage of signing, envelope bytes, and SSE collection (including the known-answer HMAC from the Osaurus custom-HTTP runner tests). No live Osaurus instance is required.

## Releasing

Do not `npm publish` from a laptop. Local `npm run release` only bumps, tags, and opens a GitHub Release. The tag triggers [`.github/workflows/publish.yml`](.github/workflows/publish.yml), which publishes to npm with a provenance attestation.

First ship is `git tag 0.1.0 && git push origin 0.1.0` after `NPM_TOKEN` is set — not `npm run release` (that would bump to 0.1.1). Full steps: [RELEASING.md](RELEASING.md).
