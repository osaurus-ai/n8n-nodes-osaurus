# n8n-nodes-osaurus

This is an n8n community node. It lets an n8n workflow talk to [Osaurus](https://osaurus.ai) — a local agent runtime — over the first-party **n8n agent channel** (secret-verified webhook in, poll or webhook out, end-to-end encrypted through the Osaurus relay when paired with an agent) and, optionally, the plaintext **agent API** on the same Mac.

**How the two connect:** n8n calls Osaurus, never the other way around. The one **pairing code** you copy from Osaurus into this node's credential is the whole hand-off — it already contains the URL that reaches your Mac from where n8n runs, the connection id, the secret and the verification method. You only ever type an n8n URL into Osaurus if you want it to *push* replies to a workflow (the optional Outbound Webhook URL).

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
2. Install `@osaurus/n8n-nodes-osaurus`.
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

**Setup: Pairing code** (default) — one paste.

1. In Osaurus, **Settings → Channels → n8n**, open the connection and go to **Pair**. A new channel already has a random secret, and the code appears as soon as the earlier steps (name, **Where is your n8n?**, **Who answers?**) are answered. If Osaurus shows a blocker instead of a code (for example *Relay not connected* for a Remote n8n), fix that first — the code it withholds could not have worked.
2. Under **Pair with n8n**, click the copy button.
3. In n8n, create an **Osaurus Channel** credential, leave **Setup** on *Pairing Code*, paste, and click **Test**.

The code (`osrs-n8n-1.…`) is base64url JSON carrying **only the URL valid for the location you picked in Osaurus** (`127.0.0.1` for This Mac, `host.docker.internal` for Docker Desktop, the LAN address, or the relay URL for Remote), the connection id, the secret, the verification method, and — when a local agent is bound under **Who answers?** — that agent's pinned address. **It contains the secret; treat it like one.** Regenerating the secret in Osaurus invalidates old codes; moving n8n means changing **Where is your n8n?** and pasting a new code.

**Test** probes the URL(s) in order with `GET /channels/n8n/{id}/ping` (5 s per plaintext candidate) and reports the first that answers, e.g. `Connected to https://0x…agent.osaurus.ai (hmac_sha256, end-to-end encrypted).` A `426` on a candidate means that URL is reached from another machine and the Osaurus connection requires Secure Channel; either include an agent in the pairing code or allow plaintext HTTP under **Where is your n8n? → Another machine on my network**. If every URL in the code is private (loopback / Docker / LAN) and none answers, Test says so and points you at **Where is your n8n? → Remote**. The winner is cached per credential and re-probed on network errors or on the next explicit Test.

**Secure Channel.** When the code carries an agent address, every Channel operation is wrapped in Osaurus Secure Channel v1 (X25519 + HKDF + ChaCha20-Poly1305, server identity pinned to the agent's secp256k1 address). The relay only forwards opaque frames and cannot read prompts or replies. There is no plaintext fallback: if `/secure/session` is missing the node fails with a clear error instead of downgrading. The implementation has **no runtime dependencies** — keccak-256 and secp256k1 recovery are implemented in `src/crypto/` and pinned against shared Swift/TypeScript vectors.

**Setup: Manual** (advanced, plaintext only) keeps the four original fields for saved credentials and stock-HTTP-style setups:

| Field | Notes |
| --- | --- |
| Base URL | `http://127.0.0.1:1337` from this Mac; `http://host.docker.internal:1337` from Docker Desktop on this Mac |
| Connection ID | Id from Osaurus **Settings → Channels → n8n → Name it** |
| Channel Secret | From **Pair → Advanced**; stored in the Osaurus Keychain |
| Verification Method | `HMAC-SHA256` (default) or `Shared secret header` — must match **Pair → Advanced → Verification** |
| Header Name | Optional override; defaults `X-Osaurus-Channel-Signature` / `X-Osaurus-Channel-Secret` |

Credentials saved without a **Setup** field are treated as Manual and keep working.

### Osaurus API

Used for `/agents/{id}/run` and `/dispatch` on **loopback or a trusted LAN**.

| Field | Notes |
| --- | --- |
| Base URL | Usually `http://127.0.0.1:1337` |
| Access Key | Agent-scoped `osk-v1-...` from **Share Agent** |

**The access key is not the inbound channel secret.** Remote `/agents/.../run` without Secure Channel returns `426 Upgrade Required`. The Agent resource is plaintext-only in this package; for remote n8n use the Channel resource with a pairing code, which rides Secure Channel.

## Compatibility

- Built against the current n8n community-node API (`n8nNodesApiVersion: 1`, `@n8n/node-cli`).
- Osaurus n8n channel contract v1 (HMAC or shared-secret header, poll-based replies, optional signed push, `GET /channels/n8n/{id}/ping`) and Secure Channel v1 (`/secure/session`, `/secure/call`). The ping route and pairing code need an Osaurus build that ships **Pair with n8n**.
- Requires n8n 1.x on Node 20+ that can load community node packages. Zero runtime dependencies.

## Usage

### Map the node to the Osaurus n8n sheet

In Osaurus, **Settings → Channels → n8n**:

1. **Name it** — the display name; the connection id is filled from it and appears in the pairing code and in every error this node raises.
2. **Where is your n8n?** — This Mac, Docker Desktop on this Mac, another machine on your network, or Remote. This picks the URL the pairing code carries, whether Relay is needed, and whether plaintext HTTP is even offered (LAN only).
3. **Who answers?** — the agent that replies. Binding a local agent makes the pairing code end-to-end encrypted, and for Remote this step also has the **Enable Relay** button. Default reply mode is poll (this node waits for you). Optional push needs a public **HTTPS** webhook (loopback / RFC1918 / `http://` are refused) — this is the only place an n8n URL is entered. If **Allow Agents to Send Messages** is off, push fails; poll still returns the reply.
4. **Pair** — **Pair with n8n** (the code, or the blocker that is stopping it), and under **Advanced** the secret (pre-generated, with Rotate), verification method, and everything for a plain HTTP Request node: URLs for the chosen location, sample envelope, HMAC Code node, curl, and the osk-v1 key for the Agent resource.
5. **Prove it** — **first run asks for approval.** Run the workflow once; Osaurus shows *Workflow '<conversation_id>' (sender '<sender.id>') wants to use <channel> — Allow / Deny*. Allow adds those ids to the allowlists and saves; run the workflow again. Until then this node fails with `pending_approval` and the exact ids to approve. Nothing reaches the agent before you allow it. Allowlists can still be edited by hand under **Advanced**.

### Remote n8n (n8n Cloud or another host)

In Osaurus choose **Where is your n8n? → Remote**, bind a local agent under **Who answers?** and press **Enable Relay** there. The pairing code is issued once the relay is connected; it carries only the relay URL, and because it also carries the agent address the node speaks Secure Channel through the relay. You do not need to allow plaintext, open a port, or run a tunnel. If you already pasted a code that only had local URLs, Test tells you and points at this step.

### Send a message and use the reply

1. Add **Osaurus** → Channel → **Send Message and Wait**.
2. Set Conversation ID and Sender ID to any stable values (e.g. the workflow name and `workflow`).
3. Set Content, e.g. `Reply with the single word PONG`.
4. Run once. The first run fails with **pending_approval** and the ids to approve; press **Allow** under **Prove it** in Osaurus and run again.
5. The item output is the poll JSON: `status`, `output`, `task_id`. `status: "rejected"` and `dispatch: "suppressed:*"` throw instead of returning silently, with the reason and the Osaurus setting to change.

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

### 0.2.0

Copy and diagnostics for the redesigned Osaurus n8n sheet (*Name it → Where is your n8n? → Who answers? → Pair → Prove it*). Wire contract unchanged.

- **`pending_approval`** rejection: the first run of a workflow now fails with the exact conversation / sender ids to approve under **Prove it**, instead of an allowlist error. Older Osaurus builds' `sender_not_allowlisted` / `room_not_allowlisted` are still handled.
- **Location-aware probe hint**: when every URL in the code is private (loopback / Docker / LAN) and none answers, Test explains that the code was issued for a local n8n and points at **Where is your n8n? → Remote**.
- **Per-candidate probe timeout** (5 s for plaintext candidates) so a stale LAN address no longer burns the whole Test budget.
- Field descriptions, credential notices and error messages point at the new step names.

### 0.1.0

First npm release (`@osaurus/n8n-nodes-osaurus@0.1.0`), published from GitHub Actions with provenance.

- **Pairing code** setup for the Channel credential: paste one `osrs-n8n-1.…` string from Osaurus **Pair → Pair with n8n**. Manual four-field setup remains as the advanced option.
- **Secure Channel v1 client.** When the code pins an agent address, every Channel request is end-to-end encrypted through the Osaurus relay; no plaintext downgrade. Zero runtime dependencies (in-repo keccak-256 and secp256k1 recovery, pinned to shared Swift/TS known-answer vectors).
- **Candidate probing** via `GET /channels/n8n/{id}/ping`: the credential Test names the URL it reached and whether the link is encrypted.
- **Fail loudly** on `status: "rejected"` and `dispatch: "suppressed:*"` with the rejection reason and the Osaurus setting to fix.
- Channel operations: send-and-wait, poll, verify push. Osaurus Trigger for verified outbound pushes.
- API credential (`osk-v1`) plus agent run / dispatch for loopback. The Agent resource does not go through Secure Channel.

## Development

```bash
pnpm install
pnpm test
pnpm build
pnpm lint
pnpm dev
```

`pnpm test` is Vitest coverage of signing, envelope bytes, SSE collection, pairing-code decoding, transport probing, and the Secure Channel client (session cache, retry-once, replay refusal, frame ordering, identity pinning) against a mocked Osaurus. `test/vectors/secure-channel-v1-vectors.json` is the same known-answer fixture the Swift `SecureChannelVectorsTests` asserts, so a byte-level drift on either side fails both suites; regenerate it from the Osaurus repo with `OSAURUS_WRITE_SC_VECTORS=1` and copy it here. No live Osaurus instance is required.

## Releasing

Do not `npm publish` from a laptop. Local `npm run release` only bumps, tags, and opens a GitHub Release. The tag triggers [`.github/workflows/publish.yml`](.github/workflows/publish.yml), which publishes to npm with a provenance attestation.

`package.json` is already `0.2.0`; ship it with `git tag 0.2.0 && git push origin 0.2.0` once `NPM_TOKEN` is set — not `npm run release` (that would bump to 0.2.1). Full steps: [RELEASING.md](RELEASING.md).
