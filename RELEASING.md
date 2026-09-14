# Releasing @osaurus/n8n-nodes-osaurus

Publish only from GitHub Actions. A laptop `npm publish` has no provenance, and n8n will not accept it for Creator Portal verification (required since May 2026).

```
local `npm run release`  →  bump, changelog, commit, tag, GitHub Release
         tag push `*.*.*`  →  .github/workflows/publish.yml
         GITHUB_ACTIONS     →  lint, build, `npm publish` with provenance
```

`ci.yml` is the PR/`main` gate. It never publishes.

The npm package is scoped to the **osaurus** npm org (`@osaurus/n8n-nodes-osaurus`). The GitHub repo stays `osaurus-ai/n8n-nodes-osaurus`.

## First publish (0.1.0)

`package.json` is already `0.1.0`. Do **not** run `npm run release` for this ship — release-it will bump to 0.1.1.

npm cannot attach a Trusted Publisher until the package name exists, so the first publish uses a short-lived token.

1. Create a **granular access token** on the `osaurus` npm org (Automation / Bypass 2FA, Read and write, org packages, short expiry).
2. Store it as org or repo secret `NPM_TOKEN` on [osaurus-ai/n8n-nodes-osaurus](https://github.com/osaurus-ai/n8n-nodes-osaurus). A repo secret of the same name overrides an org secret.
3. After `publish.yml` is on `main`:

   ```bash
   git tag 0.1.0
   git push origin 0.1.0
   ```

4. Confirm [npmjs.com/package/@osaurus/n8n-nodes-osaurus](https://www.npmjs.com/package/@osaurus/n8n-nodes-osaurus) shows `0.1.0` with a provenance attestation.
5. On the package: **Trusted Publishers → GitHub Actions**
   - Organization or user: `osaurus-ai`
   - Repository: `n8n-nodes-osaurus`
   - Workflow filename: `publish.yml` (the filename, not the workflow `name:` field)
   - Environment: leave blank
   - Allowed action: `npm publish`
6. Delete `NPM_TOKEN` from GitHub and revoke the token.
7. On the package, set **Require 2FA and disallow tokens** so only the workflow can publish.

Skip a GitHub Environment with required reviewers until this first ship works. If you add one later, recreate the Trusted Publisher with that environment name.

## Later releases

On a clean `main`:

```bash
npm run release
```

release-it prompts for patch / minor / major, writes `CHANGELOG.md`, commits, tags, pushes, and opens a GitHub Release. The tag triggers `publish.yml`, which is the only process allowed to talk to npm.

If you push a version tag without running release-it, the workflow creates a GitHub Release when one is missing.

## Install after publish

In n8n: **Settings → Community Nodes → `@osaurus/n8n-nodes-osaurus`**.

Optional: submit [creators.n8n.io](https://creators.n8n.io/nodes) for the verified Cloud listing. This package already meets the technical bar (`@scope/n8n-nodes-` name, `n8n-community-node-package` keyword, `n8n.strict`, no runtime dependencies, GHA + provenance).
