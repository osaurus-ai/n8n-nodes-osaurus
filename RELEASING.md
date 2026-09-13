# Releasing n8n-nodes-osaurus

Publish only from GitHub Actions. A laptop `npm publish` has no provenance, and n8n will not accept it for Creator Portal verification (required since May 2026).

```
local `npm run release`  →  bump, changelog, commit, tag, GitHub Release
         tag push `*.*.*`  →  .github/workflows/publish.yml
         GITHUB_ACTIONS     →  lint, build, `npm publish` with provenance
```

`ci.yml` is the PR/`main` gate. It never publishes.

## First publish (0.1.0)

`package.json` is already `0.1.0` and there is no tag. Do **not** run `npm run release` for this ship — release-it will bump to 0.1.1.

npm cannot attach a Trusted Publisher until the package name exists, so the first publish uses a short-lived token.

1. Create an npm org (`osaurus` recommended). Enable 2FA on every maintainer.
2. Create a **granular access token** (Automation, Read and write, this package / org, short expiry).
3. Store it as repo secret `NPM_TOKEN` on [osaurus-ai/n8n-nodes-osaurus](https://github.com/osaurus-ai/n8n-nodes-osaurus).
4. After `publish.yml` is on `main`:

   ```bash
   git tag 0.1.0
   git push origin 0.1.0
   ```

5. Confirm [npmjs.com/package/n8n-nodes-osaurus](https://www.npmjs.com/package/n8n-nodes-osaurus) shows `0.1.0` with a provenance attestation.
6. Add the npm org as an owner of the unscoped package.
7. On the package: **Trusted Publishers → GitHub Actions**
   - Organization or user: `osaurus-ai`
   - Repository: `n8n-nodes-osaurus`
   - Workflow filename: `publish.yml` (the filename, not the workflow `name:` field)
   - Environment: leave blank
   - Allowed action: `npm publish`
8. Delete `NPM_TOKEN` from GitHub and revoke the token.
9. On the package, set **Require 2FA and disallow tokens** so only the workflow can publish.

Skip a GitHub Environment with required reviewers until this first ship works. If you add one later, recreate the Trusted Publisher with that environment name.

## Later releases

On a clean `main`:

```bash
npm run release
```

release-it prompts for patch / minor / major, writes `CHANGELOG.md`, commits, tags, pushes, and opens a GitHub Release. The tag triggers `publish.yml`, which is the only process allowed to talk to npm.

If you push a version tag without running release-it, the workflow creates a GitHub Release when one is missing.

## Install after publish

In n8n: **Settings → Community Nodes → `n8n-nodes-osaurus`**.

Optional: submit [creators.n8n.io](https://creators.n8n.io/nodes) for the verified Cloud listing. This package already meets the technical bar (`n8n-nodes-` name, `n8n-community-node-package` keyword, `n8n.strict`, no runtime dependencies, GHA + provenance).
