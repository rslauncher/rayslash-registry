# rayslash module registry

This repository is the reviewed source for the signed static rayslash module catalog.

- Packages remain in their public GitHub repositories as immutable Release assets.
- Pull requests validate package identity, compatibility, size, digest, and manifest.
- The post-merge workflow signs the registry root and publishes GitHub Pages plus a raw `registry` branch fallback.
- Installed clients retain their last verified cache.

See [MODERATION.md](MODERATION.md) and the [module SDK](https://github.com/rslauncher/rayslash-module-sdk).
Maintainer incident, revocation, and signing-key procedures are in [RUNBOOK.md](RUNBOOK.md).

API v1 accepts WASM modules. The `declarative` kind is reserved until a future API defines a complete format and runtime.

## Emergency revocation

Add an exact package identity to `revocations.toml` and open a pull request:

```toml
[[revoked]]
module_id = "io.github.owner.module"
version = "1.2.3"
sha256 = "64-lowercase-hex-characters"
reason = "Concise user-facing security reason."
revoked_at = "2026-07-12T12:00:00Z"
```

The protected publish workflow signs the digest of `revocations.json` in the registry root. Clients refuse that exact package at install time and execution time. Do not reuse a revoked version number or release asset.

## Maintainer bootstrap

```sh
scripts/generate-signing-key.sh registry-2026-01
```

Never commit or paste the private key. Add its single base64 line to the protected `registry-production` environment as `RAYSLASH_REGISTRY_SIGNING_KEY`. Public trust roots belong in [`trusted-keys/`](trusted-keys/).
