# rayslash module registry

This repository is the reviewed source for the signed static rayslash module catalog.

- Packages remain in their public GitHub repositories as immutable Release assets.
- Pull requests validate package identity, compatibility, size, digest, and manifest.
- The post-merge workflow signs the registry root and publishes GitHub Pages plus a raw `registry` branch fallback.
- Installed clients retain their last verified cache.

See [MODERATION.md](MODERATION.md) and the [module SDK](https://github.com/rslauncher/rayslash-module-sdk).

## Maintainer bootstrap

```sh
scripts/generate-signing-key.sh registry-2026-01
```

Never commit or paste the private key. Add its single base64 line to the protected `registry-production` environment as `RAYSLASH_REGISTRY_SIGNING_KEY`. Commit only the public key after removing the `keys/` ignore rule for that one public file or place it under a dedicated tracked `trusted-keys/` directory.

