# Registry maintainer runbook

## Revoke a package

1. Confirm the module ID, semantic version, and SHA-256 from the published signed index and release asset.
2. Add one exact entry to `revocations.toml` using the format in the README. Use a concise reason that is safe to show to users.
3. If every version is unsafe, also set their submission records to `yanked = true` or remove the module submission.
4. Open and review a pull request. Never expose the production signing secret to pull-request workflows.
5. Merge, wait for `Publish registry`, and verify that Pages and the raw `registry` branch contain the new signed root and revocation.
6. Publish a security advisory where disclosure is safe. A revocation blocks code execution but deliberately does not delete user settings or data.

## Rotate the production signing key

Rotation requires an overlap release; switching the registry first would strand existing clients.

1. Run `cargo run -- keygen --key-id registry-YYYY-NN --output keys` on a trusted machine. Move the private file into secure offline storage.
2. Commit only the new `.public` file under `trusted-keys/`.
3. Add the new ID/public-key pair beside the old pair in the launcher's `TRUSTED_REGISTRY_KEYS`, release that launcher, and allow an upgrade overlap period.
4. Replace the `RAYSLASH_REGISTRY_SIGNING_KEY` environment secret with the new private-key base64 and set the `RAYSLASH_REGISTRY_KEY_ID` environment variable to the new ID. These two values must change together.
5. Dispatch `Publish registry`. Verify the root key ID, both mirrors, signature, index digest, and revocations digest with the new public key before announcing completion.
6. After the supported client population has received the overlap release, publish a later launcher release that removes the retired key. Retain old public keys and incident records for audit history.

If the private key may be compromised, perform steps 1–5 immediately, revoke any suspect packages, and publish a launcher security update. Never reuse a signing key ID with different key material.

## Failed publish

Do not manually edit the `registry` branch or Pages output. Fix the source/tooling on a pull request and rerun the protected workflow. Clients continue using their last fully verified cache when either mirror is invalid or unavailable.
