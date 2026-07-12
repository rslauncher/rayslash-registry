#!/bin/sh
set -eu

key_id="${1:-registry-2026-01}"
cargo run --locked -- keygen --key-id "$key_id" --output keys
printf '%s\n' "Store keys/$key_id.private offline and as RAYSLASH_REGISTRY_SIGNING_KEY in the registry-production environment."
printf '%s\n' "Commit and return only keys/$key_id.public. The keys directory is ignored to prevent accidental commits."

