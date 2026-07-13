# Submissions

Each accepted module has one TOML file in this directory. Identity and descriptive fields live at module level; every `[[versions]]` record contains its own exact `permissions` table. Submit additions and updates through pull requests. Pull-request validation downloads every referenced release asset, including yanked historical versions, and verifies its manifest, version-specific permissions, source, size, and SHA-256 digest.

Generated catalogs use schema 2. Schema 1 represented permissions at module level and cannot describe permission changes between immutable releases; schema 2 launchers explicitly migrate verified schema-1 catalogs in memory by applying that legacy set to each version.

For an isolated local signed-registry test, `build --allow-insecure-loopback` permits only an explicit `http://127.0.0.1:<port>` base URL. Production builds continue to require HTTPS.
