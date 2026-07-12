use std::{
    collections::BTreeSet,
    fs,
    io::{Cursor, Read},
    path::{Component, Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rayslash_module_manifest::{MAX_PACKAGE_BYTES, ModuleKind, ModuleManifest, Permissions};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: u32 = 1;

#[derive(Parser)]
#[command(name = "rayslash-registry", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Build {
        #[arg(long, default_value = "modules")]
        modules: PathBuf,
        #[arg(long, default_value = "public")]
        output: PathBuf,
        #[arg(long, default_value = "https://rslauncher.github.io/rayslash-registry")]
        base_url: String,
        #[arg(long, default_value = "registry-2026-01")]
        key_id: String,
        #[arg(long)]
        fetch: bool,
    },
    Sign {
        #[arg(long, default_value = "public/v1/root.json")]
        root: PathBuf,
        #[arg(long, env = "RAYSLASH_REGISTRY_SIGNING_KEY")]
        private_key: String,
    },
    Verify {
        #[arg(long, default_value = "public/v1/root.json")]
        root: PathBuf,
        #[arg(long)]
        public_key: String,
    },
    Keygen {
        #[arg(long)]
        key_id: String,
        #[arg(long, default_value = "keys")]
        output: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission {
    id: String,
    name: String,
    description: String,
    author: String,
    license: String,
    kind: ModuleKind,
    permissions: Permissions,
    repository: String,
    official: bool,
    review_status: ReviewStatus,
    github_stars: u64,
    updated_at: DateTime<Utc>,
    versions: Vec<SubmittedVersion>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ReviewStatus {
    Reviewed,
    LimitedReview,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmittedVersion {
    version: Version,
    api_version: VersionReq,
    source_commit: String,
    asset_url: String,
    sha256: String,
    size: u64,
    yanked: bool,
}

#[derive(Debug, Serialize)]
struct RegistryIndex {
    schema_version: u32,
    generated_at: DateTime<Utc>,
    modules: Vec<Submission>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegistryRoot {
    schema_version: u32,
    generated_at: DateTime<Utc>,
    key_id: String,
    index_url: String,
    index_sha256: String,
    revocations_url: String,
    revocations_sha256: String,
}

#[derive(Debug, Serialize)]
struct Revocations {
    schema_version: u32,
    generated_at: DateTime<Utc>,
    revoked: Vec<serde_json::Value>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Build {
            modules,
            output,
            base_url,
            key_id,
            fetch,
        } => build(&modules, &output, &base_url, &key_id, fetch)?,
        Command::Sign { root, private_key } => sign(&root, &private_key)?,
        Command::Verify { root, public_key } => verify(&root, &public_key)?,
        Command::Keygen { key_id, output } => keygen(&key_id, &output)?,
    }
    Ok(())
}

fn build(
    modules_dir: &Path,
    output: &Path,
    base_url: &str,
    key_id: &str,
    fetch: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !base_url.starts_with("https://") {
        return Err("base URL must use HTTPS".into());
    }
    let mut modules = Vec::new();
    let mut ids = BTreeSet::new();
    if modules_dir.exists() {
        let mut paths = fs::read_dir(modules_dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("toml"))
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            let submission: Submission = toml::from_str(&fs::read_to_string(&path)?)?;
            validate_submission(&submission)?;
            if !ids.insert(submission.id.clone()) {
                return Err(format!("duplicate module ID {}", submission.id).into());
            }
            if fetch {
                for version in &submission.versions {
                    validate_remote_package(&submission, version)?;
                }
            }
            modules.push(submission);
        }
    }
    modules.sort_by(|left, right| left.id.cmp(&right.id));
    let generated_at = Utc::now();
    let index = RegistryIndex {
        schema_version: SCHEMA_VERSION,
        generated_at,
        modules,
    };
    let revocations = Revocations {
        schema_version: SCHEMA_VERSION,
        generated_at,
        revoked: Vec::new(),
    };
    let v1 = output.join("v1");
    fs::create_dir_all(&v1)?;
    let index_bytes = pretty_json(&index)?;
    let revocation_bytes = pretty_json(&revocations)?;
    fs::write(v1.join("index.json"), &index_bytes)?;
    fs::write(v1.join("revocations.json"), &revocation_bytes)?;
    let root = RegistryRoot {
        schema_version: SCHEMA_VERSION,
        generated_at,
        key_id: key_id.to_owned(),
        index_url: format!("{}/v1/index.json", base_url.trim_end_matches('/')),
        index_sha256: sha256(&index_bytes),
        revocations_url: format!("{}/v1/revocations.json", base_url.trim_end_matches('/')),
        revocations_sha256: sha256(&revocation_bytes),
    };
    fs::write(v1.join("root.json"), pretty_json(&root)?)?;
    fs::write(
        output.join("index.html"),
        "<!doctype html><meta charset=\"utf-8\"><title>rayslash modules</title><h1>rayslash module registry</h1><p><a href=\"v1/index.json\">Registry index</a></p>\n",
    )?;
    fs::write(output.join(".nojekyll"), "")?;
    println!("built {} module records", index.modules.len());
    Ok(())
}

fn validate_submission(submission: &Submission) -> Result<(), Box<dyn std::error::Error>> {
    rayslash_module_manifest::validate_module_id(&submission.id)?;
    for (field, value, maximum) in [
        ("name", submission.name.as_str(), 80),
        ("description", submission.description.as_str(), 200),
        ("author", submission.author.as_str(), 80),
        ("license", submission.license.as_str(), 80),
    ] {
        let length = value.chars().count();
        if length == 0
            || length > maximum
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(format!("{} has invalid {field}", submission.id).into());
        }
    }
    if submission.official != submission.author.eq_ignore_ascii_case("rayslash") {
        return Err(format!("{} has inconsistent official author", submission.id).into());
    }
    if !submission.repository.starts_with("https://github.com/")
        || submission.repository.contains(['?', '#'])
    {
        return Err(format!("{} has an invalid repository URL", submission.id).into());
    }
    if submission.official != submission.id.starts_with("rayslash.") {
        return Err(format!("{} has inconsistent official identity", submission.id).into());
    }
    if submission.versions.is_empty() {
        return Err(format!("{} has no versions", submission.id).into());
    }
    let mut versions = BTreeSet::new();
    for version in &submission.versions {
        if !versions.insert(version.version.clone()) {
            return Err(format!("{} repeats version {}", submission.id, version.version).into());
        }
        if version.source_commit.len() != 40
            || !version
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(format!(
                "{} {} has invalid source commit",
                submission.id, version.version
            )
            .into());
        }
        if !version
            .asset_url
            .starts_with(&format!("{}/releases/download/", submission.repository))
        {
            return Err(format!(
                "{} {} asset is not a release of its source",
                submission.id, version.version
            )
            .into());
        }
        if version.sha256.len() != 64
            || !version.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(
                format!("{} {} has invalid SHA-256", submission.id, version.version).into(),
            );
        }
        if version.size == 0 || version.size > MAX_PACKAGE_BYTES {
            return Err(format!("{} {} has invalid size", submission.id, version.version).into());
        }
    }
    Ok(())
}

fn validate_remote_package(
    submission: &Submission,
    version: &SubmittedVersion,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = ureq::get(&version.asset_url)
        .header("User-Agent", "rayslash-registry/1")
        .call()?;
    let bytes = response
        .into_body()
        .with_config()
        .limit(MAX_PACKAGE_BYTES)
        .read_to_vec()?;
    if bytes.len() as u64 != version.size {
        return Err(format!("{} {} size mismatch", submission.id, version.version).into());
    }
    if sha256(&bytes) != version.sha256.to_ascii_lowercase() {
        return Err(format!("{} {} digest mismatch", submission.id, version.version).into());
    }
    let decoder = zstd::Decoder::new(Cursor::new(bytes))?;
    let mut archive = tar::Archive::new(decoder);
    let mut manifest = None;
    let mut entries = 0_u32;
    for entry in archive.entries()? {
        let entry = entry?;
        entries += 1;
        if entries > 256 {
            return Err("package has too many entries".into());
        }
        let path = entry.path()?.into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err("package contains an unsafe path".into());
        }
        if !entry.header().entry_type().is_file() {
            return Err("package contains a non-file entry".into());
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("module.toml") {
            let mut text = String::new();
            entry.take(64 * 1024 + 1).read_to_string(&mut text)?;
            manifest = Some(toml::from_str::<ModuleManifest>(&text)?);
        }
    }
    let manifest = manifest.ok_or("package has no module.toml")?;
    manifest.validate(submission.official)?;
    if manifest.id != submission.id
        || manifest.name != submission.name
        || manifest.description != submission.description
        || manifest.author != submission.author
        || manifest.license != submission.license
        || manifest.kind != submission.kind
        || manifest.permissions != submission.permissions
        || manifest.version != version.version
        || manifest.api_version != version.api_version
        || manifest.source != submission.repository
    {
        return Err("package manifest does not match registry submission".into());
    }
    Ok(())
}

fn sign(root: &Path, encoded_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bytes: [u8; 32] = STANDARD
        .decode(encoded_key.trim())?
        .try_into()
        .map_err(|_| "private key must contain exactly 32 bytes")?;
    let signing = SigningKey::from_bytes(&bytes);
    let root_bytes = fs::read(root)?;
    let signature: Signature = signing.sign(&root_bytes);
    fs::write(
        signature_path(root),
        format!("{}\n", STANDARD.encode(signature.to_bytes())),
    )?;
    println!("signed {}", root.display());
    Ok(())
}

fn verify(root: &Path, public_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let value = public_key
        .split_whitespace()
        .last()
        .ok_or("public key is empty")?;
    let bytes: [u8; 32] = STANDARD
        .decode(value)?
        .try_into()
        .map_err(|_| "public key must contain exactly 32 bytes")?;
    let verifying = VerifyingKey::from_bytes(&bytes)?;
    let signature_text = fs::read_to_string(signature_path(root))?;
    let signature_bytes: [u8; 64] = STANDARD
        .decode(signature_text.trim())?
        .try_into()
        .map_err(|_| "signature must contain exactly 64 bytes")?;
    verifying.verify(&fs::read(root)?, &Signature::from_bytes(&signature_bytes))?;
    println!("verified {}", root.display());
    Ok(())
}

fn keygen(key_id: &str, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if key_id.trim().is_empty() || key_id.chars().any(char::is_whitespace) {
        return Err("invalid key ID".into());
    }
    fs::create_dir_all(output)?;
    let signing = SigningKey::generate(&mut OsRng);
    let private_path = output.join(format!("{key_id}.private"));
    let public_path = output.join(format!("{key_id}.public"));
    if private_path.exists() || public_path.exists() {
        return Err("key output already exists".into());
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&private_path)?;
        writeln!(file, "{}", STANDARD.encode(signing.to_bytes()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(
            &private_path,
            format!("{}\n", STANDARD.encode(signing.to_bytes())),
        )?;
    }
    fs::write(
        &public_path,
        format!(
            "{key_id} {}\n",
            STANDARD.encode(signing.verifying_key().to_bytes())
        ),
    )?;
    println!(
        "generated {} and {}; keep the private file secret",
        private_path.display(),
        public_path.display()
    );
    Ok(())
}

fn pretty_json(value: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn signature_path(root: &Path) -> PathBuf {
    root.with_file_name("root.json.sig")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_builds_deterministic_links_and_digests() {
        let base =
            std::env::temp_dir().join(format!("rayslash-registry-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("modules")).unwrap();
        build(
            &base.join("modules"),
            &base.join("public"),
            "https://example.test",
            "test-key",
            false,
        )
        .unwrap();
        let root: RegistryRoot =
            serde_json::from_slice(&fs::read(base.join("public/v1/root.json")).unwrap()).unwrap();
        assert_eq!(root.index_url, "https://example.test/v1/index.json");
        assert_eq!(
            root.index_sha256,
            sha256(&fs::read(base.join("public/v1/index.json")).unwrap())
        );
        fs::remove_dir_all(base).unwrap();
    }
}
