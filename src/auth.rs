//! Authenticated Transfer Layer for sxfer.
//!
//! Provides cryptographic signing and verification for one-way simplex transfers
//! using Ed25519 digital signatures, SHA-256 content hashing, canonical manifests,
//! quarantine staging, and replay protection.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

pub const MANIFEST_VERSION: u32 = 1;
pub const DEFAULT_MAX_CLOCK_SKEW_SECS: i64 = 300; // 5 minutes
pub const MANIFEST_FILENAME: &str = ".sxfer_manifest.json";

/// Entry in a transfer manifest describing a single file, directory, or symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub path: String,
    pub entry_type: char, // 'f', 'd', 'l'
    pub size: u64,
    pub sha256_hex: String,
    pub link_target: String,
    pub mode: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
}

/// Inventory of all items expected in an authenticated transfer batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferManifest {
    pub version: u32,
    pub transfer_id: String, // 32-char hex string
    pub timestamp_sec: i64,
    pub total_entries: usize,
    pub total_bytes: u64,
    pub entries: Vec<ManifestEntry>,
}

/// Envelope containing the manifest JSON and the sender's Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedManifest {
    pub manifest_json: String,
    pub signature_hex: String,
    pub public_key_hex: String,
}

// ------------------------------------------------------------------ Cryptographic Hashing & Signing

/// Computes the SHA-256 hash of a byte slice and returns it as a lowercase hex string.
pub fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hex_encode(&hash)
}

/// Computes the SHA-256 hash of a file on disk.
pub fn compute_file_sha256_hex(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|e| format!("Failed to open '{}': {}", path.display(), e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("Failed to read '{}': {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

/// Generates a new random Ed25519 keypair in PKCS#8 v2 format along with raw public key.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let rng = SystemRandom::new();
    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| format!("Failed to generate Ed25519 keypair: {:?}", e))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
        .map_err(|e| format!("Failed to parse generated keypair: {:?}", e))?;
    let pub_bytes = key_pair.public_key().as_ref().to_vec();
    Ok((pkcs8_doc.as_ref().to_vec(), pub_bytes))
}

/// Saves an Ed25519 keypair to disk with restrictive file permissions.
pub fn save_keypair(
    private_key_path: &Path,
    public_key_path: &Path,
    pkcs8_bytes: &[u8],
    pub_bytes: &[u8],
) -> Result<(), String> {
    if let Some(parent) = private_key_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Some(parent) = public_key_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    // Write private key with 0600 permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(private_key_path)
            .map_err(|e| format!("Failed to create '{}': {}", private_key_path.display(), e))?;
        f.write_all(pkcs8_bytes)
            .map_err(|e| format!("Failed to write to '{}': {}", private_key_path.display(), e))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(private_key_path, pkcs8_bytes)
            .map_err(|e| format!("Failed to write '{}': {}", private_key_path.display(), e))?;
    }

    // Write public key hex with 0644 permissions
    let pub_hex = hex_encode(pub_bytes);
    fs::write(public_key_path, pub_hex.as_bytes())
        .map_err(|e| format!("Failed to write '{}': {}", public_key_path.display(), e))?;

    Ok(())
}

/// Loads an Ed25519 private key from a PKCS#8 file or raw 32-byte seed.
pub fn load_private_key(path: &Path) -> Result<Ed25519KeyPair, String> {
    verify_key_file_permissions(path)?;
    let bytes = fs::read(path)
        .map_err(|e| format!("Failed to read private key '{}': {}", path.display(), e))?;
    if let Ok(kp) = Ed25519KeyPair::from_pkcs8(&bytes) {
        return Ok(kp);
    }
    if bytes.len() == 32 {
        if let Ok(kp) = Ed25519KeyPair::from_seed_unchecked(&bytes) {
            return Ok(kp);
        }
    }
    if let Ok(hex_str) = std::str::from_utf8(&bytes) {
        let trimmed = hex_str.trim();
        if let Some(seed) = hex_decode(trimmed) {
            if seed.len() == 32 {
                if let Ok(kp) = Ed25519KeyPair::from_seed_unchecked(&seed) {
                    return Ok(kp);
                }
            }
        }
    }
    Err(format!(
        "Invalid Ed25519 private key format in '{}' (expected PKCS#8 or 32-byte seed)",
        path.display()
    ))
}

/// Loads an Ed25519 public key from a file (raw 32 bytes or 64-char hex string).
pub fn load_public_key(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("Failed to read public key '{}': {}", path.display(), e))?;
    if bytes.len() == 32 {
        return Ok(bytes);
    }
    if let Ok(s) = std::str::from_utf8(&bytes) {
        let trimmed = s.trim();
        if let Some(decoded) = hex_decode(trimmed) {
            if decoded.len() == 32 {
                return Ok(decoded);
            }
        }
    }
    Err(format!(
        "Invalid Ed25519 public key in '{}' (expected 32 raw bytes or 64-char hex string)",
        path.display()
    ))
}

/// Verifies that private key file permissions are not group or world writable on Unix.
pub fn verify_key_file_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o022 != 0 {
                return Err(format!(
                    "Insecure permissions ({:04o}) on private key '{}': file must not be group- or world-writable (mode 0600 recommended)",
                    mode & 0o7777,
                    path.display()
                ));
            }
        }
    }
    let _ = path;
    Ok(())
}

// ------------------------------------------------------------------ Manifest Construction & Serialization

impl TransferManifest {
    pub fn new(transfer_id: &str, timestamp_sec: i64) -> Self {
        Self {
            version: MANIFEST_VERSION,
            transfer_id: transfer_id.to_string(),
            timestamp_sec,
            total_entries: 0,
            total_bytes: 0,
            entries: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, entry: ManifestEntry) {
        if entry.entry_type == 'f' {
            self.total_bytes += entry.size;
        }
        self.total_entries += 1;
        self.entries.push(entry);
    }

    /// Serializes the manifest to canonical JSON format (sorted entries, compact spacing).
    pub fn to_canonical_json(&self) -> String {
        let mut sorted_entries = self.entries.clone();
        sorted_entries.sort_by(|a, b| a.path.cmp(&b.path));

        let mut out = String::with_capacity(1024 + sorted_entries.len() * 128);
        out.push_str("{\"version\":");
        out.push_str(&self.version.to_string());
        out.push_str(",\"transfer_id\":\"");
        out.push_str(&json_escape(&self.transfer_id));
        out.push_str("\",\"timestamp_sec\":");
        out.push_str(&self.timestamp_sec.to_string());
        out.push_str(",\"total_entries\":");
        out.push_str(&self.total_entries.to_string());
        out.push_str(",\"total_bytes\":");
        out.push_str(&self.total_bytes.to_string());
        out.push_str(",\"entries\":[");

        for (i, entry) in sorted_entries.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"path\":\"");
            out.push_str(&json_escape(&entry.path));
            out.push_str("\",\"type\":\"");
            out.push(entry.entry_type);
            out.push_str("\",\"size\":");
            out.push_str(&entry.size.to_string());
            out.push_str(",\"sha256\":\"");
            out.push_str(&entry.sha256_hex);
            out.push_str("\",\"link\":\"");
            out.push_str(&json_escape(&entry.link_target));
            out.push_str("\",\"mode\":");
            out.push_str(&(entry.mode & 0o0777).to_string());
            out.push_str(",\"mtime_sec\":");
            out.push_str(&entry.mtime_sec.to_string());
            out.push_str(",\"mtime_nsec\":");
            out.push_str(&entry.mtime_nsec.to_string());
            out.push('}');
        }

        out.push_str("]}");
        out
    }

    /// Signs this manifest with an Ed25519 private key.
    pub fn sign(&self, key_pair: &Ed25519KeyPair) -> SignedManifest {
        let manifest_json = self.to_canonical_json();
        let sig = key_pair.sign(manifest_json.as_bytes());
        let pub_hex = hex_encode(key_pair.public_key().as_ref());
        SignedManifest {
            manifest_json,
            signature_hex: hex_encode(sig.as_ref()),
            public_key_hex: pub_hex,
        }
    }
}

impl SignedManifest {
    /// Serializes the signed manifest envelope to JSON format.
    pub fn to_envelope_json(&self) -> String {
        format!(
            "{{\"manifest\":{},\"signature\":\"{}\",\"public_key\":\"{}\"}}",
            self.manifest_json, self.signature_hex, self.public_key_hex
        )
    }

    /// Parses and validates a signed manifest envelope from JSON string.
    pub fn parse(json: &str) -> Result<Self, String> {
        let sig = extract_json_string_field(json, "signature")
            .ok_or_else(|| "Signed manifest missing 'signature' field".to_string())?;
        let pubkey = extract_json_string_field(json, "public_key")
            .ok_or_else(|| "Signed manifest missing 'public_key' field".to_string())?;

        // Extract manifest sub-object
        let manifest_json = extract_json_object_field(json, "manifest")
            .ok_or_else(|| "Signed manifest missing 'manifest' object".to_string())?;

        Ok(SignedManifest {
            manifest_json,
            signature_hex: sig,
            public_key_hex: pubkey,
        })
    }

    /// Verifies the signature against a trusted public key and parses the inner manifest.
    pub fn verify(&self, trusted_pubkey: &[u8]) -> Result<TransferManifest, String> {
        let pubkey_bytes = hex_decode(&self.public_key_hex)
            .ok_or_else(|| "Invalid hex encoding for public key".to_string())?;
        if pubkey_bytes != trusted_pubkey {
            return Err(format!(
                "Public key mismatch: manifest signed with '{}', but trusted key is '{}'",
                self.public_key_hex,
                hex_encode(trusted_pubkey)
            ));
        }

        let sig_bytes = hex_decode(&self.signature_hex)
            .ok_or_else(|| "Invalid hex encoding for signature".to_string())?;
        if sig_bytes.len() != 64 {
            return Err("Invalid Ed25519 signature length (expected 64 bytes)".to_string());
        }

        let peer_pub = UnparsedPublicKey::new(&ED25519, trusted_pubkey);
        peer_pub
            .verify(self.manifest_json.as_bytes(), &sig_bytes)
            .map_err(|_| {
                "Ed25519 signature verification failed (corrupted manifest or forged signature)"
                    .to_string()
            })?;

        parse_manifest_json(&self.manifest_json)
    }
}

// ------------------------------------------------------------------ Manifest JSON Parser

fn parse_manifest_json(json: &str) -> Result<TransferManifest, String> {
    let version = extract_json_u64_field(json, "version")
        .ok_or_else(|| "Missing 'version' in manifest".to_string())? as u32;
    if version != MANIFEST_VERSION {
        return Err(format!(
            "Unsupported manifest version '{}' (expected {})",
            version, MANIFEST_VERSION
        ));
    }

    let transfer_id = extract_json_string_field(json, "transfer_id")
        .ok_or_else(|| "Missing 'transfer_id' in manifest".to_string())?;
    if transfer_id.is_empty() || transfer_id.len() > 64 {
        return Err("Invalid 'transfer_id' in manifest".to_string());
    }

    let timestamp_sec = extract_json_i64_field(json, "timestamp_sec")
        .ok_or_else(|| "Missing 'timestamp_sec' in manifest".to_string())?;
    let total_entries = extract_json_u64_field(json, "total_entries")
        .ok_or_else(|| "Missing 'total_entries' in manifest".to_string())?
        as usize;
    let total_bytes = extract_json_u64_field(json, "total_bytes")
        .ok_or_else(|| "Missing 'total_bytes' in manifest".to_string())?;

    let entries_str = extract_json_array_field(json, "entries")
        .ok_or_else(|| "Missing 'entries' array in manifest".to_string())?;

    let mut entries = Vec::new();
    let mut calculated_bytes = 0u64;

    for item_str in split_json_objects(&entries_str) {
        let path = extract_json_string_field(&item_str, "path")
            .ok_or_else(|| "Missing 'path' in entry".to_string())?;
        let entry_type_str = extract_json_string_field(&item_str, "type")
            .ok_or_else(|| "Missing 'type' in entry".to_string())?;
        let entry_type = entry_type_str
            .chars()
            .next()
            .ok_or_else(|| "Empty 'type' in entry".to_string())?;
        if entry_type != 'f' && entry_type != 'd' && entry_type != 'l' {
            return Err(format!(
                "Invalid entry type '{}' for path '{}'",
                entry_type, path
            ));
        }

        let size = extract_json_u64_field(&item_str, "size").unwrap_or(0);
        let sha256_hex = extract_json_string_field(&item_str, "sha256").unwrap_or_default();
        let link_target = extract_json_string_field(&item_str, "link").unwrap_or_default();
        let mode = extract_json_u64_field(&item_str, "mode").unwrap_or(0o644) as u32;
        let mtime_sec = extract_json_i64_field(&item_str, "mtime_sec").unwrap_or(0);
        let mtime_nsec = extract_json_u64_field(&item_str, "mtime_nsec").unwrap_or(0) as u32;

        if entry_type == 'f' {
            calculated_bytes += size;
            if sha256_hex.len() != 64 {
                return Err(format!("Invalid SHA-256 hash length for file '{}'", path));
            }
        }

        entries.push(ManifestEntry {
            path,
            entry_type,
            size,
            sha256_hex,
            link_target,
            mode,
            mtime_sec,
            mtime_nsec,
        });
    }

    if entries.len() != total_entries {
        return Err(format!(
            "Manifest entry count mismatch: declared {}, parsed {}",
            total_entries,
            entries.len()
        ));
    }
    if calculated_bytes != total_bytes {
        return Err(format!(
            "Manifest byte count mismatch: declared {}, calculated {}",
            total_bytes, calculated_bytes
        ));
    }

    Ok(TransferManifest {
        version,
        transfer_id,
        timestamp_sec,
        total_entries,
        total_bytes,
        entries,
    })
}

// ------------------------------------------------------------------ Replay Protection

/// Replay cache storing seen transfer IDs within a sliding freshness window.
#[derive(Debug, Clone, Default)]
pub struct ReplayCache {
    pub seen_transfers: HashSet<String>,
    pub cache_file: Option<PathBuf>,
}

impl ReplayCache {
    pub fn new(cache_file: Option<PathBuf>) -> Self {
        let mut cache = Self {
            seen_transfers: HashSet::new(),
            cache_file,
        };
        cache.load_from_disk();
        cache
    }

    pub fn load_from_disk(&mut self) {
        if let Some(ref p) = self.cache_file {
            if let Ok(content) = fs::read_to_string(p) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        if let Some((id, _)) = trimmed.split_once(',') {
                            self.seen_transfers.insert(id.trim().to_string());
                        } else {
                            self.seen_transfers.insert(trimmed.to_string());
                        }
                    }
                }
            }
        }
    }

    pub fn save_to_disk(&self) {
        if let Some(ref p) = self.cache_file {
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let mut out = String::new();
            out.push_str("# sxfer replay cache\n");
            for id in &self.seen_transfers {
                out.push_str(id);
                out.push('\n');
            }
            let tmp = p.with_extension("tmp");
            if fs::write(&tmp, out).is_ok() {
                let _ = fs::rename(&tmp, p);
            }
        }
    }

    /// Verifies freshness and uniqueness of a transfer manifest.
    pub fn check_and_record(
        &mut self,
        transfer_id: &str,
        timestamp_sec: i64,
        max_skew_secs: i64,
    ) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Check clock skew freshness window
        let diff = (now - timestamp_sec).abs();
        if diff > max_skew_secs {
            return Err(format!(
                "Transfer timestamp outside acceptable freshness window (age: {}s, max permitted: {}s)",
                diff, max_skew_secs
            ));
        }

        // Check for replay
        if self.seen_transfers.contains(transfer_id) {
            return Err(format!(
                "Replayed transfer detected: transfer_id '{}' has already been accepted",
                transfer_id
            ));
        }

        self.seen_transfers.insert(transfer_id.to_string());
        self.save_to_disk();
        Ok(())
    }
}

// ------------------------------------------------------------------ Quarantine & Staging

/// Quarantine staging area for an authenticated transfer batch.
pub struct QuarantineBatch {
    pub transfer_id: String,
    pub staging_dir: PathBuf,
    pub manifest: Option<TransferManifest>,
    pub verified_paths: HashSet<String>,
}

impl QuarantineBatch {
    pub fn new(out_dir: &Path, transfer_id: &str) -> Result<Self, String> {
        let staging_dir = out_dir.join(format!(".sxfer_staging_{}", transfer_id));
        if staging_dir.exists() {
            let _ = fs::remove_dir_all(&staging_dir);
        }
        fs::create_dir_all(&staging_dir).map_err(|e| {
            format!(
                "Failed to create staging quarantine directory '{}': {}",
                staging_dir.display(),
                e
            )
        })?;

        Ok(Self {
            transfer_id: transfer_id.to_string(),
            staging_dir,
            manifest: None,
            verified_paths: HashSet::new(),
        })
    }

    /// Sets the validated transfer manifest for this batch.
    pub fn set_manifest(&mut self, manifest: TransferManifest) -> Result<(), String> {
        if manifest.transfer_id != self.transfer_id {
            return Err(format!(
                "Manifest transfer_id mismatch: expected '{}', got '{}'",
                self.transfer_id, manifest.transfer_id
            ));
        }
        self.manifest = Some(manifest);
        Ok(())
    }

    /// Verifies a received file in the staging directory against the manifest.
    pub fn verify_received_file(&mut self, rel_path: &str) -> Result<(), String> {
        let manifest = self.manifest.as_ref().ok_or_else(|| {
            "Cannot verify file: manifest not yet received or validated".to_string()
        })?;

        let entry = manifest
            .entries
            .iter()
            .find(|e| e.path == rel_path)
            .ok_or_else(|| {
                format!(
                    "Unauthenticated file '{}' received: not present in signed manifest",
                    rel_path
                )
            })?;

        let staged_file = self.staging_dir.join(rel_path);
        if !staged_file.exists() {
            return Err(format!(
                "Staged file '{}' does not exist",
                staged_file.display()
            ));
        }

        if entry.entry_type == 'f' {
            let actual_hash = compute_file_sha256_hex(&staged_file)?;
            if actual_hash != entry.sha256_hex {
                return Err(format!(
                    "SHA-256 hash mismatch on '{}': expected '{}', got '{}'",
                    rel_path, entry.sha256_hex, actual_hash
                ));
            }
            let meta = fs::metadata(&staged_file).map_err(|e| {
                format!(
                    "Failed to read metadata for '{}': {}",
                    staged_file.display(),
                    e
                )
            })?;
            if meta.len() != entry.size {
                return Err(format!(
                    "Size mismatch on '{}': expected {} bytes, got {} bytes",
                    rel_path,
                    entry.size,
                    meta.len()
                ));
            }
        }

        self.verified_paths.insert(rel_path.to_string());
        Ok(())
    }

    /// Checks whether all entries in the manifest have been verified.
    pub fn is_complete(&self) -> bool {
        if let Some(ref m) = self.manifest {
            m.entries
                .iter()
                .all(|e| self.verified_paths.contains(&e.path))
        } else {
            false
        }
    }

    /// Atomically publishes all staged items to the target output directory.
    pub fn commit_to_dest(&self, out_dir: &Path) -> Result<(), String> {
        if !self.is_complete() {
            return Err(
                "Cannot commit transfer: not all manifest entries have been verified".to_string(),
            );
        }

        let manifest = self.manifest.as_ref().unwrap();

        // 1. Create all directories first
        for entry in &manifest.entries {
            let dest_path = out_dir.join(&entry.path);
            if entry.entry_type == 'd' {
                fs::create_dir_all(&dest_path).map_err(|e| {
                    format!(
                        "Failed to create directory '{}': {}",
                        dest_path.display(),
                        e
                    )
                })?;
            } else if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!("Failed to create parent dir '{}': {}", parent.display(), e)
                })?;
            }
        }

        // 2. Move files and symlinks into place
        for entry in &manifest.entries {
            let staged_path = self.staging_dir.join(&entry.path);
            let dest_path = out_dir.join(&entry.path);

            if entry.entry_type == 'f' {
                // If destination exists, remove it first
                if dest_path.exists() {
                    let _ = fs::remove_file(&dest_path);
                }
                fs::rename(&staged_path, &dest_path).map_err(|e| {
                    format!(
                        "Failed to move '{}' to destination '{}': {}",
                        staged_path.display(),
                        dest_path.display(),
                        e
                    )
                })?;
            } else if entry.entry_type == 'l' {
                if dest_path.exists() {
                    let _ = fs::remove_file(&dest_path);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;
                    symlink(&entry.link_target, &dest_path).map_err(|e| {
                        format!(
                            "Failed to create symlink '{}' -> '{}': {}",
                            dest_path.display(),
                            entry.link_target,
                            e
                        )
                    })?;
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::symlink_file;
                    let _ = symlink_file(&entry.link_target, &dest_path);
                }
            }
        }

        // 3. Clean up staging directory
        let _ = fs::remove_dir_all(&self.staging_dir);
        Ok(())
    }

    /// Aborts the batch and purges all staged items.
    pub fn purge(&self) {
        let _ = fs::remove_dir_all(&self.staging_dir);
    }
}

// ------------------------------------------------------------------ Helpers

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hex_val = std::str::from_utf8(chunk).ok()?;
        let b = u8::from_str_radix(hex_val, 16).ok()?;
        bytes.push(b);
    }
    Some(bytes)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

fn extract_json_string_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", field);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let mut out = String::new();
    let mut escaped = false;
    for c in rest.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Some(out);
        } else {
            out.push(c);
        }
    }
    None
}

fn extract_json_u64_field(json: &str, field: &str) -> Option<u64> {
    let pattern = format!("\"{}\":", field);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse::<u64>().ok()
}

fn extract_json_i64_field(json: &str, field: &str) -> Option<i64> {
    let pattern = format!("\"{}\":", field);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..end].parse::<i64>().ok()
}

fn extract_json_object_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":", field);
    let start_idx = json.find(&pattern)? + pattern.len();
    let rest = json[start_idx..].trim_start();
    if !rest.starts_with('{') {
        return None;
    }
    let mut depth = 0;
    let mut in_str = false;
    let mut escaped = false;
    let mut end_idx = 0;

    for (i, c) in rest.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else {
            match c {
                '"' => in_str = true,
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    if depth == 0 && end_idx > 0 {
        Some(rest[..end_idx].to_string())
    } else {
        None
    }
}

fn extract_json_array_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":", field);
    let start_idx = json.find(&pattern)? + pattern.len();
    let rest = json[start_idx..].trim_start();
    if !rest.starts_with('[') {
        return None;
    }
    let mut depth = 0;
    let mut in_str = false;
    let mut escaped = false;
    let mut end_idx = 0;

    for (i, c) in rest.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else {
            match c {
                '"' => in_str = true,
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    if depth == 0 && end_idx > 0 {
        Some(rest[..end_idx].to_string())
    } else {
        None
    }
}

fn split_json_objects(array_str: &str) -> Vec<String> {
    let mut result = Vec::new();
    let trimmed = array_str.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return result;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut depth = 0;
    let mut in_str = false;
    let mut escaped = false;
    let mut start = None;

    for (i, c) in inner.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else {
            match c {
                '"' => in_str = true,
                '{' => {
                    if depth == 0 {
                        start = Some(i);
                    }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        if let Some(s) = start {
                            result.push(inner[s..=i].to_string());
                            start = None;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    result
}

// ------------------------------------------------------------------ Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sign_verify_roundtrip() {
        let (priv_pkcs8, pub_bytes) = generate_keypair().unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&priv_pkcs8).unwrap();

        let mut manifest = TransferManifest::new("11223344556677889900aabbccddeeff", 1700000000);
        manifest.add_entry(ManifestEntry {
            path: "test/doc.txt".to_string(),
            entry_type: 'f',
            size: 13,
            sha256_hex: compute_sha256_hex(b"Hello, World!"),
            link_target: String::new(),
            mode: 0o644,
            mtime_sec: 1700000000,
            mtime_nsec: 0,
        });

        let signed = manifest.sign(&key_pair);
        let envelope_json = signed.to_envelope_json();
        let parsed_signed = SignedManifest::parse(&envelope_json).unwrap();

        let verified_manifest = parsed_signed.verify(&pub_bytes).unwrap();
        assert_eq!(
            verified_manifest.transfer_id,
            "11223344556677889900aabbccddeeff"
        );
        assert_eq!(verified_manifest.entries.len(), 1);
        assert_eq!(verified_manifest.entries[0].path, "test/doc.txt");
        assert_eq!(verified_manifest.entries[0].size, 13);
    }

    #[test]
    fn test_signature_fails_with_wrong_public_key() {
        let (priv_pkcs8, _pub_bytes) = generate_keypair().unwrap();
        let (_other_priv, other_pub) = generate_keypair().unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&priv_pkcs8).unwrap();

        let manifest = TransferManifest::new("12345678123456781234567812345678", 1700000000);
        let signed = manifest.sign(&key_pair);

        let err = signed.verify(&other_pub).unwrap_err();
        assert!(err.contains("Public key mismatch"));
    }

    #[test]
    fn test_signature_fails_on_tampered_manifest() {
        let (priv_pkcs8, pub_bytes) = generate_keypair().unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&priv_pkcs8).unwrap();

        let mut manifest = TransferManifest::new("12345678123456781234567812345678", 1700000000);
        manifest.add_entry(ManifestEntry {
            path: "safe.txt".to_string(),
            entry_type: 'f',
            size: 4,
            sha256_hex: compute_sha256_hex(b"safe"),
            link_target: String::new(),
            mode: 0o644,
            mtime_sec: 1700000000,
            mtime_nsec: 0,
        });

        let mut signed = manifest.sign(&key_pair);
        // Tamper manifest content
        signed.manifest_json = signed.manifest_json.replace("safe.txt", "evil.txt");

        let err = signed.verify(&pub_bytes).unwrap_err();
        assert!(err.contains("verification failed"));
    }

    #[test]
    fn test_replay_protection() {
        let mut cache = ReplayCache::new(None);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let transfer_id = "test_transfer_001";

        // 1. Initial valid transfer
        assert!(cache.check_and_record(transfer_id, now, 300).is_ok());

        // 2. Replay of same transfer ID must be rejected
        let replay_err = cache.check_and_record(transfer_id, now, 300).unwrap_err();
        assert!(replay_err.contains("Replayed transfer detected"));

        // 3. Expired timestamp must be rejected
        let old_time = now - 1000;
        let stale_err = cache
            .check_and_record("fresh_id_002", old_time, 300)
            .unwrap_err();
        assert!(stale_err.contains("freshness window"));
    }
}
