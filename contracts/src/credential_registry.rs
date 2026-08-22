use crate::utils::storage::{EntityType, StorageUtils};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, String, Symbol, Vec};

/// Credential status enumeration
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CredentialStatus {
    Active = 0,
    Expired = 1,
    Revoked = 2,
    Pending = 3,
}

impl CredentialStatus {
    pub fn to_u8(&self) -> u8 {
        match self {
            CredentialStatus::Active => 0,
            CredentialStatus::Expired => 1,
            CredentialStatus::Revoked => 2,
            CredentialStatus::Pending => 3,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => CredentialStatus::Active,
            1 => CredentialStatus::Expired,
            2 => CredentialStatus::Revoked,
            3 => CredentialStatus::Pending,
            _ => CredentialStatus::Pending,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Revocation Types
// ═══════════════════════════════════════════════════════════════════

/// Reason codes for credential revocation — stored as u32 for gas efficiency.
/// (soroban-sdk 20.5.0 has no `u8` storage type.)
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationReason {
    AdministrativeError = 0,
    AcademicDishonesty = 1,
    DataCorrection = 2,
    VoluntarySurrender = 3,
    Other = 4,
}

impl RevocationReason {
    pub fn to_u8(&self) -> u8 {
        match self {
            RevocationReason::AdministrativeError => 0,
            RevocationReason::AcademicDishonesty => 1,
            RevocationReason::DataCorrection => 2,
            RevocationReason::VoluntarySurrender => 3,
            RevocationReason::Other => 4,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => RevocationReason::AdministrativeError,
            1 => RevocationReason::AcademicDishonesty,
            2 => RevocationReason::DataCorrection,
            3 => RevocationReason::VoluntarySurrender,
            _ => RevocationReason::Other,
        }
    }
}

/// Immutable revocation record, written once.
/// Uses u32 for reason code and u64 for timestamp to minimise storage cost.
#[contracttype]
#[derive(Clone)]
pub struct RegistryRevocationRecord {
    /// Unix timestamp packed as u64
    pub timestamp: u64,
    /// Reason packed as u32 (smallest unsigned int soroban supports in storage)
    pub reason_code: u32,
    /// Human-readable note — empty string means "no reason supplied".
    /// Callers must cap the note at 256 bytes.
    pub reason_str: String,
    /// Address that performed the revocation
    pub revoker: Address,
}

/// Revocation metadata surfaced by `verify_credential`.
///
/// Wrapped in a struct (rather than inline named fields on the enum variant)
/// because `#[contracttype]` enums in soroban-sdk 20.5.0 only support a single
/// unnamed field per variant.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationDetails {
    /// Reason packed as u32 (see `RevocationReason`)
    pub reason_code: u32,
    /// Unix timestamp of the revocation
    pub timestamp:   u64,
    /// Human-readable note — empty string means "no reason supplied"
    pub reason_str:  String,
}

/// Return type for `verify_credential` in the registry
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryVerificationResult {
    Valid,
    Expired,
    Revoked(u32, u64),
    Pending,
}

/// Enhanced credential with expiration support
#[contracttype]
#[derive(Clone)]
pub struct CredentialRegistry {
    pub id: u64,
    pub issuer: Address,
    pub recipient: Address,
    pub title: String,
    pub description: String,
    pub course_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub status: CredentialStatus,
    pub ipfs_hash: String,
    pub renewal_count: u32,
    pub last_renewed_at: Option<u64>,
}

/// Input for batch credential issuance
#[contracttype]
#[derive(Clone)]
pub struct BatchIssueInput {
    pub recipient: Address,
    pub title: String,
    pub description: String,
    pub course_id: String,
    pub ipfs_hash: String,
    pub validity_duration: u64,
}

/// Input for batch credential renewal
#[contracttype]
#[derive(Clone)]
pub struct BatchRenewInput {
    pub credential_id: u64,
    pub extension_duration: u64,
}

/// Result of a single operation within a batch
#[contracttype]
#[derive(Clone)]
pub struct BatchResult {
    /// The credential ID (0 if the operation failed before an ID was assigned)
    pub credential_id: u64,
    /// Whether this individual operation succeeded
    pub success: bool,
    /// Error message if the operation failed (empty string if success)
    pub error: String,
}

/// Batch operation storage key
#[contracttype]
pub enum BatchConfigKey {
    MaxBatchSize,
}

/// Credential registry storage keys
#[contracttype]
pub enum CredentialRegistryKey {
    Credential(u64),
    UserCredentials(Address),
    CredentialCount,
    ExpiredCredentials,
    RenewalHistory(u64),    // credential_id -> Vec<RenewalRecord>
    RevocationHistory(u64), // credential_id -> RegistryRevocationRecord
}

/// Renewal record for tracking credential renewals
#[contracttype]
#[derive(Clone)]
pub struct RenewalRecord {
    pub renewed_at: u64,
    pub old_expires_at: u64,
    pub new_expires_at: u64,
    pub renewed_by: Address,
}

/// Helper: linear scan for Vec<Address> containment.
/// soroban-sdk 20.5.0 Vec has no portable contains across element types.
fn contains_address(vec: &Vec<Address>, target: &Address) -> bool {
    for item in vec.iter() {
        if item == *target {
            return true;
        }
    }
    false
}

const DEFAULT_MAX_BATCH_SIZE: u32 = 100;

/// Events for credential operations
#[contracttype]
#[derive(Clone)]
pub enum CredentialEvent {
    Issued(u64),         // credential_id
    Expired(u64),        // credential_id
    Renewed(u64),        // credential_id
    Revoked(u64),        // credential_id
    StatusChanged(u64),  // credential_id
    ProofGenerated(u64), // credential_id — cross-chain proof generated
    ProofVerified(u64),  // credential_id — cross-chain proof verified
    ProofExpired(u64),   // credential_id — cross-chain proof expired
}

// ═══════════════════════════════════════════════════════════════
// Cross-Chain Credential Verification Relay
// ═══════════════════════════════════════════════════════════════

/// Cross-chain verification proof for relay to external chains.
/// Compact proof that external relayers can verify against on-chain state.
#[contracttype]
#[derive(Clone)]
pub struct CrossChainProof {
    pub credential_id: u64,
    pub issuer: Address,
    pub issued_at: u64,
    pub status: CredentialStatus,
    pub proof_timestamp: u64,
    pub expires_at: u64,
    /// SHA-256 hash of (credential_id || issued_at || status as u8 || issuer)
    /// for integrity verification by relayers
    pub proof_hash: BytesN<32>,
}

/// Storage keys for cross-chain relay
#[contracttype]
pub enum CrossChainRelayKey {
    Proof(u64),     // credential_id -> CrossChainProof
    ValidityWindow, // u64: seconds a proof remains valid
    ProofCount,     // u64: total proofs generated
}

/// Set the validity window for cross-chain proofs (admin only).
pub fn set_proof_validity_window(env: &Env, admin: Address, window_seconds: u64) {
    crate::pause::require_not_paused(env).unwrap();
    admin.require_auth();
    let stored_admin: Address = env
        .storage()
        .instance()
        .get(&Symbol::new(env, "admin"))
        .unwrap_or_else(|| panic!("Admin not found"));

    if admin != stored_admin {
        panic!("Only admin can set proof validity window");
    }
    if window_seconds == 0 {
        panic!("Validity window must be greater than zero");
    }

    env.storage()
        .instance()
        .set(&CrossChainRelayKey::ValidityWindow, &window_seconds);

    env.events().publish(
        (
            Symbol::new(env, "relay"),
            Symbol::new(env, "validity_window_updated"),
        ),
        window_seconds,
    );
}

/// Get the current proof validity window in seconds.
pub fn get_proof_validity_window(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&CrossChainRelayKey::ValidityWindow)
        .unwrap_or(3600) // Default: 1 hour
}

/// Generate a compact cross-chain verification proof for a credential.
///
/// The proof includes credential ID, issuance timestamp, revocation status,
/// issuer identity, and an integrity hash. The proof is timestamped and
/// expires after the configured validity window.
///
/// Emits a `ProofGenerated` event for off-chain relayers to detect new proofs.
pub fn generate_verification_proof(
    env: &Env,
    credential_id: u64,
    relayer: Address,
) -> CrossChainProof {
    relayer.require_auth();

    // Look up the credential
    let credential: CredentialRegistry = env
        .storage()
        .persistent()
        .get(&CredentialRegistryKey::Credential(credential_id))
        .unwrap_or_else(|| panic!("Credential not found"));

    // Get the validity window
    let validity_window: u64 = env
        .storage()
        .instance()
        .get(&CrossChainRelayKey::ValidityWindow)
        .unwrap_or(3600);

    let current_time = env.ledger().timestamp();

    // Build proof hash: SHA-256(credential_id || issued_at || status || issuer)
    let proof_hash = compute_proof_hash(
        env,
        credential_id,
        credential.issued_at,
        &credential.status,
        &credential.issuer,
    );

    let proof = CrossChainProof {
        credential_id,
        issuer: credential.issuer.clone(),
        issued_at: credential.issued_at,
        status: credential.status,
        proof_timestamp: current_time,
        expires_at: current_time + validity_window,
        proof_hash,
    };

    // Store the proof
    env.storage()
        .instance()
        .set(&CrossChainRelayKey::Proof(credential_id), &proof);

    // Update proof count
    let count: u64 = env
        .storage()
        .instance()
        .get(&CrossChainRelayKey::ProofCount)
        .unwrap_or(0);
    env.storage()
        .instance()
        .set(&CrossChainRelayKey::ProofCount, &(count + 1));

    // Emit cross-chain relay event for off-chain relayers
    env.events().publish(
        (
            Symbol::new(env, "relay"),
            Symbol::new(env, "proof_generated"),
        ),
        (proof.clone(), relayer),
    );

    proof
}

/// Verify a cross-chain proof against on-chain credential state.
///
/// Returns true if ALL of the following pass:
/// - Proof has not expired (proof_timestamp + validity_window > current_time)
/// - Credential exists in storage
/// - Credential is not revoked
/// - Proof hash matches recomputed hash (integrity check)
/// - Proof status matches credential's current status
pub fn verify_cross_chain_proof(env: &Env, proof: CrossChainProof) -> bool {
    let current_time = env.ledger().timestamp();

    // Check 1: Proof has not expired
    if current_time >= proof.expires_at {
        env.events().publish(
            (Symbol::new(env, "relay"), Symbol::new(env, "proof_expired")),
            (proof.credential_id, current_time),
        );
        return false;
    }

    // Check 2: Credential exists
    let credential: CredentialRegistry = match env
        .storage()
        .persistent()
        .get(&CredentialRegistryKey::Credential(proof.credential_id))
    {
        Some(c) => c,
        None => {
            env.events().publish(
                (
                    Symbol::new(env, "relay"),
                    Symbol::new(env, "credential_not_found"),
                ),
                proof.credential_id,
            );
            return false;
        }
    };

    // Check 3: Credential is not revoked
    if credential.status == CredentialStatus::Revoked {
        env.events().publish(
            (
                Symbol::new(env, "relay"),
                Symbol::new(env, "credential_revoked"),
            ),
            proof.credential_id,
        );
        return false;
    }

    // Check 4: Proof hash integrity — recompute and compare
    let computed_hash = compute_proof_hash(
        env,
        proof.credential_id,
        proof.issued_at,
        &proof.status,
        &proof.issuer,
    );
    if computed_hash != proof.proof_hash {
        env.events().publish(
            (
                Symbol::new(env, "relay"),
                Symbol::new(env, "proof_hash_mismatch"),
            ),
            proof.credential_id,
        );
        return false;
    }

    // Check 5: Proof status matches credential's actual current status
    if proof.status != credential.status {
        env.events().publish(
            (
                Symbol::new(env, "relay"),
                Symbol::new(env, "status_mismatch"),
            ),
            (
                proof.credential_id,
                proof.status.to_u8() as u64,
                credential.status.to_u8() as u64,
            ),
        );
        return false;
    }

    // All checks passed — proof is valid
    env.events().publish(
        (
            Symbol::new(env, "relay"),
            Symbol::new(env, "proof_verified"),
        ),
        (proof.credential_id, current_time),
    );

    true
}

/// Get a previously generated cross-chain proof by credential ID.
pub fn get_cross_chain_proof(env: &Env, credential_id: u64) -> CrossChainProof {
    env.storage()
        .instance()
        .get(&CrossChainRelayKey::Proof(credential_id))
        .unwrap_or_else(|| panic!("No cross-chain proof found for this credential"))
}

/// Get the total number of cross-chain proofs generated.
pub fn get_proof_count(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&CrossChainRelayKey::ProofCount)
        .unwrap_or(0)
}

/// Compute integrity hash for a cross-chain proof.
/// Hash = SHA-256(credential_id || issued_at || status || issuer)
fn compute_proof_hash(
    env: &Env,
    credential_id: u64,
    issued_at: u64,
    status: &CredentialStatus,
    issuer: &Address,
) -> BytesN<32> {
    let mut input = Bytes::new(env);
    // Append credential_id as 8 bytes (big-endian u64)
    let id_bytes = credential_id.to_be_bytes();
    for b in id_bytes.iter() {
        input.push_back(*b);
    }
    // Append issued_at as 8 bytes (big-endian u64)
    let ts_bytes = issued_at.to_be_bytes();
    for b in ts_bytes.iter() {
        input.push_back(*b);
    }
    // Append status as single byte (reuse existing to_u8)
    input.push_back(status.to_u8());
    // Append issuer address as raw bytes for deterministic hashing
    input.append(&issuer.to_xdr(env));
    env.crypto().sha256(&input)
}

/// Invalidate a cross-chain proof (e.g., when credential is revoked).
pub fn invalidate_cross_chain_proof(env: &Env, credential_id: u64) {
    crate::pause::require_not_paused(env).unwrap();
    if env
        .storage()
        .instance()
        .has(&CrossChainRelayKey::Proof(credential_id))
    {
        env.storage()
            .instance()
            .remove(&CrossChainRelayKey::Proof(credential_id));

        env.events().publish(
            (
                Symbol::new(env, "relay"),
                Symbol::new(env, "proof_invalidated"),
            ),
            credential_id,
        );
    }
}

/// Issue a new credential with expiration support
pub fn issue_credential_with_expiration(
    env: &Env,
    issuer: Address,
    recipient: Address,
    title: String,
    description: String,
    course_id: String,
    ipfs_hash: String,
    validity_duration: u64, // Duration in seconds from issuance
) -> u64 {
    crate::pause::require_not_paused(env).unwrap();
    issuer.require_auth();

    let admin: Address = env
        .storage()
        .instance()
        .get(&Symbol::new(env, "admin"))
        .unwrap_or_else(|| panic!("Admin not found"));

    if issuer != admin {
        panic!("Unauthorized issuer");
    }

    let credential_id = StorageUtils::get_next_id(env, EntityType::Credential);
    let current_time = env.ledger().timestamp();

    let credential = CredentialRegistry {
        id: credential_id,
        issuer: issuer.clone(),
        recipient: recipient.clone(),
        title,
        description,
        course_id,
        issued_at: current_time,
        expires_at: current_time + validity_duration,
        status: CredentialStatus::Active,
        ipfs_hash,
        renewal_count: 0,
        last_renewed_at: None,
    };

    // Store credential
    env.storage().persistent().set(
        &CredentialRegistryKey::Credential(credential_id),
        &credential,
    );

    // Add to user's credential list
    let mut user_creds = env
        .storage()
        .persistent()
        .get(&CredentialRegistryKey::UserCredentials(recipient.clone()))
        .unwrap_or_else(|| Vec::new(env));
    user_creds.push_back(credential_id);
    env.storage().persistent().set(
        &CredentialRegistryKey::UserCredentials(recipient),
        &user_creds,
    );

    // Update credential count
    env.storage()
        .instance()
        .set(&CredentialRegistryKey::CredentialCount, &credential_id);

    // Emit event
    env.events().publish(
        (Symbol::new(env, "credential"), Symbol::new(env, "issued")),
        (credential_id, issuer.clone()),
    );

    credential_id
}

/// Renew an existing credential
pub fn renew_credential(
    env: &Env,
    credential_id: u64,
    renewer: Address,
    extension_duration: u64,
) -> bool {
    crate::pause::require_not_paused(env).unwrap();
    renewer.require_auth();

    let mut credential: CredentialRegistry = env
        .storage()
        .persistent()
        .get(&CredentialRegistryKey::Credential(credential_id))
        .unwrap_or_else(|| panic!("Credential not found"));

    // Check if renewer is authorized (admin or credential recipient)
    let admin: Address = env
        .storage()
        .instance()
        .get(&Symbol::new(env, "admin"))
        .unwrap_or_else(|| panic!("Admin not found"));

    if renewer != admin && renewer != credential.recipient {
        panic!("Unauthorized to renew credential");
    }

    // Check if credential is eligible for renewal
    match credential.status {
        CredentialStatus::Revoked => {
            panic!("Cannot renew revoked credential");
        }
        CredentialStatus::Expired => {
            // Allow renewal of expired credentials
        }
        _ => {} // Active and Pending can be renewed
    }

    let current_time = env.ledger().timestamp();
    let old_expires_at = credential.expires_at;

    // Create renewal record
    let renewal_record = RenewalRecord {
        renewed_at: current_time,
        old_expires_at,
        new_expires_at: current_time + extension_duration,
        renewed_by: renewer.clone(),
    };

    // Store renewal history
    let mut renewal_history = env
        .storage()
        .instance()
        .get(&CredentialRegistryKey::RenewalHistory(credential_id))
        .unwrap_or_else(|| Vec::new(env));
    renewal_history.push_back(renewal_record.clone());
    env.storage().instance().set(
        &CredentialRegistryKey::RenewalHistory(credential_id),
        &renewal_history,
    );

    // Update credential
    credential.expires_at = current_time + extension_duration;
    credential.status = CredentialStatus::Active;
    credential.renewal_count += 1;
    credential.last_renewed_at = Some(current_time);

    env.storage().persistent().set(
        &CredentialRegistryKey::Credential(credential_id),
        &credential,
    );

    // Emit renewal event
    env.events().publish(
        (Symbol::new(env, "credential"), Symbol::new(env, "renewed")),
        (credential_id, renewer, extension_duration),
    );

    true
}

/// Check and update credential expiration status
pub fn check_credential_expiration(env: &Env, credential_id: u64) -> CredentialStatus {
    let mut credential: CredentialRegistry = env
        .storage()
        .persistent()
        .get(&CredentialRegistryKey::Credential(credential_id))
        .unwrap_or_else(|| panic!("Credential not found"));

    let current_time = env.ledger().timestamp();

    // Skip if already revoked
    if matches!(credential.status, CredentialStatus::Revoked) {
        return credential.status;
    }

    // Check if credential has expired
    if current_time >= credential.expires_at
        && matches!(credential.status, CredentialStatus::Active)
    {
        credential.status = CredentialStatus::Expired;

        // Update stored credential
        env.storage().persistent().set(
            &CredentialRegistryKey::Credential(credential_id),
            &credential,
        );

        // Add to expired credentials list
        let mut expired_creds = env
            .storage()
            .instance()
            .get(&CredentialRegistryKey::ExpiredCredentials)
            .unwrap_or_else(|| Vec::new(env));
        expired_creds.push_back(credential_id);
        env.storage()
            .instance()
            .set(&CredentialRegistryKey::ExpiredCredentials, &expired_creds);

        // Emit expiration event
        env.events().publish(
            (Symbol::new(env, "credential"), Symbol::new(env, "expired")),
            (credential_id, current_time),
        );
    }

    credential.status
}

/// Batch update expiration status for multiple credentials
pub fn batch_update_expiration_status(env: &Env, credential_ids: Vec<u64>) -> Vec<u64> {
    crate::pause::require_not_paused(env).unwrap();
    let mut expired_credentials = Vec::new(env);

    for credential_id in credential_ids.iter() {
        let status = check_credential_expiration(env, credential_id);
        if matches!(status, CredentialStatus::Expired) {
            expired_credentials.push_back(credential_id);
        }
    }

    expired_credentials
}

/// Get credential with current status
pub fn get_credential(env: &Env, credential_id: u64) -> CredentialRegistry {
    // Check expiration status before returning
    check_credential_expiration(env, credential_id);

    env.storage()
        .persistent()
        .get(&CredentialRegistryKey::Credential(credential_id))
        .unwrap_or_else(|| panic!("Credential not found"))
}

/// Get user credentials with current status
pub fn get_user_credentials(env: &Env, user: Address) -> Vec<u64> {
    env.storage()
        .persistent()
        .get(&CredentialRegistryKey::UserCredentials(user))
        .unwrap_or_else(|| Vec::new(env))
}

/// Get expired credentials list
pub fn get_expired_credentials(env: &Env) -> Vec<u64> {
    env.storage()
        .instance()
        .get(&CredentialRegistryKey::ExpiredCredentials)
        .unwrap_or_else(|| Vec::new(env))
}

/// Get renewal history for a credential
pub fn get_renewal_history(env: &Env, credential_id: u64) -> Vec<RenewalRecord> {
    env.storage()
        .instance()
        .get(&CredentialRegistryKey::RenewalHistory(credential_id))
        .unwrap_or_else(|| Vec::new(env))
}

/// Verify a credential in the registry — returns a `RegistryVerificationResult`.
pub fn verify_credential(env: &Env, credential_id: u64) -> RegistryVerificationResult {
    // Trigger lazy expiration check
    let status = check_credential_expiration(env, credential_id);

    match status {
        CredentialStatus::Revoked => {
            let record: RegistryRevocationRecord = env
                .storage()
                .persistent()
                .get(&CredentialRegistryKey::RevocationHistory(credential_id))
                .unwrap_or_else(|| panic!("Revocation record missing for revoked credential"));
            RegistryVerificationResult::Revoked(record.reason_code, record.timestamp)
        }
        CredentialStatus::Expired => RegistryVerificationResult::Expired,
        CredentialStatus::Pending => RegistryVerificationResult::Pending,
        CredentialStatus::Active => RegistryVerificationResult::Valid,
    }
}

/// Revoke a credential with a structured reason.
///
/// Only the **original issuer** or the **contract admin** may call this.
/// Revocation is **irreversible** — calling on an already-revoked credential panics.
///
/// # Emits
/// `CredentialRevoked` event: `(credential_id, revoker, reason_code u32, timestamp u64)`.
pub fn revoke_credential(
    env: &Env,
    credential_id: u64,
    revoker: Address,
    reason: RevocationReason,
    reason_str: Option<String>,
) -> bool {
    crate::pause::require_not_paused(env).unwrap();
    revoker.require_auth();

    let admin: Address = env
        .storage()
        .instance()
        .get(&Symbol::new(env, "admin"))
        .unwrap_or_else(|| panic!("Admin not found"));

    let mut credential: CredentialRegistry = env
        .storage()
        .persistent()
        .get(&CredentialRegistryKey::Credential(credential_id))
        .unwrap_or_else(|| panic!("Credential not found"));

    // Authorization: original issuer OR admin
    if revoker != credential.issuer && revoker != admin {
        panic!("Unauthorized: only the original issuer or admin can revoke credentials");
    }

    // Revocation is irreversible
    if credential.status == CredentialStatus::Revoked {
        panic!("AlreadyRevoked");
    }

    let revocation_time = env.ledger().timestamp();
    let reason_code = reason.to_u8() as u32;

    credential.status = CredentialStatus::Revoked;
    env.storage().persistent().set(
        &CredentialRegistryKey::Credential(credential_id),
        &credential,
    );

    // Write the full revocation record. An empty `String` denotes "no reason
    // supplied" because `#[contracttype]` cannot store `Option<String>`.
    let record = RegistryRevocationRecord {
        timestamp: revocation_time,
        reason_code,
        reason_str: reason_str.unwrap_or_else(|| String::from_str(env, "")),
        revoker: revoker.clone(),
    };
    env.storage().persistent().set(
        &CredentialRegistryKey::RevocationHistory(credential_id),
        &record,
    );

    // Emit CredentialRevoked event
    env.events().publish(
        (Symbol::new(env, "credential"), Symbol::new(env, "revoked")),
        (credential_id, revoker, reason_code as u64, revocation_time),
    );

    true
}

/// Return the `RegistryRevocationRecord` for a credential, or `None` if not revoked.
pub fn get_revocation_history(env: &Env, credential_id: u64) -> Option<RegistryRevocationRecord> {
    // Confirm credential exists first
    let _: CredentialRegistry = env
        .storage()
        .persistent()
        .get(&CredentialRegistryKey::Credential(credential_id))
        .unwrap_or_else(|| panic!("Credential not found"));

    env.storage()
        .persistent()
        .get(&CredentialRegistryKey::RevocationHistory(credential_id))
}

/// Get credential count
pub fn get_credential_count(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&CredentialRegistryKey::CredentialCount)
        .unwrap_or(0)
}

/// Check if a credential is currently valid
pub fn is_credential_valid(env: &Env, credential_id: u64) -> bool {
    let credential = get_credential(env, credential_id);
    matches!(credential.status, CredentialStatus::Active)
}

/// Get credentials expiring within a time window
pub fn get_credentials_expiring_soon(env: &Env, within_seconds: u64) -> Vec<u64> {
    let current_time = env.ledger().timestamp();
    let threshold = current_time + within_seconds;
    let mut expiring_soon = Vec::new(env);

    // This is a simplified implementation - in production, you'd want
    // an indexed storage structure for better performance
    let credential_count = get_credential_count(env);
    for i in 1..=credential_count {
        if let Some(credential) = env
            .storage()
            .persistent()
            .get::<_, CredentialRegistry>(&CredentialRegistryKey::Credential(i))
        {
            if credential.expires_at <= threshold
                && matches!(credential.status, CredentialStatus::Active)
            {
                expiring_soon.push_back(i);
            }
        }
    }

    expiring_soon
}

// ═══════════════════════════════════════════════════════════════════
//  Batch Credential Operations
// ═══════════════════════════════════════════════════════════════════



/// Get the current maximum batch size
pub fn get_max_batch_size(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&BatchConfigKey::MaxBatchSize)
        .unwrap_or(DEFAULT_MAX_BATCH_SIZE)
}

/// Set the maximum batch size (admin only)
pub fn set_max_batch_size(env: &Env, admin: Address, new_size: u32) {
    crate::pause::require_not_paused(env).unwrap();
    admin.require_auth();

    let stored_admin: Address = env
        .storage()
        .instance()
        .get(&Symbol::new(env, "admin"))
        .unwrap_or_else(|| panic!("Admin not found"));

    if admin != stored_admin {
        panic!("Only admin can configure batch size");
    }

    if new_size == 0 {
        panic!("Batch size must be greater than 0");
    }

    env.storage()
        .instance()
        .set(&BatchConfigKey::MaxBatchSize, &new_size);
}

/// Issue multiple credentials in a single transaction.
///
/// Each credential is processed individually: if one fails (e.g., invalid recipient),
/// it is skipped with an error recorded in the result, and the remaining credentials
/// continue to be processed. Individual events are emitted for each successful issue.
///
/// Returns a Vec<BatchResult> with one entry per input, in the same order.
pub fn batch_issue_credentials(
    env: &Env,
    issuer: Address,
    inputs: Vec<BatchIssueInput>,
) -> Vec<BatchResult> {
    crate::pause::require_not_paused(env).unwrap();
    issuer.require_auth();

    // Authorize once at the top
    let admin: Address = env
        .storage()
        .instance()
        .get(&Symbol::new(env, "admin"))
        .unwrap_or_else(|| panic!("Admin not found"));

    if issuer != admin {
        panic!("Unauthorized issuer");
    }

    let max_batch = get_max_batch_size(env);
    let input_count = inputs.len() as u32;
    if input_count > max_batch {
        panic!("Batch size {} exceeds maximum {}", input_count, max_batch);
    }

    let mut results = Vec::new(env);
    let current_time = env.ledger().timestamp();

    for i in 0..input_count {
        // Safety: i is always in bounds of inputs (0..inputs.len())
        let input = inputs.get(i).unwrap();

        // Basic validation
        if input.validity_duration == 0 {
            results.push_back(BatchResult {
                credential_id: 0,
                success: false,
                error: String::from_str(env, "validity_duration must be greater than 0"),
            });
            continue;
        }

        // Generate credential ID
        let credential_id = StorageUtils::get_next_id(env, EntityType::Credential);

        let credential = CredentialRegistry {
            id: credential_id,
            issuer: issuer.clone(),
            recipient: input.recipient.clone(),
            title: input.title.clone(),
            description: input.description.clone(),
            course_id: input.course_id.clone(),
            issued_at: current_time,
            expires_at: current_time + input.validity_duration,
            status: CredentialStatus::Active,
            ipfs_hash: input.ipfs_hash.clone(),
            renewal_count: 0,
            last_renewed_at: None,
        };

        // Store credential
        env.storage().persistent().set(
            &CredentialRegistryKey::Credential(credential_id),
            &credential,
        );

        // Add to user's credential list
        let mut user_creds = env
            .storage()
            .persistent()
            .get(&CredentialRegistryKey::UserCredentials(
                input.recipient.clone(),
            ))
            .unwrap_or_else(|| Vec::new(env));
        user_creds.push_back(credential_id);
        env.storage().persistent().set(
            &CredentialRegistryKey::UserCredentials(input.recipient.clone()),
            &user_creds,
        );

        // Update credential count
        env.storage()
            .instance()
            .set(&CredentialRegistryKey::CredentialCount, &credential_id);

        // Emit individual event for this credential
        env.events().publish(
            (
                Symbol::new(env, "credential"),
                Symbol::new(env, "batch_issued"),
            ),
            (credential_id, issuer.clone(), input.recipient.clone()),
        );

        results.push_back(BatchResult {
            credential_id,
            success: true,
            error: String::from_str(env, ""),
        });
    }

    results
}

/// Revoke multiple credentials in a single transaction.
///
/// Each credential is processed individually: if one cannot be found or is already
/// revoked, it is skipped with an error recorded, and the remaining credentials
/// continue to be processed. Individual events are emitted for each successful revocation.
pub fn batch_revoke_credentials(
    env: &Env,
    revoker: Address,
    credential_ids: Vec<u64>,
) -> Vec<BatchResult> {
    crate::pause::require_not_paused(env).unwrap();
    revoker.require_auth();

    let admin: Address = env
        .storage()
        .instance()
        .get(&Symbol::new(env, "admin"))
        .unwrap_or_else(|| panic!("Admin not found"));

    if revoker != admin {
        panic!("Only admin can revoke credentials");
    }

    let max_batch = get_max_batch_size(env);
    let count = credential_ids.len() as u32;
    if count > max_batch {
        panic!("Batch size {} exceeds maximum {}", count, max_batch);
    }

    let mut results = Vec::new(env);

    for i in 0..count {
        // Safety: i is always in bounds of credential_ids (0..credential_ids.len())
        let credential_id = credential_ids.get(i).unwrap();

        // Try to get the credential; skip if not found
        let credential_opt: Option<CredentialRegistry> = env
            .storage()
            .persistent()
            .get(&CredentialRegistryKey::Credential(credential_id));

        if credential_opt.is_none() {
            results.push_back(BatchResult {
                credential_id,
                success: false,
                error: String::from_str(env, "credential not found"),
            });
            continue;
        }

        let mut credential = credential_opt.unwrap();

        // Skip if already revoked
        if matches!(credential.status, CredentialStatus::Revoked) {
            results.push_back(BatchResult {
                credential_id,
                success: false,
                error: String::from_str(env, "credential already revoked"),
            });
            continue;
        }

        credential.status = CredentialStatus::Revoked;
        env.storage().persistent().set(
            &CredentialRegistryKey::Credential(credential_id),
            &credential,
        );

        // Emit individual revocation event
        env.events().publish(
            (
                Symbol::new(env, "credential"),
                Symbol::new(env, "batch_revoked"),
            ),
            (credential_id, revoker.clone()),
        );

        results.push_back(BatchResult {
            credential_id,
            success: true,
            error: String::from_str(env, ""),
        });
    }

    results
}

/// Renew multiple credentials in a single transaction.
///
/// Each credential is processed individually: if one cannot be renewed (e.g., not found,
/// revoked, or unauthorized), it is skipped with an error recorded, and the remaining
/// credentials continue to be processed. Individual events are emitted for each successful renewal.
pub fn batch_renew_credentials(
    env: &Env,
    renewer: Address,
    renewals: Vec<BatchRenewInput>,
) -> Vec<BatchResult> {
    crate::pause::require_not_paused(env).unwrap();
    renewer.require_auth();

    let admin: Address = env
        .storage()
        .instance()
        .get(&Symbol::new(env, "admin"))
        .unwrap_or_else(|| panic!("Admin not found"));

    let max_batch = get_max_batch_size(env);
    let count = renewals.len() as u32;
    if count > max_batch {
        panic!("Batch size {} exceeds maximum {}", count, max_batch);
    }

    let current_time = env.ledger().timestamp();
    let mut results = Vec::new(env);

    for i in 0..count {
        // Safety: i is always in bounds of renewals (0..renewals.len())
        let renewal = renewals.get(i).unwrap();

        let credential_id = renewal.credential_id;

        // Try to get the credential; skip if not found
        let credential_opt: Option<CredentialRegistry> = env
            .storage()
            .persistent()
            .get(&CredentialRegistryKey::Credential(credential_id));

        if credential_opt.is_none() {
            results.push_back(BatchResult {
                credential_id,
                success: false,
                error: String::from_str(env, "credential not found"),
            });
            continue;
        }

        let mut credential = credential_opt.unwrap();

        // Check authorization: admin or credential recipient
        if renewer != admin && renewer != credential.recipient {
            results.push_back(BatchResult {
                credential_id,
                success: false,
                error: String::from_str(env, "unauthorized to renew credential"),
            });
            continue;
        }

        // Check if credential is eligible for renewal
        if matches!(credential.status, CredentialStatus::Revoked) {
            results.push_back(BatchResult {
                credential_id,
                success: false,
                error: String::from_str(env, "cannot renew revoked credential"),
            });
            continue;
        }

        if renewal.extension_duration == 0 {
            results.push_back(BatchResult {
                credential_id,
                success: false,
                error: String::from_str(env, "extension_duration must be greater than 0"),
            });
            continue;
        }

        let old_expires_at = credential.expires_at;

        // Create renewal record
        let renewal_record = RenewalRecord {
            renewed_at: current_time,
            old_expires_at,
            new_expires_at: current_time + renewal.extension_duration,
            renewed_by: renewer.clone(),
        };

        // Store renewal history
        let mut renewal_history = env
            .storage()
            .instance()
            .get(&CredentialRegistryKey::RenewalHistory(credential_id))
            .unwrap_or_else(|| Vec::new(env));
        renewal_history.push_back(renewal_record.clone());
        env.storage().instance().set(
            &CredentialRegistryKey::RenewalHistory(credential_id),
            &renewal_history,
        );

        // Update credential
        credential.expires_at = current_time + renewal.extension_duration;
        credential.status = CredentialStatus::Active;
        credential.renewal_count += 1;
        credential.last_renewed_at = Some(current_time);

        env.storage().persistent().set(
            &CredentialRegistryKey::Credential(credential_id),
            &credential,
        );

        // Emit individual renewal event
        env.events().publish(
            (
                Symbol::new(env, "credential"),
                Symbol::new(env, "batch_renewed"),
            ),
            (credential_id, renewer.clone(), renewal.extension_duration),
        );

        results.push_back(BatchResult {
            credential_id,
            success: true,
            error: String::from_str(env, ""),
        });
    }

    results
}

// ═══════════════════════════════════════════════════════════════════
//  Multi-Signature Credential Registry Extension
// ═══════════════════════════════════════════════════════════════════

/// Multi-signature credential registry entry
#[contracttype]
#[derive(Clone)]
pub struct MultiSigCredentialRegistry {
    pub id: u64,
    pub threshold: u32,
    pub signers: Vec<Address>,
    pub recipient: Address,
    pub title: String,
    pub description: String,
    pub course_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub status: CredentialStatus,
    pub ipfs_hash: String,
    pub signature_count: u32,
    pub renewal_count: u32,
    pub last_renewed_at: Option<u64>,
}

/// Multi-signature credential registry storage keys
#[contracttype]
pub enum MultiSigRegistryKey {
    MultiSigCredential(u64),
    MultiSigSignatures(u64),
    MultiSigSignerSet(u64),
    MultiSigUserCredentials(Address),
    MultiSigCredentialCount,
    MultiSigRenewalHistory(u64),
}

/// Create a multi-signature credential in the registry
pub fn create_multi_sig_credential(
    env: &Env,
    issuer: Address,
    signers: Vec<Address>,
    threshold: u32,
    recipient: Address,
    title: String,
    description: String,
    course_id: String,
    ipfs_hash: String,
    validity_duration: u64,
) -> u64 {
    crate::pause::require_not_paused(env).unwrap();
    issuer.require_auth();

    let admin: Address = env
        .storage()
        .instance()
        .get(&Symbol::new(env, "admin"))
        .unwrap_or_else(|| panic!("Admin not found"));

    if issuer != admin {
        panic!("Unauthorized issuer");
    }

    let signer_count = signers.len() as u32;
    if signer_count == 0 {
        panic!("Signer list cannot be empty");
    }
    if threshold == 0 || threshold > signer_count {
        panic!("Threshold must be between 1 and the number of signers");
    }

    let credential_id = StorageUtils::get_next_id(env, EntityType::Credential);
    let current_time = env.ledger().timestamp();

    let credential = MultiSigCredentialRegistry {
        id: credential_id,
        threshold,
        signers: signers.clone(),
        recipient: recipient.clone(),
        title,
        description,
        course_id,
        issued_at: current_time,
        expires_at: current_time + validity_duration,
        status: CredentialStatus::Pending,
        ipfs_hash,
        signature_count: 0,
        renewal_count: 0,
        last_renewed_at: None,
    };

    // Store credential in persistent storage
    env.storage().persistent().set(
        &MultiSigRegistryKey::MultiSigCredential(credential_id),
        &credential,
    );

    // Initialize empty signatures
    let empty_sigs: Vec<Address> = Vec::new(env);
    env.storage().persistent().set(
        &MultiSigRegistryKey::MultiSigSignatures(credential_id),
        &empty_sigs,
    );

    // Store authorized signer set for quick lookup
    env.storage().persistent().set(
        &MultiSigRegistryKey::MultiSigSignerSet(credential_id),
        &signers,
    );

    // Add to user's multi-sig credential list
    let mut user_creds = env
        .storage()
        .persistent()
        .get(&MultiSigRegistryKey::MultiSigUserCredentials(
            recipient.clone(),
        ))
        .unwrap_or_else(|| Vec::new(env));
    user_creds.push_back(credential_id);
    env.storage().persistent().set(
        &MultiSigRegistryKey::MultiSigUserCredentials(recipient),
        &user_creds,
    );

    // Update credential count
    env.storage().instance().set(
        &MultiSigRegistryKey::MultiSigCredentialCount,
        &credential_id,
    );

    // Emit event
    env.events().publish(
        (
            Symbol::new(env, "multi_sig_registry"),
            Symbol::new(env, "created"),
        ),
        (credential_id, threshold, signer_count),
    );

    credential_id
}

/// Add a signature to a multi-signature credential in the registry
pub fn add_multi_sig_signature(env: &Env, credential_id: u64, signer: Address) -> CredentialStatus {
    crate::pause::require_not_paused(env).unwrap();
    signer.require_auth();

    let mut credential: MultiSigCredentialRegistry = env
        .storage()
        .persistent()
        .get(&MultiSigRegistryKey::MultiSigCredential(credential_id))
        .unwrap_or_else(|| panic!("Multi-sig credential not found"));

    // Reject if already active or revoked
    match credential.status {
        CredentialStatus::Revoked => panic!("Credential is revoked"),
        CredentialStatus::Expired => panic!("Credential is expired"),
        CredentialStatus::Active => panic!("Credential is already active"),
        CredentialStatus::Pending => {} // OK to sign
    }

    // Verify signer is in the authorized set
    let signer_set: Vec<Address> = env
        .storage()
        .persistent()
        .get(&MultiSigRegistryKey::MultiSigSignerSet(credential_id))
        .unwrap_or_else(|| panic!("Signer set not found"));

    if !contains_address(&signer_set, &signer) {
        panic!("Signer is not authorized for this credential");
    }

    // Load signatures and check for duplicates
    let mut signatures: Vec<Address> = env
        .storage()
        .persistent()
        .get(&MultiSigRegistryKey::MultiSigSignatures(credential_id))
        .unwrap_or_else(|| Vec::new(env));

    if contains_address(&signatures, &signer) {
        panic!("Signer has already signed this credential");
    }

    // Add signature
    signatures.push_back(signer.clone());
    env.storage().persistent().set(
        &MultiSigRegistryKey::MultiSigSignatures(credential_id),
        &signatures,
    );

    credential.signature_count = signatures.len() as u32;

    // Emit signature event
    env.events().publish(
        (
            Symbol::new(env, "multi_sig_registry"),
            Symbol::new(env, "signed"),
        ),
        (credential_id, signer.clone()),
    );

    // Check threshold
    if credential.signature_count >= credential.threshold {
        credential.status = CredentialStatus::Active;
        env.storage().persistent().set(
            &MultiSigRegistryKey::MultiSigCredential(credential_id),
            &credential,
        );

        // Emit activation event
        env.events().publish(
            (
                Symbol::new(env, "multi_sig_registry"),
                Symbol::new(env, "activated"),
            ),
            (credential_id,),
        );

        return CredentialStatus::Active;
    }

    // Store updated credential with new signature count
    env.storage().persistent().set(
        &MultiSigRegistryKey::MultiSigCredential(credential_id),
        &credential,
    );

    CredentialStatus::Pending
}

/// Get a multi-sig credential from the registry
pub fn get_multi_sig_credential(env: &Env, credential_id: u64) -> MultiSigCredentialRegistry {
    env.storage()
        .persistent()
        .get(&MultiSigRegistryKey::MultiSigCredential(credential_id))
        .unwrap_or_else(|| panic!("Multi-sig credential not found"))
}

/// Get signatures for a multi-sig credential
pub fn get_multi_sig_signatures(env: &Env, credential_id: u64) -> Vec<Address> {
    env.storage()
        .persistent()
        .get(&MultiSigRegistryKey::MultiSigSignatures(credential_id))
        .unwrap_or_else(|| Vec::new(env))
}

/// Get the authorized signer set for a multi-sig credential
pub fn get_multi_sig_signer_set(env: &Env, credential_id: u64) -> Vec<Address> {
    env.storage()
        .persistent()
        .get(&MultiSigRegistryKey::MultiSigSignerSet(credential_id))
        .unwrap_or_else(|| Vec::new(env))
}

/// Check if credential threshold has been met
pub fn is_multi_sig_active(env: &Env, credential_id: u64) -> bool {
    let credential: MultiSigCredentialRegistry = env
        .storage()
        .persistent()
        .get(&MultiSigRegistryKey::MultiSigCredential(credential_id))
        .unwrap_or_else(|| panic!("Multi-sig credential not found"));

    matches!(credential.status, CredentialStatus::Active)
}

/// Get multi-sig credential count
pub fn get_multi_sig_credential_count(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&MultiSigRegistryKey::MultiSigCredentialCount)
        .unwrap_or(0)
}

/// Revoke a multi-sig credential with a structured reason.
pub fn revoke_multi_sig_credential(
    env: &Env,
    credential_id: u64,
    revoker: Address,
    reason: RevocationReason,
    _reason_str: Option<String>,
) -> bool {
    crate::pause::require_not_paused(env).unwrap();
    revoker.require_auth();

    let admin: Address = env
        .storage()
        .instance()
        .get(&Symbol::new(env, "admin"))
        .unwrap_or_else(|| panic!("Admin not found"));

    if revoker != admin {
        panic!("Only admin can revoke multi-sig credentials");
    }

    let mut credential: MultiSigCredentialRegistry = env
        .storage()
        .persistent()
        .get(&MultiSigRegistryKey::MultiSigCredential(credential_id))
        .unwrap_or_else(|| panic!("Multi-sig credential not found"));

    if credential.status == CredentialStatus::Revoked {
        panic!("AlreadyRevoked");
    }

    let revocation_time = env.ledger().timestamp();
    let reason_code = reason.to_u8() as u32;

    credential.status = CredentialStatus::Revoked;
    env.storage().persistent().set(
        &MultiSigRegistryKey::MultiSigCredential(credential_id),
        &credential,
    );

    env.events().publish(
        (
            Symbol::new(env, "multi_sig_registry"),
            Symbol::new(env, "revoked"),
        ),
        (credential_id, revoker, reason_code as u64, revocation_time),
    );

    true
}
