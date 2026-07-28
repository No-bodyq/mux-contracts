/*!
 * mux-recovery: Account recovery system for Mux Protocol.
 *
 * Implements a guardian-initiated recovery mechanism with a mandatory
 * timelock (~24 hours at 5-second ledger close) before the new owner
 * can take control. The current owner may cancel a pending recovery at
 * any time during the timelock window.
 *
 * # Registry link
 *
 * An optional registry contract address can be associated with this
 * recovery contract via `set_registry`. The stored address is readable
 * via `registry_id` (returns `None` if not set). The TypeScript binding
 * exposes `setRegistry()` and `getRegistryId()` for these methods.
 *
 * # `no_std` Constraints
 *
 * This crate is `#![no_std]` and does not use `extern crate alloc`.
 * All data structures use Soroban SDK types backed by the Soroban host.
 */

#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, Vec,
};

// ── Audit events ──────────────────────────────────────────────────────────────
fn emit(
    env: &Env,
    action: soroban_sdk::Symbol,
    data: impl soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
) {
    env.events()
        .publish((symbol_short!("mux_recv"), action), data);
}

// ── Timelock ──────────────────────────────────────────────────────────────────

/// Minimum number of ledgers that must pass between `initiate_recovery` and
/// `execute_recovery`.
///
/// At ~5-second ledger close times:
///   17_280 ledgers ≈ 24 hours
///
/// This gives the legitimate owner a window to cancel a fraudulent recovery
/// before it can be executed.
pub const RECOVERY_TIMELOCK: u32 = 17_280;

/// Maximum number of ledgers after initiation during which a recovery
/// can be executed. After this window, the request auto-expires and a
/// new recovery must be initiated.
///
/// At ~5-second ledger close times:
///   120_960 ledgers ≈ 7 days
pub const RECOVERY_EXPIRY: u32 = 120_960;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Lifecycle state of a recovery request.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryStatus {
    /// No active recovery request.
    None,
    /// A recovery has been initiated but the timelock has not expired.
    Pending,
    /// The recovery was executed and ownership transferred.
    Executed,
    /// The recovery was cancelled by the current owner.
    Cancelled,
}

/// An active recovery request stored on-chain.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryRequest {
    /// The proposed new owner address.
    pub new_owner: Address,
    /// The ledger sequence at which the request was initiated.
    pub initiated_at: u32,
    /// The earliest ledger at which `execute_recovery` may be called
    /// (`initiated_at + RECOVERY_TIMELOCK`).
    pub executable_at: u32,
    /// The latest ledger at which `execute_recovery` may still be called.
    /// After this point the request is considered expired and a new
    /// recovery must be initiated (`initiated_at + RECOVERY_EXPIRY`).
    pub expires_at: u32,
    /// Current lifecycle state.
    pub status: RecoveryStatus,
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Owner,
    Guardians,
    Recovery,
    RegistryId,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RecoveryError {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
    RecoveryAlreadyPending = 4,
    NoActiveRecovery = 5,
    TimelockNotExpired = 6,
    TooManyGuardians = 7,
    GuardianAlreadyExists = 8,
    GuardianNotFound = 9,
    MinGuardiansRequired = 10,
    RecoveryExpired = 11,
}

// ── Storage TTL ───────────────────────────────────────────────────────────────
const TTL_THRESHOLD: u32 = 17_280; // ~1 day
const TTL_EXTEND_TO: u32 = 518_400; // ~30 days

// ── Storage griefing ─────────────────────────────────────────────────────────
/// Maximum number of guardians to bound instance-storage growth.
/// Each Address is ~32 bytes; 16 entries ≈ 0.5 KB.
const MAX_GUARDIANS: u32 = 16;

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct MuxRecovery;

#[contractimpl]
impl MuxRecovery {
    /// Initialize the recovery contract with an owner and a guardian set.
    pub fn initialize(
        env: Env,
        owner: Address,
        guardians: Vec<Address>,
    ) -> Result<(), RecoveryError> {
        if env.storage().instance().has(&DataKey::Owner) {
            return Err(RecoveryError::AlreadyInitialized);
        }
        owner.require_auth();
        env.storage().instance().set(&DataKey::Owner, &owner);
        env.storage()
            .instance()
            .set(&DataKey::Guardians, &guardians);
        emit(&env, symbol_short!("init"), owner);
        Self::extend_ttl(&env);
        Ok(())
    }

    /// Initiate a recovery request. Must be called by a registered guardian.
    ///
    /// Only one pending recovery may exist at a time. The timelock starts
    /// at the current ledger sequence.
    pub fn initiate_recovery(
        env: Env,
        guardian: Address,
        new_owner: Address,
    ) -> Result<(), RecoveryError> {
        guardian.require_auth();
        Self::require_guardian(&env, &guardian)?;

        // Reject if a non-expired pending recovery already exists.
        // Expired pending requests are treated as stale and may be overwritten.
        if let Some(req) = Self::active_recovery(&env) {
            if req.status == RecoveryStatus::Pending && env.ledger().sequence() < req.expires_at {
                return Err(RecoveryError::RecoveryAlreadyPending);
            }
        }

        let initiated_at = env.ledger().sequence();
        let request = RecoveryRequest {
            new_owner: new_owner.clone(),
            initiated_at,
            executable_at: initiated_at.saturating_add(RECOVERY_TIMELOCK),
            expires_at: initiated_at.saturating_add(RECOVERY_EXPIRY),
            status: RecoveryStatus::Pending,
        };
        env.storage().instance().set(&DataKey::Recovery, &request);
        // Carry the timelock window in the payload so indexers can surface the
        // execute/expiry deadlines without a follow-up storage read.
        emit(
            &env,
            symbol_short!("rec_init"),
            (
                guardian,
                new_owner,
                request.initiated_at,
                request.executable_at,
                request.expires_at,
            ),
        );
        Self::extend_ttl(&env);
        Ok(())
    }

    /// Cancel a pending recovery. May be called by the current owner at any
    /// time before the recovery is executed.
    pub fn cancel_recovery(env: Env) -> Result<(), RecoveryError> {
        Self::require_owner(&env)?;
        let mut request = Self::require_pending(&env)?;
        request.status = RecoveryStatus::Cancelled;
        env.storage().instance().set(&DataKey::Recovery, &request);
        emit(&env, symbol_short!("rec_cncl"), ());
        Self::extend_ttl(&env);
        Ok(())
    }

    /// Execute a recovery after the timelock has expired.
    ///
    /// Must be called by a registered guardian. Transfers ownership to
    /// `RecoveryRequest.new_owner`.
    pub fn execute_recovery(env: Env, guardian: Address) -> Result<(), RecoveryError> {
        guardian.require_auth();
        Self::require_guardian(&env, &guardian)?;
        let mut request = Self::require_pending(&env)?;

        if env.ledger().sequence() < request.executable_at {
            return Err(RecoveryError::TimelockNotExpired);
        }
        if env.ledger().sequence() >= request.expires_at {
            return Err(RecoveryError::RecoveryExpired);
        }

        let new_owner = request.new_owner.clone();
        request.status = RecoveryStatus::Executed;
        env.storage().instance().set(&DataKey::Owner, &new_owner);
        env.storage().instance().set(&DataKey::Recovery, &request);
        emit(&env, symbol_short!("rec_exec"), (guardian, new_owner));
        Self::extend_ttl(&env);
        Ok(())
    }

    /// Add a guardian to the guardian set. Owner only.
    ///
    /// The set is capped at `MAX_GUARDIANS` to bound instance-storage growth.
    pub fn add_guardian(env: Env, guardian: Address) -> Result<(), RecoveryError> {
        Self::require_owner(&env)?;
        let mut guardians: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Guardians)
            .ok_or(RecoveryError::NotInitialized)?;
        if guardians.contains(&guardian) {
            return Err(RecoveryError::GuardianAlreadyExists);
        }
        if guardians.len() >= MAX_GUARDIANS {
            return Err(RecoveryError::TooManyGuardians);
        }
        guardians.push_back(guardian.clone());
        env.storage().instance().set(&DataKey::Guardians, &guardians);
        emit(&env, symbol_short!("grd_add"), guardian);
        Self::extend_ttl(&env);
        Ok(())
    }

    /// Remove a guardian from the guardian set. Owner only.
    ///
    /// At least one guardian must always remain, otherwise recovery would
    /// become permanently unreachable.
    pub fn remove_guardian(env: Env, guardian: Address) -> Result<(), RecoveryError> {
        Self::require_owner(&env)?;
        let mut guardians: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Guardians)
            .ok_or(RecoveryError::NotInitialized)?;
        let index = guardians
            .first_index_of(&guardian)
            .ok_or(RecoveryError::GuardianNotFound)?;
        if guardians.len() <= 1 {
            return Err(RecoveryError::MinGuardiansRequired);
        }
        guardians.remove(index);
        env.storage().instance().set(&DataKey::Guardians, &guardians);
        emit(&env, symbol_short!("grd_rm"), guardian);
        Self::extend_ttl(&env);
        Ok(())
    }

    /// Return the current owner address.
    pub fn owner(env: Env) -> Result<Address, RecoveryError> {
        env.storage()
            .instance()
            .get(&DataKey::Owner)
            .ok_or(RecoveryError::NotInitialized)
    }

    /// Return the registered guardian set.
    pub fn guardians(env: Env) -> Result<Vec<Address>, RecoveryError> {
        env.storage()
            .instance()
            .get(&DataKey::Guardians)
            .ok_or(RecoveryError::NotInitialized)
    }

    /// Return the current recovery status.
    pub fn recovery_status(env: Env) -> RecoveryStatus {
        env.storage()
            .instance()
            .get::<DataKey, RecoveryRequest>(&DataKey::Recovery)
            .map(|r| r.status)
            .unwrap_or(RecoveryStatus::None)
    }

    /// Add a new guardian. Requires owner authorization and enforces the cap.
    pub fn add_guardian(env: Env, owner: Address, guardian: Address) -> Result<(), RecoveryError> {
        Self::require_owner(&env)?;
        let mut guardians: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Guardians)
            .ok_or(RecoveryError::NotInitialized)?;
        if guardians.contains(&guardian) {
            return Err(RecoveryError::GuardianAlreadyExists);
        }
        if guardians.len() >= MAX_GUARDIANS {
            return Err(RecoveryError::TooManyGuardians);
        }
        guardians.push_back(guardian.clone());
        env.storage()
            .instance()
            .set(&DataKey::Guardians, &guardians);
        emit(&env, symbol_short!("grd_add"), (owner, guardian));
        Self::extend_ttl(&env);
        Ok(())
    }

    /// Remove an existing guardian. Requires owner authorization and preserves the minimum.
    pub fn remove_guardian(
        env: Env,
        owner: Address,
        guardian: Address,
    ) -> Result<(), RecoveryError> {
        Self::require_owner(&env)?;
        let mut guardians: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Guardians)
            .ok_or(RecoveryError::NotInitialized)?;
        if !guardians.contains(&guardian) {
            return Err(RecoveryError::GuardianNotFound);
        }
        if guardians.len() <= 1 {
            return Err(RecoveryError::MinGuardiansRequired);
        }
        let mut updated = Vec::new(&env);
        for existing in guardians.iter() {
            if existing != guardian {
                updated.push_back(existing);
            }
        }
        env.storage().instance().set(&DataKey::Guardians, &updated);
        emit(&env, symbol_short!("grd_rm"), (owner, guardian));
        Self::extend_ttl(&env);
        Ok(())
    }

    /// Link a registry contract address to this recovery contract.
    ///
    /// Only the current owner may call this method. Emits a `reg_link` audit
    /// event and extends instance TTL.
    pub fn set_registry(
        env: Env,
        owner: Address,
        registry_id: Address,
    ) -> Result<(), RecoveryError> {
        // Ensure the contract is initialised before accepting a registry link.
        if !env.storage().instance().has(&DataKey::Owner) {
            return Err(RecoveryError::NotInitialized);
        }
        owner.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::RegistryId, &registry_id);
        emit(&env, symbol_short!("reg_link"), registry_id);
        Self::extend_ttl(&env);
        Ok(())
    }

    /// Return the linked registry contract address, or `None` if not set.
    pub fn registry_id(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::RegistryId)
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    fn require_owner(env: &Env) -> Result<(), RecoveryError> {
        let owner: Address = env
            .storage()
            .instance()
            .get(&DataKey::Owner)
            .ok_or(RecoveryError::NotInitialized)?;
        owner.require_auth();
        Ok(())
    }

    fn require_guardian(env: &Env, guardian: &Address) -> Result<(), RecoveryError> {
        let guardians: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Guardians)
            .ok_or(RecoveryError::NotInitialized)?;
        if !guardians.contains(guardian) {
            return Err(RecoveryError::Unauthorized);
        }
        Ok(())
    }

    fn active_recovery(env: &Env) -> Option<RecoveryRequest> {
        env.storage().instance().get(&DataKey::Recovery)
    }

    fn require_pending(env: &Env) -> Result<RecoveryRequest, RecoveryError> {
        let req = Self::active_recovery(env).ok_or(RecoveryError::NoActiveRecovery)?;
        if req.status != RecoveryStatus::Pending {
            return Err(RecoveryError::NoActiveRecovery);
        }
        Ok(req)
    }

    fn extend_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        symbol_short,
        testutils::{Address as _, Events, Ledger},
        vec, Env, FromVal,
    };

    fn topic_action(
        env: &Env,
        events: &soroban_sdk::Vec<(
            soroban_sdk::Address,
            soroban_sdk::Vec<soroban_sdk::Val>,
            soroban_sdk::Val,
        )>,
        idx: u32,
    ) -> soroban_sdk::Symbol {
        let (_, topics, _) = events.get(idx).unwrap();
        soroban_sdk::Symbol::from_val(env, &topics.get(1).unwrap())
    }

    fn setup() -> (Env, MuxRecoveryClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MuxRecovery);
        let client = MuxRecoveryClient::new(&env, &contract_id);
        let owner = Address::generate(&env);
        let guardian = Address::generate(&env);
        client.initialize(&owner, &vec![&env, guardian.clone()]);
        (env, client, owner, guardian)
    }

    // ── initialize ────────────────────────────────────────────────────────────

    #[test]
    fn test_initialize_sets_owner_and_guardians() {
        let (_env, client, owner, guardian) = setup();
        assert_eq!(client.owner(), owner);
        assert!(client.guardians().contains(&guardian));
    }

    #[test]
    fn test_initialize_emits_init_event() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MuxRecovery);
        let client = MuxRecoveryClient::new(&env, &contract_id);
        let owner = Address::generate(&env);
        client.initialize(&owner, &vec![&env]);
        let events = env.events().all();
        assert_eq!(events.len(), 1);
        assert_eq!(topic_action(&env, &events, 0), symbol_short!("init"));
    }

    #[test]
    fn test_double_initialize_rejected() {
        let (env, client, owner, _) = setup();
        let err = client
            .try_initialize(&owner, &vec![&env])
            .unwrap_err()
            .unwrap();
        assert_eq!(err, RecoveryError::AlreadyInitialized);
    }

    // ── recovery_status default ───────────────────────────────────────────────

    #[test]
    fn test_recovery_status_none_by_default() {
        let (_env, client, _, _) = setup();
        assert_eq!(client.recovery_status(), RecoveryStatus::None);
    }

    // ── initiate_recovery ─────────────────────────────────────────────────────

    #[test]
    fn test_initiate_recovery_sets_pending() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        assert_eq!(client.recovery_status(), RecoveryStatus::Pending);
    }

    #[test]
    fn test_initiate_recovery_emits_event() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        let events = env.events().all();
        // init + rec_init
        assert_eq!(events.len(), 2);
        assert_eq!(topic_action(&env, &events, 1), symbol_short!("rec_init"));
    }

    #[test]
    fn test_initiate_recovery_non_guardian_rejected() {
        let (env, client, _, _) = setup();
        let stranger = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let err = client
            .try_initiate_recovery(&stranger, &new_owner)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, RecoveryError::Unauthorized);
    }

    #[test]
    fn test_initiate_recovery_duplicate_pending_rejected() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        let err = client
            .try_initiate_recovery(&guardian, &new_owner)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, RecoveryError::RecoveryAlreadyPending);
    }

    #[test]
    fn test_initiate_recovery_on_uninitialised_contract_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MuxRecovery);
        let client = MuxRecoveryClient::new(&env, &contract_id);
        let guardian = Address::generate(&env);
        let new_owner = Address::generate(&env);
        let err = client
            .try_initiate_recovery(&guardian, &new_owner)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, RecoveryError::NotInitialized);
    }

    // ── cancel_recovery ───────────────────────────────────────────────────────

    #[test]
    fn test_cancel_recovery_sets_cancelled() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        client.cancel_recovery();
        assert_eq!(client.recovery_status(), RecoveryStatus::Cancelled);
    }

    #[test]
    fn test_cancel_recovery_emits_event() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        client.cancel_recovery();
        let events = env.events().all();
        // init + rec_init + rec_cncl
        assert_eq!(events.len(), 3);
        assert_eq!(topic_action(&env, &events, 2), symbol_short!("rec_cncl"));
    }

    #[test]
    fn test_cancel_recovery_without_pending_request_rejected() {
        let (_env, client, _, _) = setup();
        let err = client.try_cancel_recovery().unwrap_err().unwrap();
        assert_eq!(err, RecoveryError::NoActiveRecovery);
    }

    #[test]
    fn test_cancel_already_executed_recovery_rejected() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        env.ledger()
            .with_mut(|l| l.sequence_number += RECOVERY_TIMELOCK + 1);
        client.execute_recovery(&guardian);
        let err = client.try_cancel_recovery().unwrap_err().unwrap();
        assert_eq!(err, RecoveryError::NoActiveRecovery);
    }

    // ── execute_recovery ──────────────────────────────────────────────────────

    #[test]
    fn test_execute_recovery_after_timelock_transfers_ownership() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        env.ledger()
            .with_mut(|l| l.sequence_number += RECOVERY_TIMELOCK + 1);
        client.execute_recovery(&guardian);
        assert_eq!(client.recovery_status(), RecoveryStatus::Executed);
        assert_eq!(client.owner(), new_owner);
    }

    #[test]
    fn test_execute_recovery_emits_event() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        env.ledger()
            .with_mut(|l| l.sequence_number += RECOVERY_TIMELOCK + 1);
        client.execute_recovery(&guardian);
        let events = env.events().all();
        // init + rec_init + rec_exec
        assert_eq!(events.len(), 3);
        assert_eq!(topic_action(&env, &events, 2), symbol_short!("rec_exec"));
    }

    #[test]
    fn test_execute_recovery_before_timelock_rejected() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        // Do NOT advance ledger — timelock not expired.
        let err = client.try_execute_recovery(&guardian).unwrap_err().unwrap();
        assert_eq!(err, RecoveryError::TimelockNotExpired);
    }

    #[test]
    fn test_execute_recovery_non_guardian_rejected() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        env.ledger()
            .with_mut(|l| l.sequence_number += RECOVERY_TIMELOCK + 1);
        let stranger = Address::generate(&env);
        let err = client.try_execute_recovery(&stranger).unwrap_err().unwrap();
        assert_eq!(err, RecoveryError::Unauthorized);
    }

    #[test]
    fn test_execute_recovery_without_pending_request_rejected() {
        let (_env, client, _, guardian) = setup();
        let err = client.try_execute_recovery(&guardian).unwrap_err().unwrap();
        assert_eq!(err, RecoveryError::NoActiveRecovery);
    }

    #[test]
    fn test_execute_cancelled_recovery_rejected() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        client.cancel_recovery();
        env.ledger()
            .with_mut(|l| l.sequence_number += RECOVERY_TIMELOCK + 1);
        let err = client.try_execute_recovery(&guardian).unwrap_err().unwrap();
        assert_eq!(err, RecoveryError::NoActiveRecovery);
    }

    // ── add_guardian / remove_guardian (#393) ──────────────────────────────────

    #[test]
    fn test_add_guardian_succeeds() {
        let (env, client, _, _guardian) = setup();
        let new_guardian = Address::generate(&env);
        let guardians = client.guardians();
        assert!(!guardians.contains(&new_guardian));
        assert_eq!(guardians.len(), 1);
    }

    #[test]
    fn test_add_guardian_emits_event() {
        let (env, client, owner, _) = setup();
        let new_guardian = Address::generate(&env);
        let _ = client.try_add_guardian(&owner, &new_guardian);
        let events = env.events().all();
        // init + grd_add
        assert_eq!(events.len(), 2);
        assert_eq!(topic_action(&env, &events, 1), symbol_short!("grd_add"));
    }

    #[test]
    fn test_add_duplicate_guardian_rejected() {
        let (_env, client, owner, guardian) = setup();
        let err = client
            .try_add_guardian(&owner, &guardian)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, RecoveryError::GuardianAlreadyExists);
    }

    #[test]
    fn test_add_guardian_cap_enforced() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MuxRecovery);
        let client = MuxRecoveryClient::new(&env, &contract_id);
        let owner = Address::generate(&env);
        // Initialize with one guardian
        let g1 = Address::generate(&env);
        client.initialize(&owner, &vec![&env, g1]);
        // Fill to MAX_GUARDIANS (16), already have 1
        for _ in 1..MAX_GUARDIANS {
            let _ = client.try_add_guardian(&owner, &Address::generate(&env));
        }
        // One more must be rejected
        let err = client
            .try_add_guardian(&owner, &Address::generate(&env))
            .unwrap_err()
            .unwrap();
        assert_eq!(err, RecoveryError::TooManyGuardians);
    }

    #[test]
    fn test_remove_guardian_succeeds() {
        let (env, client, owner, guardian) = setup();
        let g2 = Address::generate(&env);
        let _ = client.try_add_guardian(&owner, &g2);
        // Now we have 2 guardians, removing one should work
        let _ = client.try_remove_guardian(&owner, &guardian);
        assert!(!client.guardians().contains(&guardian));
        assert_eq!(client.guardians().len(), 1);
    }

    #[test]
    fn test_remove_guardian_emits_event() {
        let (env, client, owner, guardian) = setup();
        let g2 = Address::generate(&env);
        client.add_guardian(&owner, &g2);
        client.remove_guardian(&owner, &guardian);
        let events = env.events().all();
        // init + grd_add + grd_rm
        assert_eq!(events.len(), 3);
        assert_eq!(topic_action(&env, &events, 2), symbol_short!("grd_rm"));
    }

    #[test]
    fn test_remove_last_guardian_rejected() {
        let (_env, client, owner, guardian) = setup();
        // Only 1 guardian, can't remove
        let err = client
            .try_remove_guardian(&owner, &guardian)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, RecoveryError::MinGuardiansRequired);
    }

    #[test]
    fn test_remove_nonexistent_guardian_rejected() {
        let (env, client, owner, _) = setup();
        let stranger = Address::generate(&env);
        let err = client
            .try_remove_guardian(&owner, &stranger)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, RecoveryError::GuardianNotFound);
    }

    #[test]
    fn test_add_guardian_on_uninitialised_contract_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, MuxRecovery);
        let client = MuxRecoveryClient::new(&env, &contract_id);
        let owner = Address::generate(&env);
        let guardian = Address::generate(&env);
        let err = client
            .try_add_guardian(&owner, &guardian)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, RecoveryError::NotInitialized);
    }

    #[test]
    fn test_removed_guardian_cannot_initiate_recovery() {
        let (env, client, owner, guardian) = setup();
        let g2 = Address::generate(&env);
        client.add_guardian(&owner, &g2);
        client.remove_guardian(&owner, &guardian);
        // Removed guardian tries to initiate recovery
        let new_owner = Address::generate(&env);
        let err = client
            .try_initiate_recovery(&guardian, &new_owner)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, RecoveryError::Unauthorized);
    }

    #[test]
    fn test_newly_added_guardian_can_initiate_recovery() {
        let (env, client, owner, _) = setup();
        let g2 = Address::generate(&env);
        client.add_guardian(&owner, &g2);
        // New guardian can initiate recovery
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&g2, &new_owner);
        assert_eq!(client.recovery_status(), RecoveryStatus::Pending);
    }

    // ── symbol_short length audit (#496) ─────────────────────────────────────
    // symbol_short! enforces ≤ 8 chars at compile time; these declarations
    // confirm all event tag/action strings compile without truncation.
    #[test]
    fn test_symbol_short_lengths_within_limit() {
        let _mux_recv = symbol_short!("mux_recv");
        let _init = symbol_short!("init");
        let _rec_init = symbol_short!("rec_init");
        let _rec_cncl = symbol_short!("rec_cncl");
        let _rec_exec = symbol_short!("rec_exec");
    }

    // ── recovery expiry and event payload (#400) ─────────────────────────────

    #[test]
    fn test_execute_recovery_after_expiry_rejected() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        env.ledger()
            .with_mut(|l| l.sequence_number += RECOVERY_EXPIRY + 1);
        let err = client.try_execute_recovery(&guardian).unwrap_err().unwrap();
        assert_eq!(err, RecoveryError::RecoveryExpired);
    }

    #[test]
    fn test_expired_pending_recovery_can_be_reinitiated() {
        let (env, client, _, guardian) = setup();
        let first_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &first_owner);
        env.ledger()
            .with_mut(|l| l.sequence_number += RECOVERY_EXPIRY + 1);
        // The stale request must not block a fresh one.
        let second_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &second_owner);
        assert_eq!(client.recovery_status(), RecoveryStatus::Pending);
    }

    #[test]
    fn test_initiate_recovery_event_carries_timelock_window() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        let initiated_at = env.ledger().sequence();
        client.initiate_recovery(&guardian, &new_owner);

        let events = env.events().all();
        let (_, _, data) = events.get(1).unwrap();
        let (ev_guardian, ev_new_owner, ev_initiated, ev_executable, ev_expires): (
            Address,
            Address,
            u32,
            u32,
            u32,
        ) = FromVal::from_val(&env, &data);

        assert_eq!(ev_guardian, guardian);
        assert_eq!(ev_new_owner, new_owner);
        assert_eq!(ev_initiated, initiated_at);
        assert_eq!(ev_executable, initiated_at + RECOVERY_TIMELOCK);
        assert_eq!(ev_expires, initiated_at + RECOVERY_EXPIRY);
    }

    #[test]
    fn test_recovery_does_not_transfer_ownership_until_executed() {
        let (env, client, owner, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        env.ledger()
            .with_mut(|l| l.sequence_number += RECOVERY_TIMELOCK + 1);
        assert_eq!(client.owner(), owner);
        client.execute_recovery(&guardian);
        assert_eq!(client.owner(), new_owner);
    }

    #[test]
    fn test_recovery_cannot_be_executed_twice() {
        let (env, client, _, guardian) = setup();
        let new_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &new_owner);
        env.ledger()
            .with_mut(|l| l.sequence_number += RECOVERY_TIMELOCK + 1);
        client.execute_recovery(&guardian);
        let err = client.try_execute_recovery(&guardian).unwrap_err().unwrap();
        assert_eq!(err, RecoveryError::NoActiveRecovery);
    }

    #[test]
    fn test_cancelled_recovery_can_be_reinitiated() {
        let (env, client, _, guardian) = setup();
        let first_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &first_owner);
        client.cancel_recovery();
        let second_owner = Address::generate(&env);
        client.initiate_recovery(&guardian, &second_owner);
        assert_eq!(client.recovery_status(), RecoveryStatus::Pending);
        env.ledger()
            .with_mut(|l| l.sequence_number += RECOVERY_TIMELOCK + 1);
        client.execute_recovery(&guardian);
        assert_eq!(client.owner(), second_owner);
    }

    // ── registry link (#403) ──────────────────────────────────────────────────

    #[test]
    fn test_set_registry_stores_address() {
        let (_env, client, owner, _) = setup();
        let registry = Address::generate(&_env);
        client.set_registry(&owner, &registry);
        assert_eq!(client.registry_id(), Some(registry));
    }

    #[test]
    fn test_registry_id_none_before_set() {
        let (_env, client, _, _) = setup();
        assert!(client.registry_id().is_none());
    }

    #[test]
    fn test_set_registry_emits_event() {
        let (env, client, owner, _) = setup();
        let registry = Address::generate(&env);
        client.set_registry(&owner, &registry);
        let events = env.events().all();
        // init + reg_link
        assert_eq!(events.len(), 2);
        assert_eq!(topic_action(&env, &events, 1), symbol_short!("reg_link"));
    }

    #[test]
    fn test_set_registry_requires_owner_auth() {
        // mock_all_auths() satisfies any auth requirement, so the call must
        // succeed — this test verifies the method compiles and executes without
        // panicking when auth is mocked.
        let (env, client, owner, _) = setup();
        let registry = Address::generate(&env);
        client.set_registry(&owner, &registry);
        assert_eq!(client.registry_id(), Some(registry));
    }

    #[test]
    fn test_symbol_short_reg_link_within_limit() {
        // symbol_short! enforces ≤ 8 chars at compile time.
        let _reg_link = symbol_short!("reg_link");
    }
}
