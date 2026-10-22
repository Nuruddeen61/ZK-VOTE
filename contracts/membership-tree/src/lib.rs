#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    Bytes, BytesN, Env, IntoVal, Symbol, Vec, U256,
};

mod poseidon_params;
mod poseidon_params_bls12_381;

const SBT_CONTRACT: Symbol = symbol_short!("sbt");
const REGISTRY: Symbol = symbol_short!("registry");
const VOTING_CONTRACT_KEY: Symbol = symbol_short!("voting");
const DEFAULT_MAX_ROOTS: u32 = 30;
const MIN_MAX_ROOTS: u32 = 10;
const MAX_MAX_ROOTS: u32 = 100;
const MAX_TREE_DEPTH: u32 = 18;
const MIN_REGISTRATION_INTERVAL_SECS: u64 = 3600;
const ZEROS_CACHE: Symbol = symbol_short!("zeros");
const ZEROS_CACHE_BLS: Symbol = symbol_short!("z_bls");
const VERSION: u32 = 2;
const VERSION_KEY: Symbol = symbol_short!("ver");

const INSTANCE_TTL_THRESHOLD: u32 = 120_960;
const INSTANCE_TTL_EXTEND: u32 = 6_312_000;
const PERSISTENT_TTL_THRESHOLD: u32 = 120_960;
const PERSISTENT_TTL_EXTEND: u32 = 6_312_000;
pub const SWEEP_MAX_RECORDS: u32 = 50;

const POSEIDON_MDS: Symbol = symbol_short!("pos_mds");
const POSEIDON_RC: Symbol = symbol_short!("pos_rc");
const POSEIDON_MDS_BLS: Symbol = symbol_short!("mds_bl");
const POSEIDON_RC_BLS: Symbol = symbol_short!("rc_bls");

#[contracterror]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum TreeError {
    NotAdmin = 1, InvalidDepth = 2, TreeInitialized = 3, TreeNotInitialized = 4,
    CommitmentExists = 5, MemberExists = 6, TreeFull = 7, NoSbt = 8, NotOpenMembership = 9,
    LeafOutOfBounds = 10, MemberRemoved = 11, MemberNotInTree = 12, RootNotFound = 13,
    AlreadyInitialized = 14, MemberNotRevoked = 15, CommitmentAlreadyUsed = 16,
    RateLimited = 17, MaxRootsOutOfRange = 18, RootPinnedByProposal = 19,
    Sha3TreeNotInitialized = 20, PqCommitmentExists = 21, InvalidField = 22,
    CommitmentPending = 23, CommitmentNotPending = 24, CommitmentRevealTooEarly = 25,
    CommitmentHashMismatch = 26, UnknownEpoch = 27, ReentrantCall = 28,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    TreeDepth(u64), NextLeafIndex(u64), FilledSubtrees(u64), Roots(u64),
    LeafIndex(u64, U256), MemberLeafIndex(u64, Address), LeafValue(u64, u32),
    NextRootIndex(u64), RootIndex(u64, U256), RevokedAt(u64, U256),
    ReinstatedAt(u64, U256), NodeHash(u64, u32, u32), MinValidRootIdx(u64),
    PoseidonField(u64), CommitmentUsed(u64, U256), MaxRoots(u64),
    LastRegistrationAt(u64, Address), Sha3Roots(u64), Sha3NextRootIdx(u64),
    Sha3RootIndex(u64, U256), PqCommitment(U256),
    PendingRegistration(u64, Address), CommitmentSaltHash(u64, BytesN<32>),
    Epoch(u64), EpochRoot(u64, u32), EpochAdvancedAt(u64, u32),
    ReentrancyLock,
}

#[contracttype] #[derive(Clone, Debug, PartialEq)]
pub struct PendingRegistration { pub commitment_hash: BytesN<32>, pub committed_at_ledger: u32, pub committed_at: u64, }

#[contracttype] #[derive(Clone, Debug, PartialEq)]
pub struct EpochInfo { pub epoch: u32, pub root: U256, pub advanced_at: u64, }

#[soroban_sdk::contractevent] #[derive(Clone, Debug, PartialEq)]
pub struct TreeInitEvent { #[topic] pub dao_id: u64, pub depth: u32, pub empty_root: U256, pub root_index: u32, }
#[soroban_sdk::contractevent] #[derive(Clone, Debug, PartialEq)]
pub struct CommitEvent { #[topic] pub dao_id: u64, pub commitment: U256, pub index: u32, pub new_root: U256, pub root_index: u32, }
#[soroban_sdk::contractevent] #[derive(Clone, Debug, PartialEq)]
pub struct RemovalEvent { #[topic] pub dao_id: u64, #[topic] pub member: Address, pub index: u32, pub new_root: U256, pub root_index: u32, }
#[soroban_sdk::contractevent] #[derive(Clone, Debug, PartialEq)]
pub struct ReinstatementEvent { #[topic] pub dao_id: u64, #[topic] pub member: Address, pub reinstated_at: u64, }
#[soroban_sdk::contractevent] #[derive(Clone, Debug, PartialEq)]
pub struct ContractUpgraded { pub from: u32, pub to: u32, }
#[soroban_sdk::contractevent] #[derive(Clone, Debug, PartialEq)]
pub struct RootEvictedEvent { #[topic] pub dao_id: u64, pub evicted_root: U256, pub roots_len_after: u32, }
#[soroban_sdk::contractevent] #[derive(Clone, Debug, PartialEq)]
pub struct CommitmentCommittedEvent { #[topic] pub dao_id: u64, #[topic] pub member: Address, pub commitment_hash: BytesN<32>, pub committed_at_ledger: u32, }
#[soroban_sdk::contractevent] #[derive(Clone, Debug, PartialEq)]
pub struct CommitmentRevealedEvent { #[topic] pub dao_id: u64, #[topic] pub member: Address, pub commitment: U256, pub index: u32, }
#[soroban_sdk::contractevent] #[derive(Clone, Debug, PartialEq)]
pub struct EpochAdvancedEvent { #[topic] pub dao_id: u64, pub epoch: u32, pub root: U256, pub advanced_at: u64, }

#[contract] pub struct MembershipTree;

#[contractimpl]
impl MembershipTree {
    fn bump_instance(env: &Env) { env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND); }
    fn bump_persistent<K: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(env: &Env, key: &K) {
        env.storage().persistent().extend_ttl(key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
    }
    fn lock(env: &Env) {
        if env.storage().instance().has(&DataKey::ReentrancyLock) { panic_with_error!(env, TreeError::ReentrantCall); }
        env.storage().instance().set(&DataKey::ReentrancyLock, &true);
    }
    fn unlock(env: &Env) { env.storage().instance().remove(&DataKey::ReentrancyLock); }

    fn get_max_roots(env: &Env, dao_id: u64) -> u32 { env.storage().persistent().get(&DataKey::MaxRoots(dao_id)).unwrap_or(DEFAULT_MAX_ROOTS) }
    fn voting_contract(env: &Env) -> Option<Address> { env.storage().instance().get(&VOTING_CONTRACT_KEY) }

    pub fn set_voting_contract(env: Env, voting_contract: Address, registry: Address) {
        Self::bump_instance(&env); registry.require_auth();
        let expected: Address = env.storage().instance().get(&REGISTRY).unwrap_or_else(|| panic_with_error!(&env, TreeError::TreeNotInitialized));
        if registry != expected { panic_with_error!(&env, TreeError::NotAdmin); }
        env.storage().instance().set(&VOTING_CONTRACT_KEY, &voting_contract);
    }
    pub fn set_max_roots(env: Env, dao_id: u64, new_max: u32, admin: Address) {
        Self::lock(&env); Self::bump_instance(&env); admin.require_auth();
        let sbt_contract = Self::sbt_contract(&env);
        let registry: Address = env.invoke_contract(&sbt_contract, &symbol_short!("registry"), soroban_sdk::vec![&env]);
        let dao_admin: Address = env.invoke_contract(&registry, &symbol_short!("get_admin"), soroban_sdk::vec![&env, dao_id.into_val(&env)]);
        if dao_admin != admin { Self::unlock(&env); panic_with_error!(&env, TreeError::NotAdmin); }
        if new_max < MIN_MAX_ROOTS || new_max > MAX_MAX_ROOTS { Self::unlock(&env); panic_with_error!(&env, TreeError::MaxRootsOutOfRange); }
        let key = DataKey::MaxRoots(dao_id); env.storage().persistent().set(&key, &new_max); Self::bump_persistent(&env, &key); Self::unlock(&env);
    }
    pub fn max_roots(env: Env, dao_id: u64) -> u32 { Self::bump_instance(&env); Self::get_max_roots(&env, dao_id) }
    pub fn roots_len(env: Env, dao_id: u64) -> u32 {
        Self::bump_instance(&env);
        let roots: Vec<U256> = env.storage().persistent().get(&DataKey::Roots(dao_id)).unwrap_or_else(|| panic_with_error!(&env, TreeError::TreeNotInitialized));
        roots.len()
    }
    fn check_root_eviction_safety(env: &Env, dao_id: u64, candidate_root: &U256) {
        let Some(voting_addr) = Self::voting_contract(env) else { return; };
        let is_pinned: bool = env.invoke_contract(&voting_addr, &symbol_short!("root_pin"), soroban_sdk::vec![env, dao_id.into_val(env), candidate_root.clone().into_val(env)]);
        if is_pinned { panic_with_error!(env, TreeError::RootPinnedByProposal); }
        let _: () = env.invoke_contract(&voting_addr, &symbol_short!("chk_risk"), soroban_sdk::vec![env, dao_id.into_val(env), candidate_root.clone().into_val(env)]);
    }
    fn evict_oldest_root(env: &Env, dao_id: u64, roots: &mut Vec<U256>) {
        if let Some(evicted_root) = roots.get(0) {
            let evicted_key = DataKey::RootIndex(dao_id, evicted_root.clone()); env.storage().persistent().remove(&evicted_key);
            let mut new_roots = Vec::new(env); for i in 1..roots.len() { if let Some(r) = roots.get(i) { new_roots.push_back(r); } }
            *roots = new_roots;
            RootEvictedEvent { dao_id, evicted_root, roots_len_after: roots.len() }.publish(env);
        }
    }
    pub fn __constructor(env: Env, sbt_contract: Address, registry: Address) {
        if env.storage().instance().has(&VERSION_KEY) { panic_with_error!(&env, TreeError::AlreadyInitialized); }
        env.storage().instance().set(&VERSION_KEY, &VERSION);
        ContractUpgraded { from: 0, to: VERSION }.publish(&env);
        env.storage().instance().set(&SBT_CONTRACT, &sbt_contract);
        env.storage().instance().set(&REGISTRY, &registry);
        Self::ensure_zeros_cache(&env);
    }
    fn sbt_contract(env: &Env) -> Address { env.storage().instance().get(&SBT_CONTRACT).unwrap_or_else(|| panic_with_error!(env, TreeError::TreeNotInitialized)) }

    pub fn init_tree(env: Env, dao_id: u64, depth: u32, field: Symbol, admin: Address) {
        Self::lock(&env); Self::bump_instance(&env); admin.require_auth();
        let sbt_contract: Address = Self::sbt_contract(&env);
        let registry: Address = env.invoke_contract(&sbt_contract, &symbol_short!("registry"), soroban_sdk::vec![&env]);
        let dao_admin: Address = env.invoke_contract(&registry, &symbol_short!("get_admin"), soroban_sdk::vec![&env, dao_id.into_val(&env)]);
        if dao_admin != admin { Self::unlock(&env); panic_with_error!(&env, TreeError::NotAdmin); }
        if depth == 0 || depth > MAX_TREE_DEPTH { Self::unlock(&env); panic_with_error!(&env, TreeError::InvalidDepth); }
        Self::assert_valid_field(&env, &field);
        let depth_key = DataKey::TreeDepth(dao_id);
        if env.storage().persistent().has(&depth_key) { Self::unlock(&env); panic_with_error!(&env, TreeError::TreeInitialized); }
        env.storage().persistent().set(&depth_key, &depth); Self::bump_persistent(&env, &depth_key);
        let next_leaf_key = DataKey::NextLeafIndex(dao_id); env.storage().persistent().set(&next_leaf_key, &0u32); Self::bump_persistent(&env, &next_leaf_key);
        let field_key = DataKey::PoseidonField(dao_id); env.storage().persistent().set(&field_key, &field); Self::bump_persistent(&env, &field_key);
        let next_root_key = DataKey::NextRootIndex(dao_id); env.storage().persistent().set(&next_root_key, &0u32); Self::bump_persistent(&env, &next_root_key);
        let mut filled = Vec::new(&env); for level in 0..depth { filled.push_back(Self::zero_at_level_for_field(&env, level, &field)); }
        let filled_key = DataKey::FilledSubtrees(dao_id); env.storage().persistent().set(&filled_key, &filled); Self::bump_persistent(&env, &filled_key);
        let empty_root = Self::zero_at_level_for_field(&env, depth, &field);
        let mut roots = Vec::new(&env); roots.push_back(empty_root.clone());
        let roots_key = DataKey::Roots(dao_id); env.storage().persistent().set(&roots_key, &roots); Self::bump_persistent(&env, &roots_key);
        let root_idx_key = DataKey::RootIndex(dao_id, empty_root.clone()); env.storage().persistent().set(&root_idx_key, &0u32); Self::bump_persistent(&env, &root_idx_key);
        Self::init_epoch_zero(&env, dao_id, empty_root.clone());
        TreeInitEvent { dao_id, depth, empty_root, root_index: 0 }.publish(&env); Self::unlock(&env);
    }

    pub fn init_tree_from_registry(env: Env, dao_id: u64, depth: u32, field: Symbol) {
        Self::lock(&env); Self::bump_instance(&env);
        let registry: Address = env.storage().instance().get(&REGISTRY).unwrap_or_else(|| panic_with_error!(&env, TreeError::NotAdmin));
        registry.require_auth();
        if depth == 0 || depth > MAX_TREE_DEPTH { Self::unlock(&env); panic_with_error!(&env, TreeError::InvalidDepth); }
        Self::assert_valid_field(&env, &field);
        let depth_key = DataKey::TreeDepth(dao_id);
        if env.storage().persistent().has(&depth_key) { Self::unlock(&env); panic_with_error!(&env, TreeError::TreeInitialized); }
        env.storage().persistent().set(&depth_key, &depth); Self::bump_persistent(&env, &depth_key);
        let next_leaf_key = DataKey::NextLeafIndex(dao_id); env.storage().persistent().set(&next_leaf_key, &0u32); Self::bump_persistent(&env, &next_leaf_key);
        let field_key = DataKey::PoseidonField(dao_id); env.storage().persistent().set(&field_key, &field); Self::bump_persistent(&env, &field_key);
        let next_root_key = DataKey::NextRootIndex(dao_id); env.storage().persistent().set(&next_root_key, &0u32); Self::bump_persistent(&env, &next_root_key);
        let mut filled = Vec::new(&env); for level in 0..depth { filled.push_back(Self::zero_at_level_for_field(&env, level, &field)); }
        let filled_key = DataKey::FilledSubtrees(dao_id); env.storage().persistent().set(&filled_key, &filled); Self::bump_persistent(&env, &filled_key);
        let empty_root = Self::zero_at_level_for_field(&env, depth, &field);
        let mut roots = Vec::new(&env); roots.push_back(empty_root.clone());
        let roots_key = DataKey::Roots(dao_id); env.storage().persistent().set(&roots_key, &roots); Self::bump_persistent(&env, &roots_key);
        let root_idx_key = DataKey::RootIndex(dao_id, empty_root.clone()); env.storage().persistent().set(&root_idx_key, &0u32); Self::bump_persistent(&env, &root_idx_key);
        Self::init_epoch_zero(&env, dao_id, empty_root.clone());
        TreeInitEvent { dao_id, depth, empty_root, root_index: 0 }.publish(&env); Self::unlock(&env);
    }

    fn init_epoch
