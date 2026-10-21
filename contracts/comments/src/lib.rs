//! # Anonymous Comments Contract
//!
//! This contract implements anonymous commenting for DAO proposals using Groth16
//! zero-knowledge proofs on the BN254 elliptic curve.
//!
//! This contract uses the SAME vote circuit as the voting contract. The key insight
//! is that nullifier uniqueness is a CONTRACT-level concern, not a circuit concern:
//! - Vote contract: enforces nullifier uniqueness (one vote per user per proposal)
//! - Comment contract: just verifies proof for membership (allows multiple comments)
//!
//! ## Public Signals (Vote Circuit - shared with voting contract)
//! [root, nullifier, daoId, proposalId, voteChoice] - 5 signals
//! Note: commitment is computed internally in the circuit (private input)
//!
//! The voteChoice signal is ignored for comments - we just verify membership.

#![no_std]
#![allow(clippy::too_many_arguments)]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr},
    panic_with_error, symbol_short, Address, Bytes, BytesN, Env, IntoVal, String, Symbol, Vec,
    U256,
};

pub use zkvote_groth16::{
    CurveId, Groth16Error, PathContext, Proof, ProofBls381, VerificationKey, VerificationKeyBls381,
};

const TREE_CONTRACT: Symbol = symbol_short!("tree");
const REGISTRY: Symbol = symbol_short!("registry");
const LOCK: Symbol = symbol_short!("lock");
const VERSION: u32 = 3;
const VERSION_KEY: Symbol = symbol_short!("ver");

const INSTANCE_TTL_THRESHOLD: u32 = 120_960;
const INSTANCE_TTL_EXTEND: u32 = 535_680;
const PERSISTENT_TTL_THRESHOLD: u32 = 120_960;
const PERSISTENT_TTL_EXTEND: u32 = 535_680;

#[contracterror]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum CommentsError {
    NotAdmin = 1,
    Unauthorized = 19,
    NotDaoMember = 5,
    CommitmentRevoked = 9,
    RootNotInHistory = 12,
    InvalidProof = 15,
    ContractNotSet = 16,
    AlreadyInitialized = 18,
    CommentNotFound = 22,
    CommentDeleted = 23,
    NotCommentOwner = 24,
    InvalidParentComment = 25,
    CommentContentTooLong = 27,
    ProposalNotFound = 28,
    RootMismatch = 29,
    RootPredatesProposal = 30,
    SignalNotInField = 31,
    InvalidNullifier = 32,
    RootPredatesRemoval = 33,
    /// A guarded entrypoint was re-entered while it was already running (#521)
    Reentrancy = 34,
    InvalidInput = 100,
    EligibilityFailed = 101,
    ProofInvalid = 102,
    AlreadySubmitted = 103,
    WindowClosed = 104,
    InsufficientFunds = 105,
    ConfigError = 106,
}

impl CommentsError {
    pub fn to_coarse(&self, ctx: PathContext) -> CommentsError {
        #[cfg(test)]
        return *self;
        #[cfg(not(test))]
        match ctx {
            PathContext::Admin => *self,
            PathContext::Anonymous => match self {
                CommentsError::SignalNotInField
                | CommentsError::InvalidNullifier
                | CommentsError::CommentContentTooLong
                | CommentsError::InvalidParentComment => CommentsError::InvalidInput,
                CommentsError::CommitmentRevoked
                | CommentsError::RootMismatch
                | CommentsError::RootNotInHistory
                | CommentsError::RootPredatesProposal
                | CommentsError::RootPredatesRemoval => CommentsError::EligibilityFailed,
                CommentsError::InvalidProof => CommentsError::ProofInvalid,
                CommentsError::ProposalNotFound
                | CommentsError::CommentNotFound
                | CommentsError::CommentDeleted
                | CommentsError::NotCommentOwner
                | CommentsError::NotAdmin
                | CommentsError::Unauthorized
                | CommentsError::NotDaoMember
                | CommentsError::ContractNotSet
                | CommentsError::AlreadyInitialized
                | CommentsError::Reentrancy => *self,
                CommentsError::InvalidInput
                | CommentsError::EligibilityFailed
                | CommentsError::ProofInvalid
                | CommentsError::AlreadySubmitted
                | CommentsError::WindowClosed
                | CommentsError::InsufficientFunds
                | CommentsError::ConfigError => *self,
            },
        }
    }
}

#[inline]
fn panic_coarse(env: &Env, ctx: PathContext, err: CommentsError) {
    panic_with_error!(env, err.to_coarse(ctx));
}

#[contracttype]
#[derive(Clone, PartialEq)]
pub enum VoteMode {
    Fixed,
    Trailing,
}

const MAX_CID_LEN: u32 = 64;
const MAX_REVISIONS: u32 = 50;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Comment(u64, u64, u64),
    CommentCount(u64, u64),
    CommentNullifier(u64, u64, U256),
    CommitmentNonce(u64, u64, U256),
    VotingContract,
    VerifyOverride,
}

pub const DELETED_BY_NONE: u32 = 0;
pub const DELETED_BY_USER: u32 = 1;
pub const DELETED_BY_ADMIN: u32 = 2;

#[contracttype]
#[derive(Clone)]
pub struct CommentInfo {
    pub id: u64,
    pub dao_id: u64,
    pub proposal_id: u64,
    pub author: Option<Address>,
    pub content_cid: String,
    pub parent_id: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
    pub revision_cids: Vec<String>,
    pub deleted: bool,
    pub deleted_by: u32,
    pub nullifier: Option<U256>,
    pub comment_nonce: Option<u64>,
}

#[soroban_sdk::contractevent]
#[derive(Clone, Debug, PartialEq)]
pub struct CommentCreatedEvent {
    #[topic]
    pub dao_id: u64,
    #[topic]
    pub proposal_id: u64,
    pub comment_id: u64,
    pub is_anonymous: bool,
}

#[soroban_sdk::contractevent]
#[derive(Clone, Debug, PartialEq)]
pub struct CommentEditedEvent {
    #[topic]
    pub dao_id: u64,
    #[topic]
    pub proposal_id: u64,
    pub comment_id: u64,
}

#[soroban_sdk::contractevent]
#[derive(Clone, Debug, PartialEq)]
pub struct CommentDeletedEvent {
    #[topic]
    pub dao_id: u64,
    #[topic]
    pub proposal_id: u64,
    pub comment_id: u64,
    pub deleted_by: u32,
}

#[soroban_sdk::contractevent]
#[derive(Clone, Debug, PartialEq)]
pub struct ContractUpgraded {
    pub from: u32,
    pub to: u32,
}

#[contract]
pub struct Comments;

#[contractimpl]
impl Comments {
    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND);
    }

    fn bump_persistent<K: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(env: &Env, key: &K) {
        env.storage()
            .persistent()
            .extend_ttl(key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
    }

    /// Reentrancy guard (#521): take the lock, or revert if already held.
    fn enter(env: &Env) {
        if env
            .storage()
            .instance()
            .get::<_, bool>(&LOCK)
            .unwrap_or(false)
        {
            panic_with_error!(env, CommentsError::Reentrancy);
        }
        env.storage().instance().set(&LOCK, &true);
    }

    /// Reentrancy guard (#521): release the lock.
    fn exit(env: &Env) {
        env.storage().instance().set(&LOCK, &false);
    }

    pub fn __constructor(
        env: Env,
        tree_contract: Address,
        voting_contract: Address,
        registry: Address,
    ) {
        if env.storage().instance().has(&VERSION_KEY) {
            panic_with_error!(&env, CommentsError::AlreadyInitialized);
        }
        env.storage().instance().set(&VERSION_KEY, &VERSION);
        ContractUpgraded { from: 0, to: VERSION }.publish(&env);
        env.storage().instance().set(&TREE_CONTRACT, &tree_contract);
        env.storage().instance().set(&DataKey::VotingContract, &voting_contract);
        env.storage().instance().set(&REGISTRY, &registry);
    }

    fn assert_in_field(env: &Env, ctx: PathContext, value: &U256) {
        if zkvote_groth16::assert_in_field(env, value).is_err() {
            panic_coarse(env, ctx, CommentsError::SignalNotInField);
        }
    }

    fn assert_in_field_bls381(env: &Env, ctx: PathContext, value: &U256) {
        if zkvote_groth16::assert_in_field_bls381(env, value).is_err() {
            panic_coarse(env, ctx, CommentsError::SignalNotInField);
        }
    }

    fn get_vk_from_voting(env: &Env, dao_id: u64) -> VerificationKey {
        let voting_contract: Address = Self::voting_contract(env.clone());
        env.invoke_contract(
            &voting_contract,
            &symbol_short!("get_vk"),
            soroban_sdk::vec![env, dao_id.into_val(env)],
        )
    }

    fn get_vk_from_voting_bls381(env: &Env, dao_id: u64) -> VerificationKeyBls381 {
        let voting_contract: Address = Self::voting_contract(env.clone());
        env.invoke_contract(
            &voting_contract,
            &Symbol::new(env, "get_vk_bls381"),
            soroban_sdk::vec![env, dao_id.into_val(env)],
        )
    }

    fn get_proposal_eligibility(env: &Env, dao_id: u64, proposal_id: u64) -> (VoteMode, U256, u32) {
        let voting_contract: Address = Self::voting_contract(env.clone());
        let vote_mode: VoteMode = env.invoke_contract(
            &voting_contract,
            &Symbol::new(env, "get_vote_mode"),
            soroban_sdk::vec![env, dao_id.into_val(env), proposal_id.into_val(env)],
        );
        let eligible_root: U256 = env.invoke_contract(
            &voting_contract,
            &Symbol::new(env, "get_eligible_root"),
            soroban_sdk::vec![env, dao_id.into_val(env), proposal_id.into_val(env)],
        );
        let earliest_root_index: u32 = env.invoke_contract(
            &voting_contract,
            &Symbol::new(env, "get_earliest_idx"),
            soroban_sdk::vec![env, dao_id.into_val(env), proposal_id.into_val(env)],
        );
        (vote_mode, eligible_root, earliest_root_index)
    }

    fn validate_root_eligibility(
        env: &Env,
        ctx: PathContext,
        dao_id: u64,
        proposal_id: u64,
        root: &U256,
    ) {
        let (vote_mode, eligible_root, earliest_root_index) =
            Self::get_proposal_eligibility(env, dao_id, proposal_id);
        let tree_contract: Address = Self::tree_contract(env.clone());
        match vote_mode {
            VoteMode::Fixed => {
                if root != &eligible_root {
                    panic_coarse(env, ctx, CommentsError::RootMismatch);
                }
                Self::assert_root_not_revoked(env, ctx, dao_id, root);
            }
            VoteMode::Trailing => {
                let code: u32 = env.invoke_contract(
                    &tree_contract,
                    &Symbol::new(env, "root_eligibility"),
                    soroban_sdk::vec![
                        env,
                        dao_id.into_val(env),
                        root.clone().into_val(env),
                        earliest_root_index.into_val(env),
                    ],
                );
                match code {
                    0 => {}
                    1 => panic_coarse(env, ctx, CommentsError::RootNotInHistory),
                    2 => panic_coarse(env, ctx, CommentsError::RootPredatesProposal),
                    _ => panic_coarse(env, ctx, CommentsError::RootPredatesRemoval),
                }
            }
        }
    }

    fn assert_root_not_revoked(env: &Env, ctx: PathContext, dao_id: u64, root: &U256) {
        let tree_contract: Address = Self::tree_contract(env.clone());
        let code: u32 = env.invoke_contract(
            &tree_contract,
            &Symbol::new(env, "root_eligibility"),
            soroban_sdk::vec![
                env,
                dao_id.into_val(env),
                root.clone().into_val(env),
                0u32.into_val(env),
            ],
        );
        match code {
            0 => {}
            1 => panic_coarse(env, ctx, CommentsError::RootNotInHistory),
            2 => panic_coarse(env, ctx, CommentsError::RootPredatesProposal),
            _ => panic_coarse(env, ctx, CommentsError::RootPredatesRemoval),
        }
    }

    fn assert_admin(env: &Env, dao_id: u64, admin: &Address) {
        let registry: Address = env.storage().instance().get(&REGISTRY).unwrap();
        let dao_admin: Address = env.invoke_contract(
            &registry,
            &symbol_short!("get_admin"),
            soroban_sdk::vec![env, dao_id.into_val(env)],
        );
        if &dao_admin != admin {
            panic_with_error!(env, CommentsError::NotAdmin);
        }
    }

    fn validate_cid(env: &Env, ctx: PathContext, cid: &String) {
        if cid.len() > MAX_CID_LEN {
            panic_coarse(env, ctx, CommentsError::CommentContentTooLong);
        }
    }

    pub fn add_comment(
        env: Env,
        dao_id: u64,
        proposal_id: u64,
        content_cid: String,
        parent_id: Option<u64>,
        author: Address,
    ) -> u64 {
        Self::bump_instance(&env);
        Self::enter(&env);
        author.require_auth();
        Self::validate_cid(&env, PathContext::Admin, &content_cid);
        Self::assert_proposal_exists(&env, dao_id, proposal_id);
        Self::assert_membership(&env, dao_id, &author);
        if let Some(pid) = parent_id {
            let parent_key = DataKey::Comment(dao_id, proposal_id, pid);
            if !env.storage().persistent().has(&parent_key) {
                panic_with_error!(&env, CommentsError::InvalidParentComment);
            }
        }
        let comment_id = Self::next_comment_id(&env, dao_id, proposal_id);
        let now = env.ledger().timestamp();
        let comment = CommentInfo {
            id: comment_id,
            dao_id,
            proposal_id,
            author: Some(author),
            content_cid,
            parent_id,
            created_at: now,
            updated_at: now,
            revision_cids: Vec::new(&env),
            deleted: false,
            deleted_by: DELETED_BY_NONE,
            nullifier: None,
            comment_nonce: None,
        };
        let key = DataKey::Comment(dao_id, proposal_id, comment_id);
        env.storage().persistent().set(&key, &comment);
        Self::bump_persistent(&env, &key);
        Self::exit(&env);
        CommentCreatedEvent { dao_id, proposal_id, comment_id, is_anonymous: false }.publish(&env);
        comment_id
    }

    pub fn add_anonymous_comment(
        env: Env,
        dao_id: u64,
        proposal_id: u64,
        content_cid: String,
        parent_id: Option<u64>,
        nullifier: U256,
        root: U256,
        vote_choice: bool,
        proof: Proof,
    ) -> u64 {
        Self::bump_instance(&env);
        Self::enter(&env);
        let ctx = PathContext::Anonymous;
        Self::assert_in_field(&env, ctx, &nullifier);
        Self::assert_in_field(&env, ctx, &root);
        if nullifier == U256::from_u32(&env, 0) {
            panic_coarse(&env, ctx, CommentsError::InvalidNullifier);
        }
        Self::validate_cid(&env, ctx, &content_cid);
        if let Some(pid) = parent_id {
            let parent_key = DataKey::Comment(dao_id, proposal_id, pid);
            if !env.storage().persistent().has(&parent_key) {
                panic_coarse(&env, ctx, CommentsError::InvalidParentComment);
            }
        }
        Self::assert_proposal_exists(&env, dao_id, proposal_id);
        Self::validate_root_eligibility(&env, ctx, dao_id, proposal_id, &root);
        let vk = Self::get_vk_from_voting(&env, dao_id);
        let dao_signal = U256::from_u128(&env, dao_id as u128);
        let proposal_signal = U256::from_u128(&env, proposal_id as u128);
        let choice_signal = if vote_choice { U256::from_u32(&env, 1) } else { U256::from_u32(&env, 0) };
        let pub_signals = soroban_sdk::vec![&env, root.clone(), nullifier.clone(), dao_signal, proposal_signal, choice_signal];
        if !Self::verify_groth16(&env, &vk, &proof, &pub_signals) {
            panic_coarse(&env, ctx, CommentsError::InvalidProof);
        }
        let comment_id = Self::next_comment_id(&env, dao_id, proposal_id);
        let now = env.ledger().timestamp();
        let comment = CommentInfo {
            id: comment_id, dao_id, proposal_id, author: None, content_cid, parent_id,
            created_at: now, updated_at: now, revision_cids: Vec::new(&env),
            deleted: false, deleted_by: DELETED_BY_NONE, nullifier: Some(nullifier), comment_nonce: None,
        };
        let key = DataKey::Comment(dao_id, proposal_id, comment_id);
        env.storage().persistent().set(&key, &comment);
        Self::bump_persistent(&env, &key);
        Self::exit(&env);
        CommentCreatedEvent { dao_id, proposal_id, comment_id, is_anonymous: true }.publish(&env);
        comment_id
    }

    pub fn add_anonymous_comment_bls381(
        env: Env,
        dao_id: u64,
        proposal_id: u64,
        content_cid: String,
        parent_id: Option<u64>,
        nullifier: U256,
        root: U256,
        vote_choice: bool,
        proof: ProofBls381,
    ) -> u64 {
        Self::bump_instance(&env);
        Self::enter(&env);
        let ctx = PathContext::Anonymous;
        Self::assert_in_field_bls381(&env, ctx, &nullifier);
        Self::assert_in_field_bls381(&env, ctx, &root);
        if nullifier == U256::from_u32(&env, 0) {
            panic_coarse(&env, ctx, CommentsError::InvalidNullifier);
        }
        Self::validate_cid(&env, ctx, &content_cid);
        if let Some(pid) = parent_id {
            let parent_key = DataKey::Comment(dao_id, proposal_id, pid);
            if !env.storage().persistent().has(&parent_key) {
                panic_coarse(&env, ctx, CommentsError::InvalidParentComment);
            }
        }
        Self::assert_proposal_exists(&env, dao_id, proposal_id);
        Self::validate_root_eligibility(&env, ctx, dao_id, proposal_id, &root);
        let vk = Self::get_vk_from_voting_bls381(&env, dao_id);
        let dao_signal = U256::from_u128(&env, dao_id as u128);
        let proposal_signal = U256::from_u128(&env, proposal_id as u128);
        let choice_signal = if vote_choice { U256::from_u32(&env, 1) } else { U256::from_u32(&env, 0) };
        let pub_signals = soroban_sdk::vec![&env, root.clone(), nullifier.clone(), dao_signal, proposal_signal, choice_signal];
        if !Self::verify_groth16_bls381(&env, &vk, &proof, &pub_signals) {
            panic_coarse(&env, ctx, CommentsError::InvalidProof);
        }
        let comment_id = Self::next_comment_id(&env, dao_id, proposal_id);
        let now = env.ledger().timestamp();
        let comment = CommentInfo {
            id: comment_id, dao_id, proposal_id, author: None, content_cid, parent_id,
            created_at: now, updated_at: now, revision_cids: Vec::new(&env),
            deleted: false, deleted_by: DELETED_BY_NONE, nullifier: Some(nullifier), comment_nonce: None,
        };
        let key = DataKey::Comment(dao_id, proposal_id, comment_id);
        env.storage().persistent().set(&key, &comment);
        Self::bump_persistent(&env, &key);
        Self::exit(&env);
        CommentCreatedEvent { dao_id, proposal_id, comment_id, is_anonymous: true }.publish(&env);
        comment_id
    }

    pub fn edit_comment(
        env: Env,
        dao_id: u64,
        proposal_id: u64,
        comment_id: u64,
        new_content_cid: String,
        author: Address,
    ) {
        Self::bump_instance(&env);
        author.require_auth();
        if new_content_cid.len() > MAX_CID_LEN {
            panic_with_error!(&env, CommentsError::CommentContentTooLong);
        }
        let key = DataKey::Comment(dao_id, proposal_id, comment_id);
        let mut comment: CommentInfo = env.storage().persistent().get(&key).unwrap_or_else(|| panic_with_error!(&env, CommentsError::CommentNotFound));
        if comment.deleted {
            panic_with_error!(&env, CommentsError::CommentDeleted);
        }
        match &comment.author {
            Some(original_author) if original_author == &author => {}
            _ => panic_with_error!(&env, CommentsError::NotCommentOwner),
        }
        if comment.revision_cids.len() < MAX_REVISIONS {
            comment.revision_cids.push_back(comment.content_cid.clone());
        }
        comment.content_cid = new_content_cid;
        comment.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &comment);
        Self::bump_persistent(&env, &key);
        CommentEditedEvent { dao_id, proposal_id, comment_id }.publish(&env);
    }

    pub fn edit_anonymous_comment(
        env: Env,
        dao_id: u64,
        proposal_id: u64,
        comment_id: u64,
        new_content_cid: String,
        nullifier: U256,
        root: U256,
        vote_choice: bool,
        proof: Proof,
    ) {
        Self::bump_instance(&env);
        let ctx = PathContext::Anonymous;
        Self::assert_in_field(&env, ctx, &nullifier);
        Self::assert_in_field(&env, ctx, &root);
        if new_content_cid.len() > MAX_CID_LEN {
            panic_coarse(&env, ctx, CommentsError::CommentContentTooLong);
        }
        let key = DataKey::Comment(dao_id, proposal_id, comment_id);
        let mut comment: CommentInfo = env.storage().persistent().get(&key).unwrap_or_else(|| panic_with_error!(&env, CommentsError::CommentNotFound));
        if comment.deleted {
            panic_with_error!(&env, CommentsError::CommentDeleted);
        }
        match &comment.nullifier {
            Some(original_nullifier) => {
                if &nullifier != original_nullifier {
                    panic_with_error!(&env, CommentsError::NotCommentOwner);
                }
            }
            _ => panic_with_error!(&env, CommentsError::NotCommentOwner),
        }
        Self::assert_proposal_exists(&env, dao_id, proposal_id);
        Self::validate_root_eligibility(&env, ctx, dao_id, proposal_id, &root);
        let vk = Self::get_vk_from_voting(&env, dao_id);
        let dao_signal = U256::from_u128(&env, dao_id as u128);
        let proposal_signal = U256::from_u128(&env, proposal_id as u128);
        let choice_signal = if vote_choice { U256::from_u32(&env, 1) } else { U256::from_u32(&env, 0) };
        let pub_signals = soroban_sdk::vec![&env, root.clone(), nullifier.clone(), dao_signal, proposal_signal, choice_signal];
        if !Self::verify_groth16(&env, &vk, &proof, &pub_signals) {
            panic_coarse(&env, ctx, CommentsError::InvalidProof);
        }
        if comment.revision_cids.len() < MAX_REVISIONS {
            comment.revision_cids.push_back(comment.content_cid.clone());
        }
        comment.content_cid = new_content_cid;
        comment.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &comment);
        Self::bump_persistent(&env, &key);
        CommentEditedEvent { dao_id, proposal_id, comment_id }.publish(&env);
    }

    pub fn edit_anonymous_comment_bls381(
        env: Env,
        dao_id: u64,
        proposal_id: u64,
        comment_id: u64,
        new_content_cid: String,
        nullifier: U256,
        root: U256,
        vote_choice: bool,
        proof: ProofBls381,
    ) {
        Self::bump_instance(&env);
        let ctx = PathContext::Anonymous;
        Self::assert_in_field_bls381(&env, ctx, &nullifier);
        Self::assert_in_field_bls381(&env, ctx, &root);
        if new_content_cid.len() > MAX_CID_LEN {
            panic_coarse(&env, ctx, CommentsError::CommentContentTooLong);
        }
        let key = DataKey::Comment(dao_id, proposal_id, comment_id);
        let mut comment: CommentInfo = env.storage().persistent().get(&key).unwrap_or_else(|| panic_with_error!(&env, CommentsError::CommentNotFound));
        if comment.deleted {
            panic_with_error!(&env, CommentsError::CommentDeleted);
        }
        match &comment.nullifier {
            Some(original_nullifier) => {
                if &nullifier != original_nullifier {
                    panic_with_error!(&env, CommentsError::NotCommentOwner);
                }
            }
            _ => panic_with_error!(&env, CommentsError::NotCommentOwner),
        }
        Self::assert_proposal_exists(&env, dao_id, proposal_id);
        Self::validate_root_eligibility(&env, ctx, dao_id, proposal_id, &root);
        let vk = Self::get_vk_from_voting_bls381(&env, dao_id);
        let dao_signal = U256::from_u128(&env, dao_id as u128);
        let proposal_signal = U256::from_u128(&env, proposal_id as u128);
        let choice_signal = if vote_choice { U256::from_u32(&env, 1) } else { U256::from_u32(&env, 0) };
        let pub_signals = soroban_sdk::vec![&env, root.clone(), nullifier.clone(), dao_signal, proposal_signal, choice_signal];
        if !Self::verify_groth16_bls381(&env, &vk, &proof, &pub_signals) {
            panic_coarse(&env, ctx, CommentsError::InvalidProof);
        }
        if comment.revision_cids.len() < MAX_REVISIONS {
            comment.revision_cids.push_back(comment.content_cid.clone());
        }
        comment.content_cid = new_content_cid;
        comment.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &comment);
        Self::bump_persistent(&env, &key);
        CommentEditedEvent { dao_id, proposal_id, comment_id }.publish(&env);
    }

    pub fn delete_comment(env: Env, dao_id: u64, proposal_id: u64, comment_id: u64, author: Address) {
        Self::bump_instance(&env);
        author.require_auth();
        let key = DataKey::Comment(dao_id, proposal_id, comment_id);
        let mut comment: CommentInfo = env.storage().persistent().get(&key).unwrap_or_else(|| panic_with_error!(&env, CommentsError::CommentNotFound));
        if comment.deleted { return; }
        match &comment.author {
            Some(original_author) if original_author == &author => {}
            _ => panic_with_error!(&env, CommentsError::NotCommentOwner),
        }
        comment.deleted = true;
        comment.deleted_by = DELETED_BY_USER;
        comment.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &comment);
        Self::bump_persistent(&env, &key);
        CommentDeletedEvent { dao_id, proposal_id, comment_id, deleted_by: DELETED_BY_USER }.publish(&env);
    }

    pub fn delete_anonymous_comment(
        env: Env,
        dao_id: u64,
        proposal_id: u64,
        comment_id: u64,
        nullifier: U256,
        root: U256,
        vote_choice: bool,
        proof: Proof,
    ) {
        Self::bump_instance(&env);
        let ctx = PathContext::Anonymous;
        Self::assert_in_field(&env, ctx, &nullifier);
        Self::assert_in_field(&env, ctx, &root);
        let key = DataKey::Comment(dao_id, proposal_id, comment_id);
        let mut comment: CommentInfo = env.storage().persistent().get(&key).unwrap_or_else(|| panic_with_error!(&env, CommentsError::CommentNotFound));
        if comment.deleted { return; }
        match &comment.nullifier {
            Some(original_nullifier) if original_nullifier == &nullifier => {}
            _ => panic_with_error!(&env, CommentsError::NotCommentOwner),
        }
        Self::assert_proposal_exists(&env, dao_id, proposal_id);
        Self::validate_root_eligibility(&env, ctx, dao_id, proposal_id, &root);
        let vk = Self::get_vk_from_voting(&env, dao_id);
        let dao_signal = U256::from_u128(&env, dao_id as u128);
        let proposal_signal = U256::from_u128(&env, proposal_id as u128);
        let choice_signal = if vote_choice { U256::from_u32(&env, 1) } else { U256::from_u32(&env, 0) };
        let pub_signals = soroban_sdk::vec![&env, root.clone(), nullifier.clone(), dao_signal, proposal_signal, choice_signal];
        if !Self::verify_groth16(&env, &vk, &proof, &pub_signals) {
            panic_coarse(&env, ctx, CommentsError::InvalidProof);
        }
        comment.deleted = true;
        comment.deleted_by = DELETED_BY_USER;
        comment.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &comment);
        Self::bump_persistent(&env, &key);
        CommentDeletedEvent { dao_id, proposal_id, comment_id, deleted_by: DELETED_BY_USER }.publish(&env);
    }

    pub fn admin_delete_comment(env: Env, dao_id: u64, proposal_id: u64, comment_id: u64, admin: Address) {
        Self::bump_instance(&env);
        admin.require_auth();
        Self::assert_admin(&env, dao_id, &admin);
        let key = DataKey::Comment(dao_id, proposal_id, comment_id);
        let mut comment: CommentInfo = env.storage().persistent().get(&key).unwrap_or_else(|| panic_with_error!(&env, CommentsError::CommentNotFound));
        if comment.deleted { return; }
        comment.deleted = true;
        comment.deleted_by = DELETED_BY_ADMIN;
        comment.updated_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &comment);
        Self::bump_persistent(&env, &key);
        CommentDeletedEvent { dao_id, proposal_id, comment_id, deleted_by: DELETED_BY_ADMIN }.publish(&env);
    }

    pub fn get_comment(env: Env, dao_id: u64, proposal_id: u64, comment_id: u64) -> CommentInfo {
        Self::bump_instance(&env);
        let key = DataKey::Comment(dao_id, proposal_id, comment_id);
        let comment: CommentInfo = env.storage().persistent().get(&key).unwrap_or_else(|| panic_with_error!(&env, CommentsError::CommentNotFound));
        Self::bump_persistent(&env, &key);
        comment
    }

    pub fn comment_count(env: Env, dao_id: u64, proposal_id: u64) -> u64 {
        Self::bump_instance(&env);
        env.storage().instance().get(&DataKey::CommentCount(dao_id, proposal_id)).unwrap_or(0)
    }

    pub fn get_comments(env: Env, dao_id: u64, proposal_id: u64, start_id: u64, limit: u64) -> Vec<CommentInfo> {
        Self::bump_instance(&env);
        let total = Self::comment_count(env.clone(), dao_id, proposal_id);
        let mut comments = Vec::new(&env);
        let end = if start_id + limit > total { total } else { start_id + limit };
        for i in start_id..end {
            let comment_id = i + 1;
            let key = DataKey::Comment(dao_id, proposal_id, comment_id);
            if let Some(comment) = env.storage().persistent().get::<DataKey, CommentInfo>(&key) {
                comments.push_back(comment);
            }
        }
        comments
    }

    pub fn tree_contract(env: Env) -> Address {
        Self::bump_instance(&env);
        env.storage().instance().get(&TREE_CONTRACT).unwrap_or_else(|| panic_with_error!(&env, CommentsError::ContractNotSet))
    }

    pub fn voting_contract(env: Env) -> Address {
        Self::bump_instance(&env);
        env.storage().instance().get(&DataKey::VotingContract).unwrap_or_else(|| panic_with_error!(&env, CommentsError::ContractNotSet))
    }

    pub fn get_comment_nonce(env: Env, dao_id: u64, proposal_id: u64, commitment: U256) -> u64 {
        Self::bump_instance(&env);
        let key = DataKey::CommitmentNonce(dao_id, proposal_id, commitment);
        let nonce: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        if nonce > 0 {
            Self::bump_persistent(&env, &key);
        }
        nonce
    }

    pub fn version(env: Env) -> u32 {
        Self::bump_instance(&env);
        env.storage().instance().get(&VERSION_KEY).unwrap_or(VERSION)
    }

    fn next_comment_id(env: &Env, dao_id: u64, proposal_id: u64) -> u64 {
        let count_key = DataKey::CommentCount(dao_id, proposal_id);
        let count: u64 = env.storage().instance().get(&count_key).unwrap_or(0);
        let new_id = count + 1;
        env.storage().instance().set(&count_key, &new_id);
        new_id
    }

    fn assert_membership(env: &Env, dao_id: u64, member: &Address) {
        let tree_contract: Address = Self::tree_contract(env.clone());
        let sbt_contract: Address = env.invoke_contract(&tree_contract, &symbol_short!("sbt_contr"), soroban_sdk::vec![env]);
        let has_sbt: bool = env.invoke_contract(&sbt_contract, &symbol_short!("has"), soroban_sdk::vec![env, dao_id.into_val(env), member.clone().into_val(env)]);
        if !has_sbt {
            panic_with_error!(env, CommentsError::NotDaoMember);
        }
    }

    fn assert_proposal_exists(env: &Env, dao_id: u64, proposal_id: u64) {
        let voting_contract: Address = Self::voting_contract(env.clone());
        let count: u64 = env.invoke_contract(&voting_contract, &Symbol::new(env, "proposal_count"), soroban_sdk::vec![env, dao_id.into_val(env)]);
        if proposal_id == 0 || proposal_id > count {
            panic_with_error!(env, CommentsError::ProposalNotFound);
        }
    }

    fn verify_groth16(env: &Env, vk: &VerificationKey, proof: &Proof, pub_signals: &Vec<U256>) -> bool {
        #[cfg(test)]
        {
            if let Some(override_val) = env.storage().instance().get::<DataKey, bool>(&DataKey::VerifyOverride) {
                return override_val;
            }
            return pub_signals.len() + 1 == vk.ic.len();
        }
        #[cfg(not(test))]
        zkvote_groth16::verify_groth16(env, vk, proof, pub_signals)
    }

    fn verify_groth16_bls381(env: &Env, vk: &VerificationKeyBls381, proof: &ProofBls381, pub_signals: &Vec<U256>) -> bool {
        #[cfg(test)]
        {
            if let Some(override_val) = env.storage().instance().get::<DataKey, bool>(&DataKey::VerifyOverride) {
                return override_val;
            }
            return pub_signals.len() + 1 == vk.ic.len();
        }
        #[cfg(not(test))]
        zkvote_groth16::verify_groth16_bls381(env, vk, proof, pub_signals)
    }

    #[cfg(test)]
    fn set_verify_override_for_tests(env: Env, accept: bool) {
        env.storage().instance().set(&DataKey::VerifyOverride, &accept);
    }
}
