//! Constitutional Governance Runtime (CGR) Kernel interface.
//!
//! The **CGR kernel** is the heart of EXOCHAIN. Every action that matters —
//! reading data, delegating authority, invoking a tool — is first submitted
//! to the kernel, which checks the action against the constitution and the
//! eight structural invariants (including `NoSelfGrant`, `ConsentRequired`,
//! and `KernelImmutability`). Only if the kernel returns `Permitted` does the
//! action run.
//!
//! [`ConstitutionalKernel`] is a simplified, ergonomic wrapper around
//! [`exo_gatekeeper::Kernel`]. It initialises the kernel with the default
//! EXOCHAIN constitution text and the full set of eight constitutional
//! invariants. Adjudication requires caller-supplied authority signing material
//! so the SDK never fabricates a trust root.
//!
//! ## Why use this module
//!
//! - You want to ask "is this action permitted?" without having to construct
//!   the full [`exo_gatekeeper::AdjudicationContext`] by hand.
//! - You want to exercise specific invariants (self-grant, kernel
//!   modification, consent-required) in tests via the named `adjudicate_*`
//!   helpers.
//! - You want the same verdict enum to flow through your application and
//!   your test vectors.
//!
//! ## Quick start
//!
//! ```
//! use exochain_sdk::kernel::ConstitutionalKernel;
//! use exo_core::Did;
//!
//! let authority = exochain_sdk::identity::Identity::generate("authority");
//! let kernel = ConstitutionalKernel::with_authority_identity(authority);
//! let actor = Did::new("did:exo:alice").expect("valid");
//! let verdict = kernel.adjudicate(&actor, "data:medical:read");
//! assert!(verdict.is_permitted());
//! ```

use std::sync::Arc;

use exo_core::{Did, Hash256, PublicKey, Signature};
use exo_gatekeeper::{
    ActionRequest, AdjudicationContext, InvariantSet, Kernel, Verdict,
    types::{
        AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch, Permission,
        PermissionSet, Provenance, Role,
    },
};
use serde::{Deserialize, Serialize};

/// The default constitution bytes used by [`ConstitutionalKernel::new`].
const DEFAULT_CONSTITUTION: &[u8] = b"EXOCHAIN Constitution v1.0: \
    We the people of the EXOCHAIN fabric establish this constitution \
    to secure the blessings of ordered, consented, and auditable agency.";

/// Expected number of constitutional invariants enforced by the kernel.
const INVARIANT_COUNT: usize = 8;

/// Verdict returned by the SDK kernel.
///
/// This mirrors [`exo_gatekeeper::Verdict`] but flattens the violation list
/// to a simple `Vec<String>` so SDK consumers do not need to depend on the
/// full gatekeeper types.
///
/// # Examples
///
/// ```
/// use exochain_sdk::kernel::KernelVerdict;
///
/// let ok = KernelVerdict::Permitted;
/// assert!(ok.is_permitted());
///
/// let denied = KernelVerdict::Denied { violations: vec!["NoSelfGrant".into()] };
/// assert!(denied.is_denied());
///
/// let escalated = KernelVerdict::Escalated { reason: "human review".into() };
/// assert!(escalated.is_escalated());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelVerdict {
    /// The action is permitted.
    Permitted,
    /// The action is denied — one or more invariants were violated.
    Denied {
        /// Human-readable descriptions of the violated invariants.
        violations: Vec<String>,
    },
    /// The action has been escalated for review.
    Escalated {
        /// Human-readable reason for escalation.
        reason: String,
    },
}

impl KernelVerdict {
    /// Returns `true` if the verdict is [`KernelVerdict::Permitted`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::kernel::KernelVerdict;
    /// assert!(KernelVerdict::Permitted.is_permitted());
    /// assert!(!KernelVerdict::Denied { violations: vec![] }.is_permitted());
    /// ```
    #[must_use]
    pub fn is_permitted(&self) -> bool {
        matches!(self, Self::Permitted)
    }

    /// Returns `true` if the verdict is [`KernelVerdict::Denied`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::kernel::KernelVerdict;
    /// let v = KernelVerdict::Denied { violations: vec!["NoSelfGrant".into()] };
    /// assert!(v.is_denied());
    /// ```
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// Returns `true` if the verdict is [`KernelVerdict::Escalated`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::kernel::KernelVerdict;
    /// let v = KernelVerdict::Escalated { reason: "human in the loop".into() };
    /// assert!(v.is_escalated());
    /// ```
    #[must_use]
    pub fn is_escalated(&self) -> bool {
        matches!(self, Self::Escalated { .. })
    }
}

/// An ergonomic wrapper around the CGR [`Kernel`].
///
/// Provides a minimal adjudication interface suitable for common SDK use
/// cases: a single actor performing an action, with caller-supplied authority
/// signing material, signed provenance, and an active bailment from that
/// authority. Callers needing fine-grained control over the adjudication
/// context should use [`exo_gatekeeper::Kernel`] directly.
///
/// # Examples
///
/// ```
/// use exochain_sdk::kernel::ConstitutionalKernel;
/// use exo_core::Did;
///
/// let authority = exochain_sdk::identity::Identity::generate("authority");
/// let kernel = ConstitutionalKernel::with_authority_identity(authority);
/// assert!(kernel.verify_integrity());
/// assert_eq!(kernel.invariant_count(), 8);
///
/// let actor = Did::new("did:exo:alice").expect("valid");
/// let verdict = kernel.adjudicate(&actor, "read:profile");
/// assert!(verdict.is_permitted());
/// ```
pub struct ConstitutionalKernel {
    inner: Kernel,
    constitution: Vec<u8>,
    authority: Option<KernelAuthority>,
}

type AuthoritySigner = Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>;

struct KernelAuthority {
    did: Did,
    public_key: PublicKey,
    signer: AuthoritySigner,
}

impl ConstitutionalKernel {
    /// Construct a new kernel with the default constitution and all eight
    /// constitutional invariants.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::kernel::ConstitutionalKernel;
    /// let kernel = ConstitutionalKernel::new();
    /// assert_eq!(kernel.invariant_count(), 8);
    /// assert!(kernel.verify_integrity());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Kernel::new(DEFAULT_CONSTITUTION, InvariantSet::all()),
            constitution: DEFAULT_CONSTITUTION.to_vec(),
            authority: None,
        }
    }

    /// Construct a new kernel with an authority signing identity.
    ///
    /// This is the common SDK path: the identity's DID becomes the authority
    /// grantor and bailor for the default adjudication context, and its secret
    /// key signs the canonical authority/provenance payloads that the kernel
    /// verifies.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::{identity::Identity, kernel::ConstitutionalKernel};
    /// let authority = Identity::generate("authority");
    /// let kernel = ConstitutionalKernel::with_authority_identity(authority);
    /// assert!(kernel.verify_integrity());
    /// ```
    #[must_use]
    pub fn with_authority_identity(authority: crate::identity::Identity) -> Self {
        let authority_did = authority.did().clone();
        let authority_public_key = *authority.public_key();
        Self::with_authority(
            authority_did,
            authority_public_key,
            Arc::new(move |message: &[u8]| authority.sign(message)),
        )
    }

    /// Construct a new kernel with caller-supplied authority signing material.
    ///
    /// The signer must produce an Ed25519 signature over the message bytes it
    /// receives. The supplied public key is embedded in the adjudication
    /// context, and the gatekeeper verifies every signature cryptographically.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use exochain_sdk::{crypto, kernel::ConstitutionalKernel};
    /// let authority_did = crypto::Did::new("did:exo:authority").expect("valid");
    /// let (authority_public_key, authority_secret_key) = crypto::generate_keypair();
    /// let kernel = ConstitutionalKernel::with_authority(
    ///     authority_did,
    ///     authority_public_key,
    ///     Arc::new(move |message: &[u8]| crypto::sign(message, &authority_secret_key)),
    /// );
    /// assert!(kernel.verify_integrity());
    /// ```
    #[must_use]
    pub fn with_authority(
        authority_did: Did,
        authority_public_key: PublicKey,
        authority_signer: AuthoritySigner,
    ) -> Self {
        Self {
            inner: Kernel::new(DEFAULT_CONSTITUTION, InvariantSet::all()),
            constitution: DEFAULT_CONSTITUTION.to_vec(),
            authority: Some(KernelAuthority {
                did: authority_did,
                public_key: authority_public_key,
                signer: authority_signer,
            }),
        }
    }

    /// Adjudicate `action` performed by `actor` using the signed SDK context.
    ///
    /// The SDK supplies a minimal signed default context:
    /// - A single Judicial role for `actor`.
    /// - A one-link authority chain from the configured authority to `actor`
    ///   granting `read`.
    /// - An active bailment from the configured authority to `actor` scoped to
    ///   `action`.
    /// - Full human-override preservation.
    /// - Signed provenance with timestamp `"sdk"`.
    ///
    /// If the kernel was created with [`Self::new`] rather than
    /// [`Self::with_authority`] or [`Self::with_authority_identity`], this
    /// method fails closed with a denied verdict.
    ///
    /// Callers needing richer context should reach for
    /// [`exo_gatekeeper::Kernel`] directly.
    ///
    /// The action is flagged as `is_self_grant = false` and
    /// `modifies_kernel = false` by default. Helpers are available for the
    /// common deny-cases used in tests: see
    /// [`Self::adjudicate_self_grant`],
    /// [`Self::adjudicate_kernel_modification`], and
    /// [`Self::adjudicate_without_bailment`].
    ///
    /// # Examples
    ///
    /// ```
    /// use exochain_sdk::kernel::ConstitutionalKernel;
    /// use exo_core::Did;
    ///
    /// let authority = exochain_sdk::identity::Identity::generate("authority");
    /// let kernel = ConstitutionalKernel::with_authority_identity(authority);
    /// let actor = Did::new("did:exo:alice").expect("valid");
    /// let verdict = kernel.adjudicate(&actor, "data:read");
    /// assert!(verdict.is_permitted());
    /// ```
    #[must_use]
    pub fn adjudicate(&self, actor: &Did, action: &str) -> KernelVerdict {
        self.adjudicate_internal(actor, action, false, false, true, true)
    }

    /// Same as [`Self::adjudicate`] but sets `is_self_grant = true` so the
    /// kernel can enforce the `NoSelfGrant` invariant.
    ///
    /// Useful for exercising the invariant in tests: a permitted verdict
    /// here would indicate a constitutional defect.
    ///
    /// # Examples
    ///
    /// ```
    /// use exochain_sdk::kernel::ConstitutionalKernel;
    /// use exo_core::Did;
    ///
    /// let authority = exochain_sdk::identity::Identity::generate("authority");
    /// let kernel = ConstitutionalKernel::with_authority_identity(authority);
    /// let actor = Did::new("did:exo:self-granter").expect("valid");
    /// let verdict = kernel.adjudicate_self_grant(&actor, "escalate-self");
    /// assert!(verdict.is_denied());
    /// ```
    #[must_use]
    pub fn adjudicate_self_grant(&self, actor: &Did, action: &str) -> KernelVerdict {
        self.adjudicate_internal(actor, action, true, false, true, true)
    }

    /// Same as [`Self::adjudicate`] but sets `modifies_kernel = true` so the
    /// kernel can enforce the `KernelImmutability` invariant.
    ///
    /// # Examples
    ///
    /// ```
    /// use exochain_sdk::kernel::ConstitutionalKernel;
    /// use exo_core::Did;
    ///
    /// let authority = exochain_sdk::identity::Identity::generate("authority");
    /// let kernel = ConstitutionalKernel::with_authority_identity(authority);
    /// let actor = Did::new("did:exo:patcher").expect("valid");
    /// let verdict = kernel.adjudicate_kernel_modification(&actor, "patch-kernel");
    /// assert!(verdict.is_denied());
    /// ```
    #[must_use]
    pub fn adjudicate_kernel_modification(&self, actor: &Did, action: &str) -> KernelVerdict {
        self.adjudicate_internal(actor, action, false, true, true, true)
    }

    /// Same as [`Self::adjudicate`] but omits the default bailment so the
    /// kernel can enforce the `ConsentRequired` invariant.
    ///
    /// # Examples
    ///
    /// ```
    /// use exochain_sdk::kernel::ConstitutionalKernel;
    /// use exo_core::Did;
    ///
    /// let authority = exochain_sdk::identity::Identity::generate("authority");
    /// let kernel = ConstitutionalKernel::with_authority_identity(authority);
    /// let actor = Did::new("did:exo:unauth").expect("valid");
    /// let verdict = kernel.adjudicate_without_bailment(&actor, "read-data");
    /// assert!(verdict.is_denied());
    /// ```
    #[must_use]
    pub fn adjudicate_without_bailment(&self, actor: &Did, action: &str) -> KernelVerdict {
        self.adjudicate_internal(actor, action, false, false, false, true)
    }

    /// Verify that the kernel's stored constitution hash matches the
    /// configured constitution text.
    ///
    /// Returns `false` if the constitution in memory has drifted from the
    /// hash the kernel was initialised with — which should never happen in
    /// practice, but is checked defensively because constitutional integrity
    /// is a load-bearing invariant.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::kernel::ConstitutionalKernel;
    /// let kernel = ConstitutionalKernel::new();
    /// assert!(kernel.verify_integrity());
    /// ```
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.inner.verify_kernel_integrity(&self.constitution)
    }

    /// Number of constitutional invariants enforced by this kernel (always 8).
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::kernel::ConstitutionalKernel;
    /// assert_eq!(ConstitutionalKernel::new().invariant_count(), 8);
    /// ```
    #[must_use]
    pub fn invariant_count(&self) -> usize {
        INVARIANT_COUNT
    }

    fn signed_authority_link(
        authority: &KernelAuthority,
        grantee: &Did,
        permissions: &PermissionSet,
    ) -> AuthorityLink {
        let mut payload = Vec::new();
        payload.extend_from_slice(authority.did.as_str().as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(grantee.as_str().as_bytes());
        payload.push(0x00);
        for permission in &permissions.permissions {
            payload.extend_from_slice(permission.0.as_bytes());
            payload.push(0x00);
        }
        let message = Hash256::digest(&payload);
        let signature = (authority.signer)(message.as_bytes());

        AuthorityLink {
            grantor: authority.did.clone(),
            grantee: grantee.clone(),
            permissions: permissions.clone(),
            signature: signature.to_bytes().to_vec(),
            grantor_public_key: Some(authority.public_key.as_bytes().to_vec()),
        }
    }

    fn signed_provenance(authority: &KernelAuthority, actor: &Did, action: &str) -> Provenance {
        let timestamp = "sdk".to_owned();
        let action_hash = Hash256::digest(action.as_bytes()).as_bytes().to_vec();

        let mut payload = Vec::new();
        payload.extend_from_slice(actor.as_str().as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(&action_hash);
        payload.push(0x00);
        payload.extend_from_slice(timestamp.as_bytes());
        let message = Hash256::digest(&payload);
        let signature = (authority.signer)(message.as_bytes());

        Provenance {
            actor: actor.clone(),
            timestamp,
            action_hash,
            signature: signature.to_bytes().to_vec(),
            public_key: Some(authority.public_key.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        }
    }

    fn adjudicate_internal(
        &self,
        actor: &Did,
        action: &str,
        is_self_grant: bool,
        modifies_kernel: bool,
        include_bailment: bool,
        human_override_preserved: bool,
    ) -> KernelVerdict {
        let Some(authority) = self.authority.as_ref() else {
            return KernelVerdict::Denied {
                violations: vec![
                    "AuthorityChainValid: SDK authority signer is required for adjudication".into(),
                ],
            };
        };

        let permissions = PermissionSet::new(vec![Permission::new("read")]);
        let request = ActionRequest {
            actor: actor.clone(),
            action: action.to_owned(),
            required_permissions: permissions.clone(),
            is_self_grant,
            modifies_kernel,
        };

        let scope = action.to_owned();

        let (bailment_state, consent_records) = if include_bailment {
            (
                BailmentState::Active {
                    bailor: authority.did.clone(),
                    bailee: actor.clone(),
                    scope: scope.clone(),
                },
                vec![ConsentRecord {
                    subject: authority.did.clone(),
                    granted_to: actor.clone(),
                    scope,
                    active: true,
                }],
            )
        } else {
            (BailmentState::None, Vec::new())
        };

        let context = AdjudicationContext {
            actor_roles: vec![Role {
                name: "sdk-default".into(),
                branch: GovernmentBranch::Judicial,
            }],
            authority_chain: AuthorityChain {
                links: vec![Self::signed_authority_link(authority, actor, &permissions)],
            },
            consent_records,
            bailment_state,
            human_override_preserved,
            actor_permissions: permissions,
            provenance: Some(Self::signed_provenance(authority, actor, action)),
            quorum_evidence: None,
            active_challenge_reason: None,
        };

        match self.inner.adjudicate(&request, &context) {
            Verdict::Permitted => KernelVerdict::Permitted,
            Verdict::Denied { violations } => KernelVerdict::Denied {
                violations: violations
                    .into_iter()
                    .map(|v| format!("{:?}: {}", v.invariant, v.description))
                    .collect(),
            },
            Verdict::Escalated { reason } => KernelVerdict::Escalated { reason },
        }
    }
}

impl Default for ConstitutionalKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ConstitutionalKernel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConstitutionalKernel")
            .field("invariant_count", &INVARIANT_COUNT)
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid DID")
    }

    fn signed_kernel() -> ConstitutionalKernel {
        ConstitutionalKernel::with_authority_identity(crate::identity::Identity::generate(
            "sdk-authority",
        ))
    }

    #[test]
    fn new_initialises_with_eight_invariants() {
        let k = ConstitutionalKernel::new();
        assert_eq!(k.invariant_count(), 8);
    }

    #[test]
    fn verify_integrity_holds_after_new() {
        let k = ConstitutionalKernel::new();
        assert!(k.verify_integrity());
    }

    #[test]
    fn default_matches_new() {
        let a = ConstitutionalKernel::default();
        let b = ConstitutionalKernel::new();
        assert_eq!(a.invariant_count(), b.invariant_count());
        assert_eq!(a.verify_integrity(), b.verify_integrity());
    }

    #[test]
    fn valid_action_permitted() {
        let k = signed_kernel();
        let actor = did("did:exo:valid-actor");
        let verdict = k.adjudicate(&actor, "read-medical-record");
        assert!(
            verdict.is_permitted(),
            "expected Permitted, got {verdict:?}"
        );
    }

    #[test]
    fn adjudicate_without_authority_signer_fails_closed() {
        let k = ConstitutionalKernel::new();
        let actor = did("did:exo:valid-actor");
        let verdict = k.adjudicate(&actor, "read-medical-record");
        assert!(verdict.is_denied(), "expected Denied, got {verdict:?}");
        match verdict {
            KernelVerdict::Denied { violations } => {
                assert!(violations.iter().any(|v| v.contains("authority signer")));
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn self_grant_denied() {
        let k = signed_kernel();
        let actor = did("did:exo:self-granter");
        let verdict = k.adjudicate_self_grant(&actor, "escalate-self");
        assert!(verdict.is_denied(), "expected Denied, got {verdict:?}");
    }

    #[test]
    fn kernel_modification_denied() {
        let k = signed_kernel();
        let actor = did("did:exo:patcher");
        let verdict = k.adjudicate_kernel_modification(&actor, "patch-kernel");
        assert!(verdict.is_denied(), "expected Denied, got {verdict:?}");
    }

    #[test]
    fn no_bailment_denied() {
        let k = signed_kernel();
        let actor = did("did:exo:unauth");
        let verdict = k.adjudicate_without_bailment(&actor, "read-data");
        assert!(verdict.is_denied(), "expected Denied, got {verdict:?}");
    }

    #[test]
    fn verdict_helpers() {
        assert!(KernelVerdict::Permitted.is_permitted());
        assert!(!KernelVerdict::Permitted.is_denied());
        let denied = KernelVerdict::Denied { violations: vec![] };
        assert!(denied.is_denied());
        assert!(!denied.is_permitted());
        let esc = KernelVerdict::Escalated { reason: "r".into() };
        assert!(esc.is_escalated());
        assert!(!esc.is_permitted());
    }

    #[test]
    fn verdict_serde_roundtrip() {
        let v = KernelVerdict::Denied {
            violations: vec!["NoSelfGrant: reason".into()],
        };
        let json = serde_json::to_string(&v).expect("ser");
        let decoded: KernelVerdict = serde_json::from_str(&json).expect("de");
        assert_eq!(v, decoded);
    }

    #[test]
    fn debug_impl_smoke() {
        let k = ConstitutionalKernel::new();
        let dbg = format!("{k:?}");
        assert!(dbg.contains("ConstitutionalKernel"));
        assert!(dbg.contains("8"));
    }
}
