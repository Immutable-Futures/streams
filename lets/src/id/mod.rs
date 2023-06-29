/// Ed25519 functions and types
#[cfg(not(feature = "did"))]
mod ed25519;
/// User Identifier functions and types
mod identifier;
/// User Identity functions and types
mod identity;
mod permission;
mod psk;

pub use self::identity::{Identity, IdentityKind};
#[cfg(not(feature = "did"))]
pub use ed25519::{Ed25519, Ed25519Pub};
pub use identifier::Identifier;
pub use permission::{PermissionDuration, Permissioned};
pub use psk::{Psk, PskId};

/// Iota Identity functions and types
#[cfg(feature = "did")]
pub mod did;
