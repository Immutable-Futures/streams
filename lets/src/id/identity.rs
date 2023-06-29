// Rust
use alloc::boxed::Box;
use core::{hash::Hash, ops::{Deref, DerefMut}};

// 3rd-party
use async_trait::async_trait;

// IOTA
#[cfg(not(feature = "did"))]
use crypto::signatures::ed25519;
#[cfg(feature = "did")]
use identity_iota::{
    did::DID as IdentityDID,
    iota::IotaDID,
};

#[cfg(feature = "did")]
use iota_client::{
    api::EncryptedData,
    stronghold::Location,
};

// IOTA-Streams
#[cfg(not(feature = "did"))]
use spongos::{
    ddml::commands::{X25519, Ed25519 as Ed25519Command},
};
#[cfg(feature = "did")]
use spongos::ddml::types::Bytes;

use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Mask, Squeeze},
        io,
        modifiers::External,
        types::{NBytes, Uint8},
    },
    error::{Error as SpongosError, Result as SpongosResult},
    PRP,
};

// Local
#[cfg(not(feature = "did"))]
use crate::id::ed25519::Ed25519;

#[cfg(feature = "did")]
use crate::{
    alloc::string::ToString,
    error::Error,
    id::did::{DID, get_exchange_method, STREAMS_VAULT},
};

use crate::{
    id::identifier::Identifier,
    message::{ContentDecrypt, ContentSign, ContentSignSizeof},
};

/// Wrapper around [`Identifier`], specifying which type of [`Identity`] is being used. An
/// [`Identity`] is the foundation of message sending and verification.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(clippy::large_enum_variant)]
pub struct Identity {
    /// Type of User Identity
    identitykind: IdentityKind,
    /// User Identifier
    identifier: Identifier,
}

impl Default for Identity {
    fn default() -> Self {
        Identity::new(IdentityKind::default())
    }
}

impl Identity {
    /// Create a new [`Identity`] from the provided `IdentityKind` wrapper
    ///
    /// # Arguments
    /// * `identity_kind`: A wrapper containing [`Identity`] details
    pub fn new(identity_kind: IdentityKind) -> Self {
        let identifier = identity_kind.to_identifier();
        Self {
            identitykind: identity_kind,
            identifier,
        }
    }

    /// Returns a reference to the User [`Identifier`]
    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    pub fn identity_kind(&mut self) -> &mut IdentityKind {
        &mut self.identitykind
    }
}

impl Deref for Identity {
    type Target = IdentityKind;
    fn deref(&self) -> &Self::Target {
        &self.identitykind
    }
}

impl DerefMut for Identity {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.identity_kind()
    }
}

impl From<IdentityKind> for Identity {
    fn from(identitykind: IdentityKind) -> Self {
        Self::new(identitykind)
    }
}

#[cfg(not(feature = "did"))]
impl From<Ed25519> for Identity {
    fn from(ed25519: Ed25519) -> Self {
        Self::new(IdentityKind::Ed25519(ed25519))
    }
}

#[cfg(feature = "did")]
impl From<DID> for Identity {
    fn from(did: DID) -> Self {
        Self::new(IdentityKind::DID(did))
    }
}

/// Wrapper for [`Identity`] details
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum IdentityKind {
    #[cfg(not(feature = "did"))]
    /// An Ed25519 type [`Identity`] using a private key
    Ed25519(Ed25519),
    /// An IOTA `DID` type [`Identity`] using a `DID` document stored in the tangle
    #[cfg(feature = "did")]
    DID(DID),
}

impl Default for IdentityKind {
    fn default() -> Self {
        #[cfg(not(feature = "did"))]
        {
            // unwrap is fine because we are using default
            let signing_private_key = ed25519::SecretKey::from_bytes([0; ed25519::SECRET_KEY_LENGTH]);
            Self::Ed25519(Ed25519::new(signing_private_key))
        }
        #[cfg(feature = "did")]
        Self::DID(DID::Default)
    }
}

impl IdentityKind {
    /// Converts the [`IdentityKind`] instance into an [`Identifier`]
    pub fn to_identifier(&self) -> Identifier {
        match self {
            #[cfg(not(feature = "did"))]
            Self::Ed25519(ed25519) => ed25519.inner().public_key().into(),
            #[cfg(feature = "did")]
            Self::DID(did) => Identifier::DID(did.info().url_info().clone()),
        }
    }
}

impl Mask<&Identity> for sizeof::Context {
    fn mask(&mut self, identity: &Identity) -> SpongosResult<&mut Self> {
        match &identity.identitykind {
            #[cfg(not(feature = "did"))]
            IdentityKind::Ed25519(ed25519) => self.mask(Uint8::new(0))?.mask(NBytes::new(ed25519)),
            #[cfg(feature = "did")]
            IdentityKind::DID(did) => self.mask(Uint8::new(1))?.mask(did),
        }
    }
}

impl<OS, F> Mask<&Identity> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, identity: &Identity) -> SpongosResult<&mut Self> {
        match &identity.identitykind {
            #[cfg(not(feature = "did"))]
            IdentityKind::Ed25519(ed25519) => self.mask(Uint8::new(0))?.mask(NBytes::new(ed25519)),
            #[cfg(feature = "did")]
            IdentityKind::DID(did) => self.mask(Uint8::new(1))?.mask(did),
        }
    }
}

impl<IS, F> Mask<&mut Identity> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, identity: &mut Identity) -> SpongosResult<&mut Self> {
        let mut oneof = Uint8::default();
        self.mask(&mut oneof)?;
        let identitykind = match oneof.inner() {
            #[cfg(not(feature = "did"))]
            0 => {
                let mut ed25519_bytes = [0; ed25519::SECRET_KEY_LENGTH];
                self.mask(NBytes::new(&mut ed25519_bytes))?;
                IdentityKind::Ed25519(ed25519::SecretKey::from_bytes(ed25519_bytes).into())
            }
            #[cfg(feature = "did")]
            1 => {
                let mut did = DID::default();
                self.mask(&mut did)?;
                IdentityKind::DID(did)
            }
            o => return Err(SpongosError::InvalidOption("identitykind", o)),
        };

        *identity = Identity::new(identitykind);
        Ok(self)
    }
}

#[async_trait]
impl ContentSignSizeof<Identity> for sizeof::Context {
    async fn sign_sizeof(&mut self, signer: &Identity) -> SpongosResult<&mut Self> {
        match &signer.identitykind {
            #[cfg(not(feature = "did"))]
            IdentityKind::Ed25519(ed25519) => {
                let hash = External::new(NBytes::new([0; 64]));
                self.absorb(Uint8::new(0))?
                    .commit()?
                    .squeeze(hash.as_ref())?
                    .ed25519(ed25519.inner(), hash.as_ref())?;
                Ok(self)
            }

            #[cfg(feature = "did")]
            IdentityKind::DID(did_impl) => match did_impl {
                DID::PrivateKey(info) => {
                    let hash = [0; 64];
                    let key_fragment = info.url_info().signing_fragment().as_bytes().to_vec();
                    let signature = [0; 64];
                    self.absorb(Uint8::new(1))?
                        .absorb(Bytes::new(key_fragment))?
                        .commit()?
                        .squeeze(External::new(&NBytes::new(&hash)))?
                        .absorb(NBytes::new(signature))
                }
                DID::Default => unreachable!(),
            },
        }
    }
}

#[async_trait]
impl<OS, F> ContentSign<IdentityKind> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    async fn sign(&mut self, signer: &mut IdentityKind) -> SpongosResult<&mut Self> {
        match signer {
            #[cfg(not(feature = "did"))]
            IdentityKind::Ed25519(ed25519) => {
                let mut hash = External::new(NBytes::new([0; 64]));
                self.absorb(Uint8::new(0))?
                    .commit()?
                    .squeeze(hash.as_mut())?
                    .ed25519(ed25519.inner(), hash.as_ref())?;
                Ok(self)
            }

            #[cfg(feature = "did")]
            IdentityKind::DID(ref mut did_impl) => {
                match did_impl {
                    DID::PrivateKey(info) => {
                        let url_info = info.url_info_mut();
                        let did_url = url_info.did().to_string();
                        let fragment = url_info.signing_fragment().to_string();
                        // Check to see if there is a stronghold stored first to avoid unnecessary
                        // processing
                        let stronghold = url_info.stronghold()
                            .map_err(|e| SpongosError::Context("fetching stronghold adaptor", e.to_string()))?;
                        let mut hash = [0; 64];
                        let key_fragment = fragment.as_bytes().to_vec();
                        self.absorb(Uint8::new(1))?
                            .absorb(Bytes::new(key_fragment))?
                            .commit()?
                            .squeeze(External::new(&mut NBytes::new(&mut hash)))?;

                        // Join the DID identifier with the key fragment of the verification method
                        let fragment = if !fragment.starts_with("#") {
                          format!("#{fragment}")
                        } else {
                            fragment
                        };
                        let method = IotaDID::parse(did_url)
                            .map_err(|e| SpongosError::Context("ContentSign", Error::did("did parse", e).to_string()))?
                            .join(&fragment)
                            .map_err(|e| {
                                SpongosError::Context("ContentSign", Error::did("join did fragments", e).to_string())
                            })?;

                        // update stronghold snapshot
                        let _ = stronghold.read_stronghold_snapshot().await;

                        let location = Location::generic(STREAMS_VAULT, method.to_string().as_bytes());
                        let sig = stronghold.ed25519_sign(location, &hash).await
                            .map_err(|e| SpongosError::Context("signing hash", e.to_string()))?;

                        self.absorb(NBytes::new(sig))
                    }
                    DID::Default => unreachable!(),
                    // TODO: Implement Account logic
                }
            }
        }
    }
}

#[async_trait]
impl<IS, F> ContentDecrypt<IdentityKind> for unwrap::Context<IS, F>
where
    F: PRP + Send,
    IS: io::IStream + Send,
{
    async fn decrypt(&mut self, recipient: &mut IdentityKind, key: &mut [u8]) -> SpongosResult<&mut Self> {
        // TODO: Replace with separate logic for EdPubKey and DID instances (pending Identity xkey
        // introduction)
        match recipient {
            #[cfg(not(feature = "did"))]
            IdentityKind::Ed25519(kp) => self.x25519(&kp.to_x25519(), NBytes::new(key)),
            #[cfg(feature = "did")]
            IdentityKind::DID(did) => {
                let mut pk = [0u8; 32];
                let mut nonce = [0u8; 12];
                let mut tag = [0u8; 16];
                let mut ciphertext = [0u8; 32];

                // Unwrap AEAD Encryption packet
                self.mask(NBytes::new(&mut pk))?
                    .mask(NBytes::new(&mut nonce))?
                    .mask(NBytes::new(&mut tag))?
                    .mask(NBytes::new(&mut ciphertext))?;

                let data = EncryptedData::new(pk, nonce, tag, ciphertext);
                let method = get_exchange_method(did.info().url_info()).await?;

                // Perform stronghold AEAD decryption
                let location = Location::generic(STREAMS_VAULT, method.id().to_string());
                let stronghold = did.info_mut().url_info_mut().stronghold()
                    .map_err(|e| SpongosError::Context("retrieving stronghold adapter", e.to_string()))?;
                let _ = stronghold.read_stronghold_snapshot().await;
                let data = stronghold.x25519_decrypt(location, data).await
                    .map_err(|e| SpongosError::Context("decrypting data", e.to_string()))?;
                // Update key with decrypted secret
                key.clone_from_slice(data.as_slice());
                Ok(self)
            }
        }
    }
}
