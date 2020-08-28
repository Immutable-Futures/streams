//! `Announce` message content. This is the initial message of the Channel application instance.
//! It announces channel owner's public keys: Ed25519 signature key and corresponding X25519 key
//! exchange key (derived from Ed25519 public key). The `Announce` message is similar to
//! self-signed certificate in a conventional PKI.
//!
//! ```ddml
//! message Announce {
//!     absorb u8 ed25519pk[32];
//!     commit;
//!     squeeze external u8 tag[32];
//!     ed25519(tag) sig;
//! }
//! ```
//!
//! # Fields
//!
//! * `ed25519pk` -- channel owner's Ed25519 public key.
//!
//! * `tag` -- hash-value to be signed.
//!
//! * `sig` -- signature of `tag` field produced with the Ed25519 private key corresponding to ed25519pk`.
//!

use anyhow::Result;

use iota_streams_app::message;
use iota_streams_core::sponge::prp::PRP;
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};
use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

/// Type of `Announce` message content.
pub const TYPE: &str = "STREAMS9CHANNELS9ANNOUNCE";

pub struct ContentWrap<'a, F> {
    sig_kp: &'a ed25519::Keypair,
    _phantom: core::marker::PhantomData<F>,
}

impl<'a, F> ContentWrap<'a, F>
{
    pub fn new(sig_kp: &'a ed25519::Keypair) -> Self {
        Self {
            sig_kp,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<'a, F, Store> message::ContentWrap<F, Store> for ContentWrap<'a, F>
where
    F: PRP,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        ctx.absorb(&self.sig_kp.public)?;
        ctx.ed25519(self.sig_kp, HashSig)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.absorb(&self.sig_kp.public)?;
        ctx.ed25519(self.sig_kp, HashSig)?;
        Ok(ctx)
    }
}

pub struct ContentUnwrap<F> {
    pub(crate) sig_pk: ed25519::PublicKey,
    pub(crate) ke_pk: x25519::PublicKey,
    _phantom: core::marker::PhantomData<F>,
}

impl<F> Default for ContentUnwrap<F> {
    fn default() -> Self {
        let sig_pk = ed25519::PublicKey::default();
        let ke_pk = x25519::public_from_ed25519(&sig_pk);
        Self {
            sig_pk,
            ke_pk,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F, Store> message::ContentUnwrap<F, Store> for ContentUnwrap<F>
where
    F: PRP,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        ctx.absorb(&mut self.sig_pk)?;
        self.ke_pk = x25519::public_from_ed25519(&self.sig_pk);
        ctx.ed25519(&self.sig_pk, HashSig)?;
        Ok(ctx)
    }
}