use anyhow::Result;

use super::Context;
use crate::{
    command::X25519,
    types::NBytes,
};
use iota_streams_core_edsig::key_exchange::x25519;

/// Sizeof encapsulated secret is fixed.
impl<F> X25519<&x25519::PublicKey, &NBytes> for Context<F>
{
    fn x25519(&mut self, _key: &x25519::PublicKey, _secret: &NBytes) -> Result<&mut Self> {
        //TODO: Ensure key is valid.
        self.size += 64;
        Ok(self)
    }
}
